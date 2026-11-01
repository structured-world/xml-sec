//! Configuration and key material for `XMLDSig` key resolution.

use alloc::{boxed::Box, collections::BTreeMap, string::String, vec::Vec};
use core::fmt;

#[cfg(test)]
use super::parse::parse_x509_certificate;
use crate::rsa_encoding::RsaPublicKeyEncoding as _;
use crypto_bigint::BoxedUint;
use dsa::pkcs8::EncodePublicKey as DsaEncodePublicKey;
use hmac::{KeyInit, Mac};
#[cfg(test)]
use x509_parser::prelude::FromDer;
#[cfg(test)]
use x509_parser::prelude::X509Certificate;
use zeroize::Zeroizing;

use super::pkix::X509DataSource;
use super::signature::{
    signature_value_matches_spki_with_encoding, validate_dsa_signature_spki_with_minimum,
    validate_rsa_signature_spki_with_minimum, verify_dsa_signature_spki_primitive,
    verify_ecdsa_signature_spki_in, verify_rsa_signature_spki_primitive,
};
use super::{
    DsigError, KeyInfo, KeyInfoSource, KeyResolver, KeyValueInfo, SignatureAlgorithm, VerifyingKey,
    X509ChainOptions, X509DataInfo,
    parse::{
        EC_P256_OID, EC_P384_OID, EC_P521_OID, ParseError, X509ChainBuildError,
        build_x509_certificate_paths_to_selector_targets,
        build_x509_certificate_paths_to_trusted_prefix, x509_certificate_matches_any_selector,
        x509_data_has_lookup_identifiers, x509_selector_categories_match_candidates,
    },
    x509::verify_x509_certificate_chain_in_session,
};
use super::{ResolvedVerificationKey, TrustedPublicKey, X509TrustEvidence};

/// Operation-local indexing borrows configured and document bytes. It never
/// manufactures public display metadata or clones encoded certificate pools.
struct BorrowedX509Pool<'a> {
    certificates: structured_asn1::memory::OwnedVec<&'a [u8]>,
    crls: &'a [Vec<u8>],
    certificate_chain: structured_asn1::memory::OwnedVec<usize>,
}

impl<'a> BorrowedX509Pool<'a> {
    fn new(crls: &'a [Vec<u8>], session: &super::pkix::CertificateSession) -> Self {
        Self {
            certificates: session.memory().vector(),
            crls,
            certificate_chain: session.memory().vector(),
        }
    }

    fn insert(
        &mut self,
        encoded: &'a [u8],
        session: &super::pkix::CertificateSession,
    ) -> Result<usize, KeyResolutionError> {
        for (index, known) in self.certificates.iter().enumerate() {
            if known.len() != encoded.len() {
                continue;
            }
            if known.as_ptr() == encoded.as_ptr() {
                return Ok(index);
            }
            session
                .memory()
                .charge_work(encoded.len() as u64)
                .map_err(|reason| {
                    certificate_resolution_error(session.error(structured_pkix::Error::resource(
                        reason,
                        "certificate.pool_identity",
                        0,
                    )))
                })?;
            if *known == encoded {
                return Ok(index);
            }
        }
        self.certificates.try_push(encoded).map_err(|reason| {
            certificate_resolution_error(session.error(structured_pkix::Error::resource(
                reason,
                "certificate.pool",
                0,
            )))
        })?;
        Ok(self.certificates.len() - 1)
    }
}

impl X509DataSource for BorrowedX509Pool<'_> {
    fn certificate_count(&self) -> usize {
        self.certificates.len()
    }
    fn certificate(&self, index: usize) -> Option<&[u8]> {
        self.certificates.get(index).copied()
    }
    fn chain(&self) -> &[usize] {
        &self.certificate_chain
    }
    fn crls(&self) -> &[Vec<u8>] {
        self.crls
    }
}

/// Caller-owned HMAC verification key.
///
/// Policy-free [`VerifyingKey`] calls enforce [`crate::policy::HmacPolicy::default`].
/// [`super::VerifyContext`] supplies its immutable operation policy through the
/// policy-aware hooks, so legacy truncation always requires an explicit opt-in.
/// Owned secret bytes are zeroized when the key is dropped.
#[derive(Clone)]
pub struct HmacVerificationKey {
    secret: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for HmacVerificationKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HmacVerificationKey")
            .finish_non_exhaustive()
    }
}

impl HmacVerificationKey {
    /// Construct a key from non-empty secret bytes.
    ///
    /// # Errors
    /// Returns `InvalidPublicKey` if the supplied secret is empty.
    pub fn new(secret: impl Into<Vec<u8>>) -> Result<Self, KeyResolutionError> {
        let secret = secret.into();
        if secret.is_empty() {
            return Err(KeyResolutionError::InvalidPublicKey);
        }
        Ok(Self {
            secret: Zeroizing::new(secret),
        })
    }

    fn validate_output(
        &self,
        policy: crate::policy::HmacPolicy,
        algorithm: SignatureAlgorithm,
        signature_value: &[u8],
    ) -> Result<(), DsigError> {
        if algorithm.hmac_output_bits().is_none() {
            return Err(KeyResolutionError::AlgorithmMismatch.into());
        }
        policy.validate_key_bytes(self.secret.len())?;
        policy.validate_output(algorithm, signature_value.len().saturating_mul(8))?;
        Ok(())
    }

    fn verify_with_hmac_policy(
        &self,
        policy: crate::policy::HmacPolicy,
        algorithm: SignatureAlgorithm,
        signed_data: &[u8],
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        self.validate_output(policy, algorithm, signature_value)?;
        macro_rules! verify_hmac {
            ($digest:ty) => {{
                let mut mac = hmac::Hmac::<$digest>::new_from_slice(&self.secret)
                    .map_err(|_| KeyResolutionError::InvalidPublicKey)?;
                mac.update(signed_data);
                let expected = mac.finalize().into_bytes();
                subtle::ConstantTimeEq::ct_eq(&expected[..signature_value.len()], signature_value)
                    .into()
            }};
        }
        Ok(match algorithm {
            #[cfg(feature = "legacy-algorithms")]
            SignatureAlgorithm::HmacMd5 => verify_hmac!(md5::Md5),
            #[cfg(feature = "legacy-algorithms")]
            SignatureAlgorithm::HmacRipemd160 => verify_hmac!(ripemd::Ripemd160),
            SignatureAlgorithm::HmacSha1 => verify_hmac!(sha1::Sha1),
            SignatureAlgorithm::HmacSha224 => verify_hmac!(sha2::Sha224),
            SignatureAlgorithm::HmacSha256 => verify_hmac!(sha2::Sha256),
            SignatureAlgorithm::HmacSha384 => verify_hmac!(sha2::Sha384),
            SignatureAlgorithm::HmacSha512 => verify_hmac!(sha2::Sha512),
            _ => return Err(KeyResolutionError::AlgorithmMismatch.into()),
        })
    }
}

impl VerifyingKey for HmacVerificationKey {
    fn validate_policy(&self, scope: &super::VerificationScope<'_>) -> Result<(), DsigError> {
        scope
            .policy()
            .hmac
            .validate_key_bytes(self.secret.len())
            .map_err(Into::into)
    }

    fn validate_signature_value(
        &self,
        algorithm: SignatureAlgorithm,
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        self.validate_output(
            crate::policy::HmacPolicy::default(),
            algorithm,
            signature_value,
        )?;
        Ok(true)
    }

    fn validate_signature_value_with_policy(
        &self,
        scope: &super::VerificationScope<'_>,
        algorithm: SignatureAlgorithm,
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        self.validate_output(scope.policy().hmac, algorithm, signature_value)?;
        Ok(true)
    }

    fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        signed_data: &[u8],
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        self.verify_with_hmac_policy(
            crate::policy::HmacPolicy::default(),
            algorithm,
            signed_data,
            signature_value,
        )
    }

    fn verify_with_policy(
        &self,
        scope: &super::VerificationScope<'_>,
        algorithm: SignatureAlgorithm,
        context: &super::SignatureContext,
        signed_data: &[u8],
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        if !context.as_bytes().is_empty() {
            return self.verify_with_context(algorithm, context, signed_data, signature_value);
        }
        self.verify_with_hmac_policy(scope.policy().hmac, algorithm, signed_data, signature_value)
    }
}

/// Compatibility name for the verification key originally limited to HMAC-SHA1.
pub type HmacSha1VerificationKey = HmacVerificationKey;

/// A public verification key available to key resolvers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationKey {
    /// Signature algorithm this key is configured to verify.
    pub algorithm: SignatureAlgorithm,
    /// DER-encoded `SubjectPublicKeyInfo` bytes.
    pub public_key_bytes: Vec<u8>,
    /// DER certificate from which the key was extracted, when applicable.
    pub certificate_der: Option<Vec<u8>>,
    /// Name used to register this key for `<KeyName>` resolution.
    pub name: Option<String>,
}

impl VerificationKey {
    /// Strength checks of this key's SPKI, read under `session`.
    fn validate_in(
        &self,
        rsa_minimum_bits: usize,
        dsa_minimum_bits: usize,
        session: &super::pkix::CertificateSession,
    ) -> Result<(), DsigError> {
        let result = match self.algorithm {
            #[cfg(feature = "legacy-algorithms")]
            SignatureAlgorithm::RsaMd5 | SignatureAlgorithm::RsaRipemd160 => {
                validate_rsa_signature_spki_with_minimum(
                    self.algorithm,
                    &self.public_key_bytes,
                    rsa_minimum_bits,
                    session,
                )
            }
            #[cfg(feature = "legacy-algorithms")]
            SignatureAlgorithm::HmacMd5
            | SignatureAlgorithm::HmacRipemd160
            | SignatureAlgorithm::EcdsaRipemd160 => Ok(()),
            SignatureAlgorithm::Ed25519
            | SignatureAlgorithm::Ed25519Ctx
            | SignatureAlgorithm::Ed25519Ph
            | SignatureAlgorithm::Ed448
            | SignatureAlgorithm::Ed448Ph
            | SignatureAlgorithm::PostQuantum(_) => {
                super::modern::validate_public_key(self.algorithm, &self.public_key_bytes, session)
            }
            SignatureAlgorithm::DsaSha1 | SignatureAlgorithm::DsaSha256 => {
                validate_dsa_signature_spki_with_minimum(
                    &self.public_key_bytes,
                    dsa_minimum_bits,
                    session,
                )
            }
            #[cfg(feature = "dstu4145")]
            SignatureAlgorithm::Dstu4145Gost34311 | SignatureAlgorithm::Dstu4145Dstu7564_256 => {
                super::dstu4145::validate_public_key(&self.public_key_bytes, session)
            }
            SignatureAlgorithm::RsaSha1
            | SignatureAlgorithm::RsaSha224
            | SignatureAlgorithm::RsaSha256
            | SignatureAlgorithm::RsaSha384
            | SignatureAlgorithm::RsaSha512
            | SignatureAlgorithm::RsaPssSha1
            | SignatureAlgorithm::RsaPssSha224
            | SignatureAlgorithm::RsaPssSha256
            | SignatureAlgorithm::RsaPssSha384
            | SignatureAlgorithm::RsaPssSha512
            | SignatureAlgorithm::RsaPssSha3_224
            | SignatureAlgorithm::RsaPssSha3_256
            | SignatureAlgorithm::RsaPssSha3_384
            | SignatureAlgorithm::RsaPssSha3_512
            | SignatureAlgorithm::RsaPss(_) => validate_rsa_signature_spki_with_minimum(
                self.algorithm,
                &self.public_key_bytes,
                rsa_minimum_bits,
                session,
            ),
            SignatureAlgorithm::HmacSha1
            | SignatureAlgorithm::HmacSha224
            | SignatureAlgorithm::HmacSha256
            | SignatureAlgorithm::HmacSha384
            | SignatureAlgorithm::HmacSha512
            | SignatureAlgorithm::EcdsaSha1
            | SignatureAlgorithm::EcdsaSha224
            | SignatureAlgorithm::EcdsaSha256
            | SignatureAlgorithm::EcdsaSha384
            | SignatureAlgorithm::EcdsaSha512
            | SignatureAlgorithm::EcdsaSha3_224
            | SignatureAlgorithm::EcdsaSha3_256
            | SignatureAlgorithm::EcdsaSha3_384
            | SignatureAlgorithm::EcdsaSha3_512 => Ok(()),
        };
        result.map_err(DsigError::Crypto)
    }

    /// `SignatureValue` framing check under `encoding`, reading the SPKI
    /// under `session`.
    fn signature_value_in(
        &self,
        algorithm: SignatureAlgorithm,
        signature_value: &[u8],
        encoding: crate::policy::EcdsaSignatureValueEncoding,
        session: &super::pkix::CertificateSession,
    ) -> Result<bool, DsigError> {
        if algorithm != self.algorithm {
            return Err(KeyResolutionError::AlgorithmMismatch.into());
        }
        signature_value_matches_spki_with_encoding(
            algorithm,
            &self.public_key_bytes,
            signature_value,
            encoding,
            session,
        )
        .map_err(DsigError::Crypto)
    }

    /// Signature check under `encoding`, reading the SPKI under `session`.
    /// Only `EdDSA` and post-quantum methods accept a non-empty `context`.
    fn verify_in(
        &self,
        algorithm: SignatureAlgorithm,
        context: &super::SignatureContext,
        signed_data: &[u8],
        signature_value: &[u8],
        encoding: crate::policy::EcdsaSignatureValueEncoding,
        session: &super::pkix::CertificateSession,
    ) -> Result<bool, DsigError> {
        if algorithm != self.algorithm {
            return Err(KeyResolutionError::AlgorithmMismatch.into());
        }
        let key = &self.public_key_bytes;
        #[cfg(feature = "dstu4145")]
        let dstu4145 = algorithm.dstu4145_digest().is_some();
        #[cfg(not(feature = "dstu4145"))]
        let dstu4145 = false;
        let result = if dstu4145
            || algorithm.eddsa_signature_len().is_some()
            || matches!(algorithm, SignatureAlgorithm::PostQuantum(_))
        {
            super::modern::verify_with_context(
                algorithm,
                key,
                context,
                signed_data,
                signature_value,
                session,
            )
        } else if !context.as_bytes().is_empty() {
            return Err(KeyResolutionError::AlgorithmMismatch.into());
        } else if algorithm.is_rsa() {
            verify_rsa_signature_spki_primitive(
                algorithm,
                key,
                signed_data,
                signature_value,
                session,
            )
        } else if algorithm.ecdsa_digest().is_some() {
            verify_ecdsa_signature_spki_in(
                algorithm,
                key,
                signed_data,
                signature_value,
                encoding,
                session,
            )
        } else if matches!(
            algorithm,
            SignatureAlgorithm::DsaSha1 | SignatureAlgorithm::DsaSha256
        ) {
            verify_dsa_signature_spki_primitive(
                algorithm,
                key,
                signed_data,
                signature_value,
                session,
            )
        } else {
            // HMAC methods need a secret, not a public key.
            return Err(KeyResolutionError::AlgorithmMismatch.into());
        };
        result.map_err(DsigError::Crypto)
    }
}

impl VerifyingKey for VerificationKey {
    fn association_spki(&self, algorithm: SignatureAlgorithm) -> Option<&[u8]> {
        if algorithm == self.algorithm {
            Some(&self.public_key_bytes)
        } else {
            None
        }
    }
    fn verification_spki(&self, algorithm: SignatureAlgorithm) -> Result<Option<&[u8]>, DsigError> {
        if algorithm != self.algorithm {
            return Err(KeyResolutionError::AlgorithmMismatch.into());
        }
        Ok(Some(&self.public_key_bytes))
    }
    // The hooks without a scope serve standalone use outside any operation,
    // so they read the key under the standalone account.
    fn verify_with_context(
        &self,
        algorithm: SignatureAlgorithm,
        context: &super::SignatureContext,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, DsigError> {
        self.verify_in(
            algorithm,
            context,
            data,
            signature,
            crate::policy::EcdsaSignatureValueEncoding::XmlDsig,
            &super::pkix::CertificateSession::standalone(),
        )
    }
    fn validate_policy(&self, scope: &super::VerificationScope<'_>) -> Result<(), DsigError> {
        let trust = &scope.policy().key_trust;
        self.validate_in(
            trust.rsa_keys.minimum_modulus_bits,
            trust.dsa_keys.minimum_modulus_bits,
            scope.certificates(),
        )
    }

    fn validate_signature_value(
        &self,
        algorithm: SignatureAlgorithm,
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        self.signature_value_in(
            algorithm,
            signature_value,
            crate::policy::EcdsaSignatureValueEncoding::XmlDsig,
            &super::pkix::CertificateSession::standalone(),
        )
    }

    fn validate_signature_value_with_policy(
        &self,
        scope: &super::VerificationScope<'_>,
        algorithm: SignatureAlgorithm,
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        self.signature_value_in(
            algorithm,
            signature_value,
            scope.policy().ecdsa_signature_value_encoding,
            scope.certificates(),
        )
    }

    fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        signed_data: &[u8],
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        self.verify_with_context(
            algorithm,
            &super::SignatureContext::default(),
            signed_data,
            signature_value,
        )
    }

    fn verify_with_policy(
        &self,
        scope: &super::VerificationScope<'_>,
        algorithm: SignatureAlgorithm,
        context: &super::SignatureContext,
        signed_data: &[u8],
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        self.verify_in(
            algorithm,
            context,
            signed_data,
            signature_value,
            scope.policy().ecdsa_signature_value_encoding,
            scope.certificates(),
        )
    }
}

struct PolicyBoundVerificationKey {
    key: VerificationKey,
    rsa_minimum_bits: usize,
    dsa_minimum_bits: usize,
    /// The resolving operation's account; reads of this key charge it.
    certificates: super::pkix::CertificateSession,
    // Last field: key storage is released before its accounting guards.
    _storage: Option<VerificationKeyStorage>,
}

impl PolicyBoundVerificationKey {
    /// Strength checks bound at resolution, then the signature check, all
    /// reading the SPKI under `session`.
    fn verify_in(
        &self,
        algorithm: SignatureAlgorithm,
        context: &super::SignatureContext,
        signed_data: &[u8],
        signature_value: &[u8],
        encoding: crate::policy::EcdsaSignatureValueEncoding,
        session: &super::pkix::CertificateSession,
    ) -> Result<bool, DsigError> {
        if algorithm != self.key.algorithm {
            return Err(KeyResolutionError::AlgorithmMismatch.into());
        }
        // RSA and DSA accept no context, so the key check below refuses a
        // non-empty one before any strength check.
        if context.as_bytes().is_empty() {
            match algorithm {
                SignatureAlgorithm::DsaSha1 | SignatureAlgorithm::DsaSha256 => {
                    validate_dsa_signature_spki_with_minimum(
                        &self.key.public_key_bytes,
                        self.dsa_minimum_bits,
                        session,
                    )
                }
                algorithm if algorithm.is_rsa() => validate_rsa_signature_spki_with_minimum(
                    algorithm,
                    &self.key.public_key_bytes,
                    self.rsa_minimum_bits,
                    session,
                ),
                _ => Ok(()),
            }
            .map_err(DsigError::Crypto)?;
        }
        self.key.verify_in(
            algorithm,
            context,
            signed_data,
            signature_value,
            encoding,
            session,
        )
    }
}

struct VerificationKeyStorage {
    _reservation: structured_asn1::memory::MemoryReservation,
}

impl VerificationKeyStorage {
    fn reserve(
        session: &super::pkix::CertificateSession,
        public_key_bytes: usize,
        certificate_bytes: usize,
        name_bytes: usize,
    ) -> Result<Self, KeyResolutionError> {
        let reserve = |bytes| {
            session.memory().reserve(bytes).map_err(|reason| {
                certificate_resolution_error(session.error(structured_pkix::Error::resource(
                    reason,
                    "verification.key",
                    0,
                )))
            })
        };
        let work = (public_key_bytes as u64)
            .checked_add(certificate_bytes as u64)
            .and_then(|work| work.checked_add(name_bytes as u64))
            .ok_or_else(|| {
                certificate_resolution_error(session.error(structured_pkix::Error::resource(
                    structured_asn1::memory::MemoryError::WorkExceeded,
                    "verification.key",
                    0,
                )))
            })?;
        session.memory().charge_work(work).map_err(|reason| {
            certificate_resolution_error(session.error(structured_pkix::Error::resource(
                reason,
                "verification.key",
                0,
            )))
        })?;
        let capacity = usize::try_from(work)
            .ok()
            .and_then(|bytes| bytes.checked_add(core::mem::size_of::<PolicyBoundVerificationKey>()))
            .ok_or_else(|| {
                certificate_resolution_error(session.error(structured_pkix::Error::resource(
                    structured_asn1::memory::MemoryError::CapacityOverflow,
                    "verification.key",
                    0,
                )))
            })?;
        Ok(Self {
            _reservation: reserve(capacity)?,
        })
    }
}

impl VerifyingKey for PolicyBoundVerificationKey {
    fn association_spki(&self, algorithm: SignatureAlgorithm) -> Option<&[u8]> {
        self.key.association_spki(algorithm)
    }
    fn verification_spki(&self, algorithm: SignatureAlgorithm) -> Result<Option<&[u8]>, DsigError> {
        // Preserve strength checks carried by this resolver-produced handle.
        if algorithm.is_rsa() {
            validate_rsa_signature_spki_with_minimum(
                algorithm,
                &self.key.public_key_bytes,
                self.rsa_minimum_bits,
                &self.certificates,
            )
            .map_err(DsigError::Crypto)?;
        }
        self.key.verification_spki(algorithm)
    }
    fn verify_with_context(
        &self,
        algorithm: SignatureAlgorithm,
        context: &super::SignatureContext,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, DsigError> {
        self.verify_in(
            algorithm,
            context,
            data,
            signature,
            crate::policy::EcdsaSignatureValueEncoding::XmlDsig,
            &self.certificates,
        )
    }
    fn validate_signature_value(
        &self,
        algorithm: SignatureAlgorithm,
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        self.key.signature_value_in(
            algorithm,
            signature_value,
            crate::policy::EcdsaSignatureValueEncoding::XmlDsig,
            &self.certificates,
        )
    }

    fn validate_signature_value_with_policy(
        &self,
        scope: &super::VerificationScope<'_>,
        algorithm: SignatureAlgorithm,
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        self.key
            .validate_signature_value_with_policy(scope, algorithm, signature_value)
    }

    fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        signed_data: &[u8],
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        self.verify_with_context(
            algorithm,
            &super::SignatureContext::default(),
            signed_data,
            signature_value,
        )
    }

    fn verify_with_policy(
        &self,
        scope: &super::VerificationScope<'_>,
        algorithm: SignatureAlgorithm,
        context: &super::SignatureContext,
        signed_data: &[u8],
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        self.verify_in(
            algorithm,
            context,
            signed_data,
            signature_value,
            scope.policy().ecdsa_signature_value_encoding,
            scope.certificates(),
        )
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
    /// Certificate validation has no time: the caller supplied none and the
    /// host clock is unavailable or outside the representable range.
    #[error("system time is unavailable")]
    SystemTime,
}

/// Configuration for the default `XMLDSig` key resolver.
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
    /// Caller-owned revocation evidence applied without copying it into each XML source.
    pub crls: Vec<Vec<u8>>,
    /// Verification keys addressable by `<KeyName>` content.
    pub named_keys: BTreeMap<String, VerificationKey>,
}

/// Configuration-driven resolver for embedded certificates, DER keys, and key names.
#[derive(Debug, Clone, Default)]
pub struct DefaultKeyResolver {
    config: KeyResolverConfig,
}

#[derive(Clone, Copy)]
pub(crate) enum ResolutionScope {
    Document,
    Trusted,
    DocumentPrefix(usize),
    TrustedPrefix(usize),
    DocumentSuffix(usize),
    TrustedSuffix(usize),
}

impl ResolutionScope {
    /// Whether the scanned sources come from the document rather than the caller.
    fn document_sources(self) -> bool {
        matches!(
            self,
            Self::Document | Self::DocumentPrefix(_) | Self::DocumentSuffix(_)
        )
    }

    /// The `KeyInfo` source positions this scope scans out of `len`.
    fn source_range(self, len: usize) -> core::ops::Range<usize> {
        let start = match self {
            Self::DocumentSuffix(start) | Self::TrustedSuffix(start) => start,
            _ => 0,
        };
        let end = match self {
            Self::DocumentPrefix(end) | Self::TrustedPrefix(end) => end,
            _ => len,
        };
        start..end
    }
}

/// Configured certificates pooled for one `X509Data` lookup.
struct ConfiguredX509Pool<'a> {
    available: BorrowedX509Pool<'a>,
    /// Pool indices matching any selector.
    matches: structured_asn1::memory::OwnedVec<usize>,
    /// Trusted certificates occupy this many leading pool entries.
    trusted_prefix_len: usize,
}

/// A key resolved from one `KeyInfo` source, before trust classification.
struct SourceCandidate {
    key: VerificationKey,
    evidence: Option<X509TrustEvidence>,
    storage: Option<VerificationKeyStorage>,
    caller_trusted: bool,
}

impl SourceCandidate {
    /// Bind the operation's key-strength minimums and classify trust: path
    /// evidence, then caller trust; cryptographic-only mode trusts nothing.
    fn bind(
        self,
        policy: &crate::policy::VerificationPolicy,
        certificates: &super::pkix::CertificateSession,
    ) -> ResolvedVerificationKey<'static> {
        let trust = &policy.key_trust;
        let key = Box::new(PolicyBoundVerificationKey {
            key: self.key,
            rsa_minimum_bits: trust.rsa_keys.minimum_modulus_bits,
            dsa_minimum_bits: trust.dsa_keys.minimum_modulus_bits,
            certificates: certificates.share(),
            _storage: self.storage,
        });
        if trust.mode == crate::policy::VerificationTrustMode::CryptographicOnly {
            ResolvedVerificationKey::Candidate(key)
        } else if let Some(evidence) = self.evidence {
            ResolvedVerificationKey::Validated(TrustedPublicKey::new(key, trust.clone(), evidence))
        } else if self.caller_trusted {
            ResolvedVerificationKey::CallerTrusted(key)
        } else {
            ResolvedVerificationKey::Candidate(key)
        }
    }
}

/// A `DEREncodedKeyValue` candidate whose SPKI matches `algorithm`.
fn der_key_value_candidate(
    public_key_bytes: &[u8],
    algorithm: SignatureAlgorithm,
    candidate_budget: &mut InspectedKeyCandidateBudget,
    caller_trusted: bool,
) -> Result<SourceCandidate, DsigError> {
    candidate_budget.charge()?;
    validate_spki_algorithm(&candidate_budget.certificates, public_key_bytes, algorithm)?;
    let storage = VerificationKeyStorage::reserve(
        &candidate_budget.certificates,
        public_key_bytes.len(),
        0,
        0,
    )?;
    Ok(SourceCandidate {
        key: VerificationKey {
            algorithm,
            public_key_bytes: public_key_bytes.to_vec(),
            certificate_der: None,
            name: None,
        },
        evidence: None,
        storage: Some(storage),
        caller_trusted,
    })
}

/// A partial source scan separates a deferred mismatch from terminal errors.
/// Continuations may retain the former, but cannot retry the latter.
pub(crate) struct SourceResolution {
    pub(crate) key: Option<ResolvedVerificationKey<'static>>,
    pub(crate) deferred_error: Option<KeyResolutionError>,
}

impl SourceResolution {
    pub(crate) fn finish(self) -> Result<Option<ResolvedVerificationKey<'static>>, DsigError> {
        if let Some(error) = self.deferred_error {
            return Err(error.into());
        }
        Ok(self.key)
    }
}

/// Counts candidates actually inspected by one resolver invocation.
///
/// Parser cardinality preflights prevent expensive materialization, but do not
/// replace this runtime accounting: embedded and indirect candidates both
/// consume resolver work when inspected.
/// Cumulative source-inspection work shared across one key resolution operation.
/// Reuse this budget when resolving multiple caller-owned candidate records.
#[derive(Debug)]
pub struct InspectedKeyCandidateBudget<'a> {
    maximum: usize,
    attempted: usize,
    certificates: super::pkix::CertificateSession,
    utc_facts: Option<structured_pkix::temporal::LeapTable<'a>>,
}

impl<'a> InspectedKeyCandidateBudget<'a> {
    /// Start shared accounting derived solely from the operation policy.
    #[must_use]
    pub fn new(policy: &crate::policy::VerificationPolicy) -> Self {
        Self::from_inputs(policy, None)
    }

    /// Start an operation with caller-supplied UTC history. The table is
    /// borrowed request evidence, not a policy rule or an implicit clock.
    #[must_use]
    pub fn new_with_utc_facts(
        policy: &crate::policy::VerificationPolicy,
        facts: structured_pkix::temporal::LeapTable<'a>,
    ) -> Self {
        Self::from_inputs(policy, Some(facts))
    }

    fn from_inputs(
        policy: &crate::policy::VerificationPolicy,
        utc_facts: Option<structured_pkix::temporal::LeapTable<'a>>,
    ) -> Self {
        Self {
            maximum: policy.resources.max_key_candidates,
            attempted: 0,
            certificates: super::pkix::CertificateSession::new(&policy.resources),
            utc_facts,
        }
    }

    pub(crate) fn with_ingestion(
        policy: &crate::policy::VerificationPolicy,
        certificates: &super::pkix::CertificateSession,
        utc_facts: Option<structured_pkix::temporal::LeapTable<'a>>,
    ) -> Self {
        Self {
            maximum: policy.resources.max_key_candidates,
            attempted: 0,
            certificates: certificates.share(),
            utc_facts,
        }
    }

    /// UTC evidence captured for this operation. Absence does not supply an
    /// invented history, and rebinding policy cannot replace these facts.
    #[must_use]
    pub fn utc_facts(&self) -> Option<&structured_pkix::temporal::LeapTable<'a>> {
        self.utc_facts.as_ref()
    }

    /// Current certificate execution account, shared with ingestion by core operations.
    /// Custom resolvers must use this account for their certificate mechanism work;
    /// failed attempts spend work and retained allocations keep their original charge.
    #[must_use]
    pub fn execution(&self) -> &structured_asn1::memory::Memory {
        self.certificates.memory()
    }

    pub(crate) fn certificates(&self) -> &super::pkix::CertificateSession {
        &self.certificates
    }

    /// The scope a resolver passes to [`VerifyingKey::validate_policy`] when
    /// it checks a candidate before returning it, so the check reads key
    /// material under this operation's account.
    #[must_use]
    pub fn verification_scope<'s>(
        &'s self,
        policy: &'s crate::policy::VerificationPolicy,
    ) -> super::VerificationScope<'s> {
        super::VerificationScope::new(policy, &self.certificates)
    }

    pub(crate) fn bind_policy(
        &mut self,
        policy: &crate::policy::VerificationPolicy,
    ) -> Result<(), DsigError> {
        policy.resources.validate()?;
        self.certificates.require_resources(&policy.resources)?;
        self.maximum = self.maximum.min(policy.resources.max_key_candidates);
        self.charge_many(0)
    }

    /// Reserve one direct-key inspection before copying or decoding it.
    ///
    /// # Errors
    /// Returns a resource-policy error if the operation has no remaining
    /// candidate allowance. Failed attempts do not restore the allowance.
    pub fn charge(&mut self) -> Result<(), DsigError> {
        self.charge_many(1)
    }

    pub(crate) fn charge_many(&mut self, count: usize) -> Result<(), DsigError> {
        self.charge_policy(count).map_err(Into::into)
    }

    pub(crate) fn charge_policy(
        &mut self,
        count: usize,
    ) -> Result<(), crate::policy::PolicyViolation> {
        if self.attempted > self.maximum || count > self.maximum - self.attempted {
            return Err(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::KEY_CANDIDATES,
                maximum: self.maximum,
                actual: self.attempted.saturating_add(count),
            });
        }
        debug_assert!(self.attempted <= self.maximum);
        self.attempted += count;
        Ok(())
    }
}

pub(crate) fn validate_key_info_source_permissions(
    key_info: &KeyInfo,
    allowed: crate::policy::KeySourcePolicy,
) -> Result<(), crate::policy::PolicyViolation> {
    use crate::policy::KeySourceKind;

    for source in &key_info.sources {
        let disabled_reason = match source {
            KeyInfoSource::X509Data(_) if !allowed.contains(KeySourceKind::X509Data) => {
                Some("X509Data key sources are disabled")
            }
            KeyInfoSource::DerEncodedKeyValue(_)
                if !allowed.contains(KeySourceKind::DerEncodedKeyValue) =>
            {
                Some("DEREncodedKeyValue key sources are disabled")
            }
            KeyInfoSource::KeyName(_) if !allowed.contains(KeySourceKind::KeyName) => {
                Some("KeyName key sources are disabled")
            }
            KeyInfoSource::KeyValue(_) if !allowed.contains(KeySourceKind::KeyValue) => {
                Some("KeyValue key sources are disabled")
            }
            KeyInfoSource::KeyInfoReference { .. }
                if !allowed.contains(KeySourceKind::KeyInfoReference) =>
            {
                Some("KeyInfoReference key sources are disabled")
            }
            KeyInfoSource::X509Data(_)
            | KeyInfoSource::DerEncodedKeyValue(_)
            | KeyInfoSource::KeyName(_)
            | KeyInfoSource::KeyValue(_)
            | KeyInfoSource::RetrievalMethod { .. }
            | KeyInfoSource::KeyInfoReference { .. } => None,
        };
        if let Some(reason) = disabled_reason {
            return Err(crate::policy::PolicyViolation::KeyTrust { reason });
        }
    }
    Ok(())
}

impl DefaultKeyResolver {
    /// Resolve another candidate without resetting aggregate inspection work.
    /// The caller must keep the same budget throughout an operation, including
    /// failed attempts; policy denials must not be treated as candidate misses.
    ///
    /// # Errors
    /// Returns an error for invalid or incompatible policy resources, exhausted
    /// candidate/certificate work, invalid key material, or failed trust processing.
    pub fn resolve_with_candidate_budget(
        &self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
        policy: &crate::policy::VerificationPolicy,
        provider: &dyn crate::provider::CryptoProvider,
        candidate_budget: &mut InspectedKeyCandidateBudget,
    ) -> Result<Option<ResolvedVerificationKey<'static>>, DsigError> {
        candidate_budget.bind_policy(policy)?;
        self.resolve_with_trust(
            key_info,
            algorithm,
            policy,
            provider,
            candidate_budget,
            ResolutionScope::Document,
        )
    }

    pub(crate) fn resolve_trusted_material_with_candidate_budget(
        &self,
        key_info: &KeyInfo,
        algorithm: SignatureAlgorithm,
        policy: &crate::policy::VerificationPolicy,
        provider: &dyn crate::provider::CryptoProvider,
        candidate_budget: &mut InspectedKeyCandidateBudget,
    ) -> Result<Option<ResolvedVerificationKey<'static>>, DsigError> {
        self.resolve_with_trust(
            Some(key_info),
            algorithm,
            policy,
            provider,
            candidate_budget,
            ResolutionScope::Trusted,
        )
    }

    pub(crate) fn resolve_sources_with_candidate_budget(
        &self,
        key_info: &KeyInfo,
        algorithm: SignatureAlgorithm,
        policy: &crate::policy::VerificationPolicy,
        provider: &dyn crate::provider::CryptoProvider,
        candidate_budget: &mut InspectedKeyCandidateBudget,
        scope: ResolutionScope,
    ) -> Result<SourceResolution, DsigError> {
        self.resolve_source_range(
            Some(key_info),
            algorithm,
            policy,
            provider,
            candidate_budget,
            scope,
        )
    }
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

    fn check_configured_x509_material(
        &self,
        info: &X509DataInfo,
        resources: &crate::policy::ResourcePolicy,
        trust: &crate::policy::KeyTrustPolicy,
        budget: &mut InspectedKeyCandidateBudget,
        charge_crls: bool,
    ) -> Result<(), DsigError> {
        if charge_crls && trust.check_crls && trust.verify_x509_chains {
            budget.charge_many(self.config.crls.len())?;
        }
        let certificates = self
            .config
            .trusted_certs
            .iter()
            .chain(&self.config.lookup_certs);
        let crls = self
            .config
            .crls
            .iter()
            .filter(|_| trust.check_crls && trust.verify_x509_chains);
        let mut total = 0_usize;
        // Embedded and configured input share one admission limit, even though
        // the private path catalogue borrows rather than clones their bytes.
        for material in info
            .certificates
            .iter()
            .chain(&info.crls)
            .chain(certificates)
            .chain(crls)
        {
            if material.len() > resources.max_external_resource_bytes {
                return Err(crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
                    maximum: resources.max_external_resource_bytes,
                    actual: material.len(),
                }
                .into());
            }
            debug_assert!(total <= resources.max_external_resource_total_bytes);
            if material.len() > resources.max_external_resource_total_bytes - total {
                return Err(crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                    maximum: resources.max_external_resource_total_bytes,
                    actual: total.saturating_add(material.len()),
                }
                .into());
            }
            total += material.len();
        }
        Ok(())
    }

    fn resolve_x509(
        &self,
        info: &X509DataInfo,
        algorithm: SignatureAlgorithm,
        trust: &crate::policy::KeyTrustPolicy,
        provider: &dyn crate::provider::CryptoProvider,
        budget: &mut InspectedKeyCandidateBudget,
    ) -> Result<
        Option<(
            VerificationKey,
            Option<X509TrustEvidence>,
            VerificationKeyStorage,
        )>,
        DsigError,
    > {
        let mut evidence = None;
        let effective_trust;
        let trust = if trust.verify_x509_chains && trust.verification_time.is_none() {
            effective_trust = {
                let mut captured = trust.clone();
                // Without a host clock this stays `None`, and evidence
                // construction reports the missing verification time.
                captured.verification_time = crate::policy::clock::host_now();
                captured
            };
            &effective_trust
        } else {
            trust
        };
        let configured;
        let mut effective_key = None;
        let certificate_der = if let Some(&signing_index) = info.certificate_chain.first() {
            if trust.verify_x509_chains {
                let (path, key) =
                    self.prepare_embedded_x509(info, signing_index, trust, provider, budget)?;
                evidence = Some(Self::x509_trust_evidence(
                    &path,
                    trust,
                    &budget.certificates,
                )?);
                effective_key = key.effective_spki;
            } else {
                budget.charge_many(info.certificates.len())?;
            }
            info.certificates
                .get(signing_index)
                .ok_or(KeyResolutionError::InvalidCertificate)?
                .as_slice()
        } else {
            let Some((selected, key)) =
                self.resolve_configured_x509(info, trust, provider, budget)?
            else {
                return Ok(None);
            };
            if trust.verify_x509_chains {
                evidence = Some(Self::x509_trust_evidence(
                    &selected,
                    trust,
                    &budget.certificates,
                )?);
            }
            effective_key = key.effective_spki;
            configured = selected;
            configured
                .certificate_chain
                .first()
                .and_then(|index| configured.certificates.get(*index))
                .copied()
                .ok_or(KeyResolutionError::InvalidCertificate)?
        };

        let certificate = budget
            .certificates
            .read(certificate_der)
            .map_err(certificate_resolution_error)?;
        let spki = effective_key
            .as_deref()
            .unwrap_or_else(|| certificate.tbs().public_key().as_bytes());
        validate_spki_algorithm(&budget.certificates, spki, algorithm)?;
        let storage = VerificationKeyStorage::reserve(
            &budget.certificates,
            spki.len(),
            certificate_der.len(),
            0,
        )?;
        let public_key_bytes = spki.to_vec();
        drop(certificate);
        Ok(Some((
            VerificationKey {
                algorithm,
                public_key_bytes,
                certificate_der: Some(certificate_der.to_vec()),
                name: None,
            },
            evidence,
            storage,
        )))
    }

    fn x509_trust_evidence(
        info: &impl X509DataSource,
        trust: &crate::policy::KeyTrustPolicy,
        session: &super::pkix::CertificateSession,
    ) -> Result<X509TrustEvidence, DsigError> {
        let time = trust
            .verification_time
            .ok_or(KeyResolutionError::SystemTime)?;
        // Path fingerprints are internal identity, not signature permission.
        // Admit every source-byte hash before constructing the evidence.
        for index in info.chain() {
            session
                .memory()
                .charge_work(
                    info.certificate(*index)
                        .ok_or(KeyResolutionError::InvalidCertificate)?
                        .len() as u64,
                )
                .map_err(|reason| {
                    certificate_resolution_error(session.error(structured_pkix::Error::resource(
                        reason,
                        "certificate.path_identity",
                        0,
                    )))
                })?;
        }
        X509TrustEvidence::new(
            info.chain()
                .iter()
                .map(|index| info.certificate(*index).expect("validated path index")),
            time,
            trust.check_crls,
        )
    }

    fn verify_x509_policy(
        &self,
        info: &impl X509DataSource,
        trust: &crate::policy::KeyTrustPolicy,
        provider: &dyn crate::provider::CryptoProvider,
        budget: &InspectedKeyCandidateBudget<'_>,
    ) -> Result<super::pkix::ValidatedX509Key, KeyResolutionError> {
        let options = X509ChainOptions {
            utc_facts: budget.utc_facts().copied(),
            trusted_certs: &self.config.trusted_certs,
            verification_time: trust
                .verification_time
                .or_else(crate::policy::clock::host_now)
                .ok_or(KeyResolutionError::SystemTime)?,
            max_chain_depth: trust.max_x509_chain_depth,
            check_crls: trust.check_crls,
            allowed_extended_key_usages: Some(&trust.allowed_extended_key_usages),
            rsa_keys: trust.rsa_keys,
            dsa_keys: trust.dsa_keys,
            certificate_signature_algorithms: trust.certificate_signature_algorithms.as_ref(),
        };
        Ok(verify_x509_certificate_chain_in_session(
            info,
            &options,
            provider,
            &self.config.crls,
            &budget.certificates,
        )?)
    }

    fn prepare_embedded_x509<'a>(
        &'a self,
        info: &'a X509DataInfo,
        signing_index: usize,
        trust: &crate::policy::KeyTrustPolicy,
        provider: &dyn crate::provider::CryptoProvider,
        budget: &mut InspectedKeyCandidateBudget,
    ) -> Result<(BorrowedX509Pool<'a>, super::pkix::ValidatedX509Key), DsigError> {
        if signing_index >= info.certificates.len() {
            return Err(KeyResolutionError::InvalidCertificate.into());
        }
        let mut available = BorrowedX509Pool::new(&info.crls, &budget.certificates);
        let mut trusted_prefix_len = 0;
        for certificate in &self.config.trusted_certs {
            budget.charge()?;
            available.insert(certificate, &budget.certificates)?;
            trusted_prefix_len = available.certificates.len();
        }
        for certificate in &self.config.lookup_certs {
            budget.charge()?;
            available.insert(certificate, &budget.certificates)?;
        }
        let mut selected_index = None;
        for (index, certificate) in info.certificates.iter().enumerate() {
            budget.charge()?;
            let pool_index = available.insert(certificate, &budget.certificates)?;
            if index == signing_index {
                selected_index = Some(pool_index);
            }
        }
        let signing_index = selected_index.ok_or(KeyResolutionError::InvalidCertificate)?;
        let effective_key = self
            .select_valid_x509_path(
                &mut available,
                signing_index,
                trusted_prefix_len,
                trust,
                None,
                (provider, budget),
            )?
            .ok_or(KeyResolutionError::InvalidCertificate)?;
        Ok((available, effective_key))
    }

    fn select_valid_x509_path(
        &self,
        available: &mut BorrowedX509Pool<'_>,
        signing_index: usize,
        trusted_prefix_len: usize,
        trust: &crate::policy::KeyTrustPolicy,
        selectors: Option<&X509DataInfo>,
        execution: (
            &dyn crate::provider::CryptoProvider,
            &InspectedKeyCandidateBudget<'_>,
        ),
    ) -> Result<Option<super::pkix::ValidatedX509Key>, KeyResolutionError> {
        let (provider, budget) = execution;
        let certificates = &budget.certificates;
        let candidates = build_x509_certificate_paths_to_trusted_prefix(
            available,
            signing_index,
            trusted_prefix_len,
            super::parse::X509PathBounds {
                max_depth: trust.max_x509_chain_depth,
                max_candidate_paths: trust.max_x509_candidate_paths,
            },
            provider,
            trust.certificate_signature_algorithms.as_ref(),
            certificates,
        )
        .map_err(|error| match error {
            X509ChainBuildError::AmbiguousIssuer => KeyResolutionError::AmbiguousCertificate,
            X509ChainBuildError::Certificate(error) => KeyResolutionError::Chain(error),
            X509ChainBuildError::Policy(error) => {
                KeyResolutionError::Chain(super::X509ChainError::Policy(error))
            }
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
            match self.verify_x509_policy(available, trust, provider, budget) {
                Ok(effective_key) => {
                    if match selectors {
                        Some(selectors) => selected_x509_path_matches_selectors(
                            available,
                            selectors,
                            provider,
                            certificates,
                        )?,
                        None => true,
                    } {
                        return Ok(Some(effective_key));
                    }
                    valid_path_without_selector_match = true;
                }
                Err(error) => {
                    if matches!(&error, KeyResolutionError::Chain(failure) if failure.is_execution_failure())
                    {
                        return Err(error);
                    }
                    first_error.get_or_insert(error);
                }
            }
        }
        if valid_path_without_selector_match {
            return Ok(None);
        }
        Err(first_error.unwrap_or(KeyResolutionError::Chain(
            super::X509ChainError::UntrustedRoot,
        )))
    }

    fn select_x509_selector_path(
        available: &mut BorrowedX509Pool<'_>,
        signing_index: usize,
        matching_indices: &[usize],
        trust: &crate::policy::KeyTrustPolicy,
        selectors: &X509DataInfo,
        execution: (
            &dyn crate::provider::CryptoProvider,
            &super::pkix::CertificateSession,
        ),
    ) -> Result<bool, KeyResolutionError> {
        let (provider, certificates) = execution;
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
            super::parse::X509PathBounds {
                max_depth: trust.max_x509_chain_depth,
                max_candidate_paths: trust.max_x509_candidate_paths,
            },
            provider,
            trust.certificate_signature_algorithms.as_ref(),
            certificates,
        )
        .map_err(|error| match error {
            X509ChainBuildError::AmbiguousIssuer => KeyResolutionError::AmbiguousCertificate,
            X509ChainBuildError::Certificate(error) => KeyResolutionError::Chain(error),
            X509ChainBuildError::Policy(error) => {
                KeyResolutionError::Chain(super::X509ChainError::Policy(error))
            }
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
            if selected_x509_path_matches_selectors(available, selectors, provider, certificates)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn configured_signing_index(
        matches: &[usize],
        available: &BorrowedX509Pool<'_>,
        budget: &InspectedKeyCandidateBudget<'_>,
    ) -> Result<Option<usize>, DsigError> {
        match matches {
            [] => return Ok(None),
            [index] => return Ok(Some(*index)),
            _ => {}
        }
        let source = budget
            .certificates
            .read_sources(available.encoded_certificates())
            .map_err(certificate_resolution_error)?;
        let mut leaves = budget.certificates.memory().vector();
        for candidate in matches {
            let certificate = &source[*candidate];
            if budget
                .certificates
                .source_names_equal(certificate.tbs().subject(), certificate.tbs().issuer())
                .map_err(certificate_resolution_error)?
            {
                continue;
            }
            let mut issuer = false;
            for index in matches {
                if budget
                    .certificates
                    .source_names_equal(source[*index].tbs().issuer(), certificate.tbs().subject())
                    .map_err(certificate_resolution_error)?
                {
                    issuer = true;
                    break;
                }
            }
            if !issuer {
                leaves.try_push(*candidate).map_err(|reason| {
                    certificate_resolution_error(budget.certificates.error(
                        structured_pkix::Error::resource(reason, "certificate.selection", 0),
                    ))
                })?;
            }
        }
        match &leaves[..] {
            [index] => Ok(Some(*index)),
            _ => Err(KeyResolutionError::AmbiguousCertificate.into()),
        }
    }

    /// Pool the configured certificates, trusted first, deduplicated, and
    /// record which of them match any `X509Data` selector.
    fn configured_x509_pool<'a>(
        &'a self,
        info: &'a X509DataInfo,
        provider: &dyn crate::provider::CryptoProvider,
        budget: &mut InspectedKeyCandidateBudget,
    ) -> Result<ConfiguredX509Pool<'a>, DsigError> {
        let mut available = BorrowedX509Pool::new(&info.crls, &budget.certificates);
        let mut matches = budget.certificates.memory().vector();
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
            budget.charge()?;
            let previous_len = available.certificates.len();
            let pool_index = available.insert(certificate_der, &budget.certificates)?;
            if pool_index < previous_len {
                continue;
            }
            let is_match = x509_certificate_matches_any_selector(
                info,
                certificate_der,
                provider,
                &budget.certificates,
            )
            .map_err(map_x509_selector_error)?;
            if is_match {
                matches.try_push(pool_index).map_err(|reason| {
                    certificate_resolution_error(budget.certificates.error(
                        structured_pkix::Error::resource(reason, "certificate.selection", 0),
                    ))
                })?;
            }
            if trusted {
                trusted_prefix_len += 1;
            }
        }
        Ok(ConfiguredX509Pool {
            available,
            matches,
            trusted_prefix_len,
        })
    }

    fn resolve_configured_x509<'a>(
        &'a self,
        info: &'a X509DataInfo,
        trust: &crate::policy::KeyTrustPolicy,
        provider: &dyn crate::provider::CryptoProvider,
        budget: &mut InspectedKeyCandidateBudget,
    ) -> Result<Option<(BorrowedX509Pool<'a>, super::pkix::ValidatedX509Key)>, DsigError> {
        if !x509_data_has_lookup_identifiers(info) {
            return Ok(None);
        }

        let ConfiguredX509Pool {
            mut available,
            matches,
            trusted_prefix_len,
        } = self.configured_x509_pool(info, provider, budget)?;

        if !x509_selector_categories_match_candidates(
            info,
            matches.iter().map(|index| available.certificates[*index]),
            provider,
            &budget.certificates,
        )
        .map_err(map_x509_selector_error)?
        {
            return Ok(None);
        }

        let Some(signing_index) = Self::configured_signing_index(&matches, &available, budget)?
        else {
            return Ok(None);
        };
        // `available` preserves trusted certificates as a prefix. Selecting
        // one of those exact certificates is already a terminal trust
        // decision, even when the certificate is not self-signed.
        let effective_key = if signing_index < trusted_prefix_len || !trust.verify_x509_chains {
            available
                .certificate_chain
                .try_push(signing_index)
                .map_err(|reason| {
                    certificate_resolution_error(budget.certificates.error(
                        structured_pkix::Error::resource(reason, "certificate.path", 0),
                    ))
                })?;
            if trust.verify_x509_chains {
                self.verify_x509_policy(&available, trust, provider, budget)?
            } else {
                super::pkix::ValidatedX509Key {
                    effective_spki: None,
                }
            }
        } else {
            let Some(key) = self.select_valid_x509_path(
                &mut available,
                signing_index,
                trusted_prefix_len,
                trust,
                Some(info),
                (provider, budget),
            )?
            else {
                return Ok(None);
            };
            key
        };
        if !trust.verify_x509_chains || signing_index < trusted_prefix_len {
            let direct_match = selected_x509_path_matches_selectors(
                &available,
                info,
                provider,
                &budget.certificates,
            )?;
            if !direct_match
                && (signing_index < trusted_prefix_len
                    || !Self::select_x509_selector_path(
                        &mut available,
                        signing_index,
                        &matches,
                        trust,
                        info,
                        (provider, &budget.certificates),
                    )?)
            {
                return Ok(None);
            }
        }
        Ok(Some((available, effective_key)))
    }

    fn resolve_key_value(
        key_value: &KeyValueInfo,
        algorithm: SignatureAlgorithm,
        session: &super::pkix::CertificateSession,
    ) -> Result<Option<VerificationKey>, KeyResolutionError> {
        let public_key_bytes = match key_value {
            KeyValueInfo::Dsa { p, q, g, y } => {
                if !matches!(
                    algorithm,
                    SignatureAlgorithm::DsaSha1 | SignatureAlgorithm::DsaSha256
                ) {
                    return Err(KeyResolutionError::AlgorithmMismatch);
                }
                let (Some(p), Some(q), Some(g)) = (p.as_deref(), q.as_deref(), g.as_deref()) else {
                    return Err(KeyResolutionError::InvalidPublicKey);
                };
                dsa_key_value_to_spki_der(p, q, g, y)?
            }
            KeyValueInfo::Rsa { modulus, exponent } => {
                if !algorithm.is_rsa() {
                    return Err(KeyResolutionError::AlgorithmMismatch);
                }
                rsa_key_value_to_spki_der(modulus, exponent)?
            }
            KeyValueInfo::Ec {
                curve_oid,
                public_key,
            } => {
                if algorithm.ecdsa_digest().is_none() {
                    return Ok(None);
                }
                ec_key_value_to_spki_der(curve_oid, public_key)?
            }
            KeyValueInfo::InvalidEcKeyValue => return Err(KeyResolutionError::InvalidPublicKey),
            // DH key agreement keys cannot verify an XML signature.
            KeyValueInfo::Dh { .. } | KeyValueInfo::Unsupported { .. } => return Ok(None),
        };
        validate_spki_algorithm(session, &public_key_bytes, algorithm)?;

        Ok(Some(VerificationKey {
            algorithm,
            public_key_bytes,
            certificate_der: None,
            name: None,
        }))
    }

    /// Admit an `X509Data` source: selector permissions and configured
    /// material are checked before any candidate work or hashing.
    fn admit_x509_source(
        &self,
        info: &X509DataInfo,
        policy: &crate::policy::VerificationPolicy,
        candidate_budget: &mut InspectedKeyCandidateBudget,
        configured_material_checked: &mut bool,
    ) -> Result<(), DsigError> {
        let trust = &policy.key_trust;
        // Enforce selector permissions before candidate work or
        // hashing, including direct callers of this resolver.
        for (uri, _) in &info.digests {
            let algorithm = super::DigestAlgorithm::from_uri(uri)
                .ok_or_else(|| KeyResolutionError::UnsupportedDigestAlgorithm(uri.clone()))?;
            policy.check_digest_algorithm(algorithm)?;
        }
        let configured = if info.certificate_chain.is_empty() {
            x509_data_has_lookup_identifiers(info)
        } else {
            trust.verify_x509_chains
        };
        if configured {
            self.check_configured_x509_material(
                info,
                &policy.resources,
                trust,
                candidate_budget,
                !*configured_material_checked,
            )?;
            *configured_material_checked = true;
        }
        Ok(())
    }

    /// An admitted `X509Data` source; a pinned anchor makes it caller-trusted.
    fn x509_source_candidate(
        &self,
        info: &X509DataInfo,
        algorithm: SignatureAlgorithm,
        trust: &crate::policy::KeyTrustPolicy,
        provider: &dyn crate::provider::CryptoProvider,
        candidate_budget: &mut InspectedKeyCandidateBudget,
        caller_trusted: bool,
    ) -> Result<Option<SourceCandidate>, DsigError> {
        let Some((key, evidence, storage)) =
            self.resolve_x509(info, algorithm, trust, provider, candidate_budget)?
        else {
            return Ok(None);
        };
        let mut caller_trusted = caller_trusted;
        if evidence.is_none()
            && !caller_trusted
            && trust.mode == crate::policy::VerificationTrustMode::RequireTrustedKey
            && let Some(der) = key.certificate_der.as_ref()
        {
            // Pin lookup shares the same work allowance as
            // discovery; charge before each DER comparison.
            for anchor in &self.config.trusted_certs {
                candidate_budget.charge()?;
                if anchor == der {
                    caller_trusted = true;
                    break;
                }
            }
        }
        Ok(Some(SourceCandidate {
            key,
            evidence,
            storage: Some(storage),
            caller_trusted,
        }))
    }

    /// A configured key named by `KeyName`; its algorithm must match exactly.
    fn named_source_candidate(
        &self,
        name: &str,
        algorithm: SignatureAlgorithm,
        candidate_budget: &mut InspectedKeyCandidateBudget,
        caller_trusted: bool,
    ) -> Result<Option<SourceCandidate>, DsigError> {
        candidate_budget.charge()?;
        let Some(key) = self.config.named_keys.get(name) else {
            return Ok(None);
        };
        if key.algorithm != algorithm {
            return Err(KeyResolutionError::AlgorithmMismatch.into());
        }
        validate_spki_algorithm(
            &candidate_budget.certificates,
            &key.public_key_bytes,
            algorithm,
        )?;
        let storage = VerificationKeyStorage::reserve(
            &candidate_budget.certificates,
            key.public_key_bytes.len(),
            key.certificate_der.as_ref().map_or(0, Vec::len),
            key.name.as_ref().map_or(0, String::len),
        )?;
        Ok(Some(SourceCandidate {
            key: key.clone(),
            evidence: None,
            storage: Some(storage),
            caller_trusted,
        }))
    }

    fn resolve_with_trust(
        &self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
        policy: &crate::policy::VerificationPolicy,
        provider: &dyn crate::provider::CryptoProvider,
        candidate_budget: &mut InspectedKeyCandidateBudget,
        scope: ResolutionScope,
    ) -> Result<Option<ResolvedVerificationKey<'static>>, DsigError> {
        self.resolve_source_range(
            key_info,
            algorithm,
            policy,
            provider,
            candidate_budget,
            scope,
        )?
        .finish()
    }

    fn resolve_source_range(
        &self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
        policy: &crate::policy::VerificationPolicy,
        provider: &dyn crate::provider::CryptoProvider,
        candidate_budget: &mut InspectedKeyCandidateBudget,
        scope: ResolutionScope,
    ) -> Result<SourceResolution, DsigError> {
        let trust = &policy.key_trust;
        let resources = &policy.resources;
        trust.validate()?;
        resources.validate()?;
        candidate_budget.certificates.require_resources(resources)?;
        let Some(key_info) = key_info else {
            return Ok(SourceResolution {
                key: None,
                deferred_error: None,
            });
        };
        let document_sources = scope.document_sources();
        if document_sources {
            validate_key_info_source_permissions(key_info, policy.key_sources)?;
        }
        let mut deferred_key_value_error = None;
        let mut configured_material_checked = false;
        for source in &key_info.sources[scope.source_range(key_info.sources.len())] {
            if !document_sources && matches!(source, KeyInfoSource::KeyName(_)) {
                continue;
            }
            let caller_trusted = !document_sources || matches!(source, KeyInfoSource::KeyName(_));
            let candidate = match source {
                KeyInfoSource::X509Data(info) => {
                    self.admit_x509_source(
                        info,
                        policy,
                        candidate_budget,
                        &mut configured_material_checked,
                    )?;
                    self.x509_source_candidate(
                        info,
                        algorithm,
                        trust,
                        provider,
                        candidate_budget,
                        caller_trusted,
                    )?
                }
                KeyInfoSource::DerEncodedKeyValue(public_key_bytes) => {
                    Some(der_key_value_candidate(
                        public_key_bytes,
                        algorithm,
                        candidate_budget,
                        caller_trusted,
                    )?)
                }
                KeyInfoSource::KeyName(name) => {
                    self.named_source_candidate(name, algorithm, candidate_budget, caller_trusted)?
                }
                KeyInfoSource::KeyValue(key_value) => {
                    candidate_budget.charge()?;
                    match Self::resolve_key_value(
                        key_value,
                        algorithm,
                        &candidate_budget.certificates,
                    ) {
                        Ok(resolved) => resolved.map(|key| SourceCandidate {
                            key,
                            evidence: None,
                            storage: None,
                            caller_trusted,
                        }),
                        Err(error) if key_value_error_allows_fallback(key_value, &error) => {
                            deferred_key_value_error.get_or_insert(error);
                            None
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                KeyInfoSource::RetrievalMethod { .. } | KeyInfoSource::KeyInfoReference { .. } => {
                    candidate_budget.charge()?;
                    None
                }
            };
            if let Some(candidate) = candidate {
                return Ok(SourceResolution {
                    key: Some(candidate.bind(policy, &candidate_budget.certificates)),
                    deferred_error: None,
                });
            }
        }
        Ok(SourceResolution {
            key: None,
            deferred_error: deferred_key_value_error,
        })
    }
}

impl KeyResolver for DefaultKeyResolver {
    fn resolve_for_verification_with_budget<'a>(
        &'a self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
        policy: &crate::policy::VerificationPolicy,
        provider: &dyn crate::provider::CryptoProvider,
        budget: &mut InspectedKeyCandidateBudget,
    ) -> Result<Option<ResolvedVerificationKey<'a>>, DsigError> {
        self.resolve_with_candidate_budget(key_info, algorithm, policy, provider, budget)
    }

    fn resolve_for_verification<'a>(
        &'a self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
        policy: &crate::policy::VerificationPolicy,
        provider: &dyn crate::provider::CryptoProvider,
    ) -> Result<Option<ResolvedVerificationKey<'a>>, DsigError> {
        let mut budget = InspectedKeyCandidateBudget::new(policy);
        self.resolve_with_candidate_budget(key_info, algorithm, policy, provider, &mut budget)
    }
    fn resolve<'a>(
        &'a self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
    ) -> Result<Option<Box<dyn VerifyingKey + 'a>>, DsigError> {
        let policy = crate::policy::VerificationPolicy::default();
        let mut candidate_budget = InspectedKeyCandidateBudget::new(&policy);
        self.resolve_with_trust(
            key_info,
            algorithm,
            &policy,
            crate::provider::default_provider(),
            &mut candidate_budget,
            ResolutionScope::Document,
        )
        .map(|key| key.map(ResolvedVerificationKey::into_key))
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
        let mut candidate_budget = InspectedKeyCandidateBudget::new(policy);
        self.resolve_with_candidate_budget(
            key_info,
            algorithm,
            policy,
            provider,
            &mut candidate_budget,
        )
        .map(|key| key.map(ResolvedVerificationKey::into_key))
    }

    fn consumes_document_key_info(&self) -> bool {
        true
    }
}

fn map_x509_selector_error(error: ParseError) -> DsigError {
    match error {
        ParseError::Provider(error) => DsigError::Provider(error),
        ParseError::Policy(error) => error.into(),
        error => selector_resolution_error(error).into(),
    }
}

fn selector_resolution_error(error: ParseError) -> KeyResolutionError {
    match error {
        ParseError::Provider(error) => {
            KeyResolutionError::Chain(super::X509ChainError::Provider(error))
        }
        ParseError::Policy(error) => {
            KeyResolutionError::Chain(super::X509ChainError::Policy(error))
        }
        ParseError::Certificate(error) => {
            KeyResolutionError::Chain(super::X509ChainError::Processing(error))
        }
        ParseError::UnsupportedAlgorithm { uri } => {
            KeyResolutionError::UnsupportedDigestAlgorithm(uri)
        }
        _ => KeyResolutionError::InvalidCertificate,
    }
}

fn certificate_resolution_error(error: super::X509ChainError) -> KeyResolutionError {
    match error {
        error if error.is_execution_failure() => KeyResolutionError::Chain(error),
        super::X509ChainError::Processing(error) => {
            KeyResolutionError::Chain(super::X509ChainError::Processing(error))
        }
        _ => KeyResolutionError::InvalidCertificate,
    }
}

fn selected_x509_path_matches_selectors(
    available: &impl X509DataSource,
    selectors: &X509DataInfo,
    provider: &dyn crate::provider::CryptoProvider,
    certificates: &super::pkix::CertificateSession,
) -> Result<bool, KeyResolutionError> {
    x509_selector_categories_match_candidates(
        selectors,
        available
            .chain()
            .iter()
            .map(|index| available.certificate(*index).expect("selected path index")),
        provider,
        certificates,
    )
    .map_err(selector_resolution_error)
}

fn rsa_key_value_to_spki_der(
    modulus: &[u8],
    exponent: &[u8],
) -> Result<Vec<u8>, KeyResolutionError> {
    let (modulus, exponent) = bounded_rsa_public_components(modulus, exponent)?;
    let key = rsa::RsaPublicKey::new(
        BoxedUint::from_be_slice_vartime(modulus),
        BoxedUint::from_be_slice_vartime(exponent),
    )
    .map_err(|_| KeyResolutionError::InvalidPublicKey)?;
    key.to_public_key_der()
        .map_err(|_| KeyResolutionError::InvalidPublicKey)
        .map(|der| der.as_bytes().to_vec())
}

pub(crate) fn bounded_rsa_public_components<'a>(
    modulus: &'a [u8],
    exponent: &'a [u8],
) -> Result<(&'a [u8], &'a [u8]), KeyResolutionError> {
    let modulus = &modulus[modulus
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(modulus.len())..];
    let exponent = &exponent[exponent
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(exponent.len())..];
    let maximum = crate::hard_limits::RSA_MODULUS_BIT_CEILING;
    if modulus.is_empty()
        || exponent.is_empty()
        || modulus.len() > maximum.div_ceil(8)
        || exponent.len() > maximum.div_ceil(8)
        || (modulus.len() * 8 - modulus[0].leading_zeros() as usize) > maximum
    {
        return Err(KeyResolutionError::InvalidPublicKey);
    }
    Ok((modulus, exponent))
}

fn dsa_key_value_to_spki_der(
    p: &[u8],
    q: &[u8],
    g: &[u8],
    y: &[u8],
) -> Result<Vec<u8>, KeyResolutionError> {
    // Bound borrowed unsigned components before any bigint allocation or
    // subgroup exponentiation, not only after the SPKI has been produced.
    super::signature::dsa_verifying_key(p, q, g, y)
        .ok_or(KeyResolutionError::InvalidPublicKey)?
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
        EC_P521_OID => p521::PublicKey::from_sec1_bytes(public_key)
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
    session: &super::pkix::CertificateSession,
    public_key_bytes: &[u8],
    algorithm: SignatureAlgorithm,
) -> Result<(), KeyResolutionError> {
    use super::pkix::SpkiAlgorithm;
    if algorithm.rsa_pss_parameters().is_some() {
        // RFC 4055 section 1.2 requires id-RSASSA-PSS for PSS-only keys.
        // Share the borrowed RSA validator so resolver and provider enforce the
        // same parameter restrictions; the generic parser recognizes only rsaEncryption.
        // https://www.rfc-editor.org/rfc/rfc4055.html#section-1.2
        // Eight bits is structural validation only; the selected policy's
        // strength minimum is enforced on the resolved key before execution.
        return validate_rsa_signature_spki_with_minimum(algorithm, public_key_bytes, 8, session)
            .map_err(spki_check_error);
    }
    if algorithm.eddsa_signature_len().is_some()
        || matches!(algorithm, SignatureAlgorithm::PostQuantum(_))
    {
        return super::modern::validate_public_key(algorithm, public_key_bytes, session)
            .map_err(spki_check_error);
    }
    #[cfg(feature = "dstu4145")]
    if algorithm.dstu4145_digest().is_some() {
        return super::dstu4145::validate_public_key(public_key_bytes, session)
            .map_err(spki_check_error);
    }
    let family = session
        .spki_algorithm(public_key_bytes)
        .map_err(|error| structured_key_error(session, error))?;
    // RFC 5280 4.1.2.7: apply encoding rules only after identifying the key.
    // https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.7
    match (algorithm, family) {
        (SignatureAlgorithm::DsaSha1 | SignatureAlgorithm::DsaSha256, SpkiAlgorithm::Dsa) => {
            validate_dsa_spki(session, public_key_bytes)
        }
        (method, SpkiAlgorithm::RsaEncryption) if method.is_rsa() => {
            validate_rsa_spki(session, public_key_bytes)
        }
        (method, SpkiAlgorithm::Ec) if method.ecdsa_digest().is_some() => {
            validate_ec_spki_point(session, public_key_bytes)
        }
        _ => Err(KeyResolutionError::AlgorithmMismatch),
    }
}

pub(crate) fn supported_spki_is_rsa(
    session: &super::pkix::CertificateSession,
    public_key_bytes: &[u8],
) -> Result<bool, KeyResolutionError> {
    use super::pkix::SpkiAlgorithm;
    let modern = match session
        .spki_algorithm(public_key_bytes)
        .map_err(|error| structured_key_error(session, error))?
    {
        SpkiAlgorithm::PostQuantum(parameter) => SignatureAlgorithm::PostQuantum(parameter),
        SpkiAlgorithm::Ed25519 => SignatureAlgorithm::Ed25519,
        SpkiAlgorithm::Ed448 => SignatureAlgorithm::Ed448,
        SpkiAlgorithm::RsaEncryption => {
            validate_rsa_spki(session, public_key_bytes)?;
            crate::rsa_encoding::read_spki_public_key(session, public_key_bytes)
                .map_err(|error| structured_key_error(session, error))?
                .ok_or(KeyResolutionError::InvalidPublicKey)?;
            return Ok(true);
        }
        SpkiAlgorithm::Dsa => {
            validate_dsa_spki(session, public_key_bytes)?;
            return Ok(false);
        }
        SpkiAlgorithm::Ec => {
            validate_ec_spki_point(session, public_key_bytes)?;
            return Ok(false);
        }
        SpkiAlgorithm::RsaPss | SpkiAlgorithm::Other => {
            return Err(KeyResolutionError::AlgorithmMismatch);
        }
    };
    super::modern::validate_public_key(modern, public_key_bytes, session)
        .map_err(spki_check_error)?;
    Ok(false)
}

/// A shared SPKI check's refusal: exhausting the session stays a resource
/// failure; any other refusal is an invalid key.
fn spki_check_error(error: super::SignatureVerificationError) -> KeyResolutionError {
    match error {
        super::SignatureVerificationError::KeyPolicy(
            violation @ crate::policy::PolicyViolation::ResourceLimitExceeded { .. },
        ) => certificate_resolution_error(violation.into()),
        _ => KeyResolutionError::InvalidPublicKey,
    }
}

/// Exhausting the session stays a resource failure; every other refusal of the
/// key structure is an invalid key.
fn structured_key_error(
    session: &super::pkix::CertificateSession,
    error: structured_pkix::Error,
) -> KeyResolutionError {
    if error.is_resource() {
        certificate_resolution_error(session.error(error))
    } else {
        KeyResolutionError::InvalidPublicKey
    }
}

fn validate_rsa_spki(
    session: &super::pkix::CertificateSession,
    spki: &[u8],
) -> Result<(), KeyResolutionError> {
    let key = match session.read_public_key(spki) {
        Ok(super::pkix::PublicKey::Rsa(key)) => key,
        Ok(super::pkix::PublicKey::Ec(_)) => return Err(KeyResolutionError::InvalidPublicKey),
        Err(error) => return Err(structured_key_error(session, error)),
    };
    bounded_rsa_public_components(key.modulus().as_bytes(), key.exponent().as_bytes())?;
    Ok(())
}

fn validate_dsa_spki(
    session: &super::pkix::CertificateSession,
    spki: &[u8],
) -> Result<(), KeyResolutionError> {
    let key = session
        .read_dsa_public_key(spki)
        .map_err(|error| structured_key_error(session, error))?;
    // RFC 3279 section 2.3.2: a standalone key needs supplied domain parameters.
    // Shared inspection preserves absence; it does not invent an inherited group.
    // https://www.rfc-editor.org/rfc/rfc3279#section-2.3.2
    let parameters = key
        .parameters()
        .ok_or(KeyResolutionError::InvalidPublicKey)?;
    let [p, q, g, y] = [parameters.p(), parameters.q(), parameters.g(), key.y()]
        .map(structured_pkix::key::dsa::Component::as_bytes);
    // Borrowed magnitudes are bounded before bigint conversion; group/key
    // validity remains with RustCrypto.
    super::signature::dsa_verifying_key(p, q, g, y)
        .map(|_| ())
        .ok_or(KeyResolutionError::InvalidPublicKey)
}

fn validate_ec_spki_point(
    session: &super::pkix::CertificateSession,
    spki: &[u8],
) -> Result<(), KeyResolutionError> {
    let key = match session.read_public_key(spki) {
        Ok(super::pkix::PublicKey::Ec(key)) => key,
        // RFC 5480 2.1.1 requires ECParameters; without them no curve is named.
        Err(error) if error.code() == structured_pkix::ErrorCode::MissingField => {
            return Err(KeyResolutionError::AlgorithmMismatch);
        }
        Err(error) => return Err(structured_key_error(session, error)),
        Ok(super::pkix::PublicKey::Rsa(_)) => return Err(KeyResolutionError::InvalidPublicKey),
    };
    // RFC 5480 2.1.1: implicitCurve and specifiedCurve MUST NOT be used.
    // https://www.rfc-editor.org/rfc/rfc5480.html#section-2.1.1
    let structured_pkix::key::ec::Curve::Named(curve) = key.curve() else {
        return Err(KeyResolutionError::AlgorithmMismatch);
    };
    let curve = super::signature::EcCurve::from_oid_bytes(curve.as_bytes())
        .ok_or(KeyResolutionError::AlgorithmMismatch)?;
    let point = key.as_bytes();
    curve
        .validate_point(point)
        .map_err(|_| KeyResolutionError::InvalidPublicKey)?;
    match curve {
        super::signature::EcCurve::P256 => p256::PublicKey::from_sec1_bytes(point).map(|_| ()),
        super::signature::EcCurve::P384 => p384::PublicKey::from_sec1_bytes(point).map(|_| ()),
        super::signature::EcCurve::P521 => p521::PublicKey::from_sec1_bytes(point).map(|_| ()),
    }
    .map_err(|_| KeyResolutionError::InvalidPublicKey)
}

pub(crate) fn supported_key_value_is_rsa(
    session: &super::pkix::CertificateSession,
    value: &KeyValueInfo,
) -> Result<bool, KeyResolutionError> {
    let (spki, is_rsa) = match value {
        KeyValueInfo::Rsa { modulus, exponent } => {
            (rsa_key_value_to_spki_der(modulus, exponent)?, true)
        }
        KeyValueInfo::Dsa {
            p: Some(p),
            q: Some(q),
            g: Some(g),
            y,
        } => (dsa_key_value_to_spki_der(p, q, g, y)?, false),
        KeyValueInfo::Ec {
            curve_oid,
            public_key,
        } => (ec_key_value_to_spki_der(curve_oid, public_key)?, false),
        _ => return Err(KeyResolutionError::InvalidPublicKey),
    };
    let algorithm = if is_rsa {
        SignatureAlgorithm::RsaSha256
    } else if matches!(value, KeyValueInfo::Dsa { .. }) {
        SignatureAlgorithm::DsaSha256
    } else {
        SignatureAlgorithm::EcdsaSha256
    };
    validate_spki_algorithm(session, &spki, algorithm)?;
    Ok(is_rsa)
}

#[cfg(test)]
mod tests {
    use crate::xml::dom as roxmltree;
    use alloc::collections::BTreeSet;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use base64::{Engine, engine::general_purpose::STANDARD};
    #[cfg(feature = "xmldsig-sign")]
    use der::Decode as _;
    use pkcs8::DecodePublicKey as _;
    use rcgen::{
        CertificateRevocationListParams, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose,
        RevokedCertParams, SerialNumber, date_time_ymd,
    };
    use rsa::traits::PublicKeyParts;

    use super::*;

    #[test]
    fn shared_candidate_budget_cannot_relax_active_policy() {
        // A policy-derived budget cannot override policy, nor can a
        // later tighter snapshot forget work already performed.
        let resolver = DefaultKeyResolver::new(KeyResolverConfig::default());
        let info = KeyInfo {
            sources: vec![KeyInfoSource::KeyName("missing".into())],
        };
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.resources.max_key_candidates = 1;
        let mut budget = InspectedKeyCandidateBudget::new(&policy);
        assert!(
            resolver
                .resolve_with_candidate_budget(
                    Some(&info),
                    SignatureAlgorithm::RsaSha256,
                    &policy,
                    crate::provider::default_provider(),
                    &mut budget
                )
                .expect("first candidate fits the active policy")
                .is_none()
        );
        assert!(matches!(
            resolver.resolve_with_candidate_budget(
                Some(&info),
                SignatureAlgorithm::RsaSha256,
                &policy,
                crate::provider::default_provider(),
                &mut budget
            ),
            Err(DsigError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    maximum: 1,
                    actual: 2,
                    ..
                }
            ))
        ));
        let mut spent =
            InspectedKeyCandidateBudget::new(&crate::policy::VerificationPolicy::default());
        spent
            .charge_many(2)
            .expect("initial budget admits two candidates");
        assert!(matches!(
            resolver.resolve_with_candidate_budget(
                None,
                SignatureAlgorithm::RsaSha256,
                &policy,
                crate::provider::default_provider(),
                &mut spent
            ),
            Err(DsigError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    maximum: 1,
                    actual: 2,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn dsa_key_value_components_are_bounded_before_bigint_decode() {
        // Every unsigned XML component uses the same pre-conversion ceiling;
        // redundant zero padding must not inflate bigint precision or change it.
        let public = dsa::VerifyingKey::from_public_key_pem(include_str!(
            "../../tests/fixtures/keys/dsa/dsa-2048-public.pem"
        ))
        .expect("DSA fixture");
        let components = public.components();
        let values = [
            components.p().to_be_bytes_trimmed_vartime().to_vec(),
            components.q().to_be_bytes_trimmed_vartime().to_vec(),
            components.g().to_be_bytes_trimmed_vartime().to_vec(),
            public.y().to_be_bytes_trimmed_vartime().to_vec(),
        ];
        let expected = dsa_key_value_to_spki_der(&values[0], &values[1], &values[2], &values[3])
            .expect("valid DSA");
        for index in 0..4 {
            let mut oversized = values.clone();
            oversized[index] = vec![1; crate::hard_limits::DSA_KEY_COMPONENT_BYTE_CEILING + 1];
            assert!(
                dsa_key_value_to_spki_der(
                    &oversized[0],
                    &oversized[1],
                    &oversized[2],
                    &oversized[3]
                )
                .is_err()
            );
        }
        let padded = values.map(|value| {
            let mut padded = vec![0; 1024];
            padded.extend(value);
            padded
        });
        assert_eq!(
            dsa_key_value_to_spki_der(&padded[0], &padded[1], &padded[2], &padded[3])
                .expect("zero padding preserves unsigned DSA value"),
            expected
        );
    }

    #[test]
    fn opaque_spki_reports_algorithm_mismatch_before_key_octet_rules()
    -> Result<(), Box<dyn std::error::Error>> {
        // RFC 5280 4.1.2.7: an unknown algorithm cannot inherit a known
        // algorithm's key encoding. Resolution still refuses unsupported keys.
        // https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.7
        let opaque = pkcs8::SubjectPublicKeyInfoRef {
            algorithm: pkcs8::AlgorithmIdentifierRef {
                oid: der::asn1::ObjectIdentifier::new_unwrap("1.2.3.4"),
                parameters: None,
            },
            subject_public_key: der::asn1::BitStringRef::new(1, &[0])?,
        };
        let encoded = der::Encode::to_der(&opaque)?;
        let session =
            super::super::pkix::CertificateSession::new(&crate::policy::ResourcePolicy::default());
        assert!(matches!(
            supported_spki_is_rsa(&session, &encoded),
            Err(KeyResolutionError::AlgorithmMismatch)
        ));
        for method in [
            SignatureAlgorithm::RsaSha256,
            SignatureAlgorithm::DsaSha256,
            SignatureAlgorithm::EcdsaSha256,
        ] {
            assert!(matches!(
                validate_spki_algorithm(&session, &encoded, method),
                Err(KeyResolutionError::AlgorithmMismatch)
            ));
        }
        Ok(())
    }

    #[test]
    fn borrowed_certificate_pool_retains_identity_and_capacity_charge()
    -> Result<(), Box<dyn std::error::Error>> {
        // Private selection borrows source bytes, deduplicates without moving
        // the trusted prefix, and retains its index allocation until drop.
        let bytes = [7u8; 1024];
        let duplicate = bytes;
        let session =
            super::super::pkix::CertificateSession::new(&crate::policy::ResourcePolicy::default());
        let mut pool = BorrowedX509Pool::new(&[], &session);
        assert_eq!(pool.insert(&bytes, &session)?, 0);
        let allocated_work = session.memory().work_used();
        assert_eq!(pool.insert(&bytes, &session)?, 0);
        assert_eq!(session.memory().work_used(), allocated_work);
        assert_eq!(pool.insert(&duplicate, &session)?, 0);
        assert_eq!(pool.certificates.len(), 1);
        assert_eq!(
            pool.certificate(0).map(<[u8]>::as_ptr),
            Some(bytes.as_ptr())
        );
        assert_eq!(
            session.memory().used(),
            pool.certificates.capacity() * core::mem::size_of::<&[u8]>(),
        );
        assert_eq!(session.memory().work_used() - allocated_work, bytes.len());
        drop(pool);
        assert_eq!(session.memory().used(), 0);
        let bounded = super::super::pkix::CertificateSession::new(&crate::policy::ResourcePolicy {
            max_x509_workspace_bytes: core::mem::size_of::<&[u8]>() - 1,
            ..Default::default()
        });
        let mut pool = BorrowedX509Pool::new(&[], &bounded);
        assert!(pool.insert(&bytes, &bounded).is_err());
        assert!(pool.certificates.is_empty());
        assert_eq!(bounded.memory().used(), 0);
        Ok(())
    }

    #[test]
    fn resolved_key_storage_keeps_its_execution_reservation() {
        // Returned keys own their projections: releasing parser scratch must
        // not release the charge while the verification key is still alive.
        let key = rcgen::KeyPair::generate().expect("EC key generation");
        let encoded = rcgen::PublicKeyData::subject_public_key_info(&key);
        let policy = crate::policy::VerificationPolicy::default();
        let mut budget = InspectedKeyCandidateBudget::new(&policy);
        let memory = budget.certificates.memory().clone();
        let resolver = DefaultKeyResolver::new(KeyResolverConfig::default());
        let info = KeyInfo {
            sources: vec![KeyInfoSource::DerEncodedKeyValue(encoded.clone())],
        };
        let retained_key = resolver
            .resolve_with_candidate_budget(
                Some(&info),
                SignatureAlgorithm::EcdsaSha256,
                &policy,
                crate::provider::default_provider(),
                &mut budget,
            )
            .expect("key resolution")
            .expect("resolved key");
        assert_eq!(
            memory.used(),
            encoded.len() + core::mem::size_of::<PolicyBoundVerificationKey>()
        );
        drop(budget);
        assert_eq!(
            memory.used(),
            encoded.len() + core::mem::size_of::<PolicyBoundVerificationKey>()
        );
        drop(retained_key);
        assert_eq!(
            memory.used(),
            0,
            "deallocation releases the original account"
        );
    }

    /// A DSA root and a leaf whose SPKI omits the parameters it inherits.
    #[cfg(feature = "xmldsig-sign")]
    struct InheritedDsaPath {
        private: der::SecretDocument,
        public: der::Document,
        root: Vec<u8>,
        leaf: Vec<u8>,
    }

    #[cfg(feature = "xmldsig-sign")]
    fn inherited_dsa_path() -> Result<InheritedDsaPath, Box<dyn std::error::Error>> {
        use der::{Decode as _, Encode as _};
        use dsa::pkcs8::DecodePrivateKey as _;
        use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng as _};
        use signature::hazmat::RandomizedPrehashSigner as _;
        let private = pkcs8::EncryptedPrivateKeyInfoRef::from_der(include_bytes!(
            "../../tests/fixtures/xmldsig/keys/dsa/dsa-2048-key.p8-der"
        ))?
        .decrypt(b"secret123")?;
        let key = dsa::SigningKey::from_pkcs8_der(private.as_bytes())?;
        let public = key.verifying_key().to_public_key_der()?;
        let complete = pkcs8::SubjectPublicKeyInfoRef::from_der(public.as_bytes())?;
        let incomplete = pkcs8::SubjectPublicKeyInfoRef {
            algorithm: pkcs8::AlgorithmIdentifierRef {
                oid: dsa::OID,
                parameters: None,
            },
            subject_public_key: complete.subject_public_key,
        }
        .to_der()?;
        let root_name: x509_cert::name::Name = "CN=parameter-root".parse()?;
        let leaf_name: x509_cert::name::Name = "CN=parameter-leaf".parse()?;
        let template_key = rcgen::KeyPair::generate()?;
        let template = rcgen::CertificateParams::new(Vec::new())?.self_signed(&template_key)?;
        let template = x509_cert::Certificate::from_der(template.der())?;
        let algorithm = pkcs8::AlgorithmIdentifierRef {
            oid: der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10040.4.3"),
            parameters: None,
        }
        .to_der()?;
        let make_certificate = |root: bool| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            let mut body = Vec::new();
            if root {
                body.extend_from_slice(&[0xa0, 3, 2, 1, 2]);
            }
            body.extend_from_slice(if root { &[2, 1, 1] } else { &[2, 1, 2] });
            body.extend_from_slice(&algorithm);
            body.extend(root_name.to_der()?);
            body.extend(template.tbs_certificate().validity().to_der()?);
            body.extend(if root {
                root_name.to_der()?
            } else {
                leaf_name.to_der()?
            });
            body.extend_from_slice(if root { public.as_bytes() } else { &incomplete });
            if root {
                let extensions = vec![
                    x509_cert::ext::Extension {
                        extn_id: der::asn1::ObjectIdentifier::new_unwrap("2.5.29.19"),
                        critical: true,
                        extn_value: der::asn1::OctetString::new([0x30, 3, 1, 1, 0xff])?,
                    },
                    x509_cert::ext::Extension {
                        extn_id: der::asn1::ObjectIdentifier::new_unwrap("2.5.29.15"),
                        critical: true,
                        // X.690 11.2.2: named bits end at the last set bit.
                        // keyCertSign + cRLSign leave one unused bit.
                        extn_value: der::asn1::OctetString::new([3, 2, 1, 6])?,
                    },
                ]
                .to_der()?;
                body.extend(
                    der::asn1::Any::new(
                        der::Tag::ContextSpecific {
                            constructed: true,
                            number: der::TagNumber(3),
                        },
                        extensions,
                    )?
                    .to_der()?,
                );
            }
            let signed = der::asn1::Any::new(der::Tag::Sequence, body)?.to_der()?;
            let digest = crate::provider::default_provider()
                .digest(super::super::DigestAlgorithm::Sha1, &signed)?;
            // Test-certificate generation only; production dispatch stays in CryptoProvider.
            let signature: dsa::Signature = key.sign_prehash_with_rng(
                &mut ChaCha20Rng::from_seed([u8::from(root); 32]),
                &digest,
            )?;
            let mut body = signed;
            body.extend_from_slice(&algorithm);
            body.extend(der::asn1::BitString::from_bytes(&signature.to_der()?)?.to_der()?);
            Ok(der::asn1::Any::new(der::Tag::Sequence, body)?.to_der()?)
        };
        let root = make_certificate(true)?;
        let leaf = make_certificate(false)?;
        Ok(InheritedDsaPath {
            private,
            public,
            root,
            leaf,
        })
    }

    /// Receipt association consumes the same effective PKIX state. The
    /// identical original leaf has insufficient standing parameters but
    /// becomes provable after the existing authenticated DSA transition.
    #[cfg(feature = "xmldsig-sign")]
    fn assert_inherited_dsa_receipt(
        original: &super::super::pkix::CertificateSession,
        path: &InheritedDsaPath,
        effective: &[u8],
        signer: &super::super::DsaSigningKey,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let source = original.read(&path.leaf)?;
        let root_source = original.read(&path.root)?;
        let standing = structured_pkix::path::WorkingKey::standing(source.tbs().public_key());
        let inherited = structured_pkix::path::WorkingKey::standing(root_source.tbs().public_key())
            .subject(&source, original.memory())?;
        let verification_key = VerificationKey {
            algorithm: SignatureAlgorithm::DsaSha256,
            public_key_bytes: effective.to_vec(),
            certificate_der: None,
            name: None,
        };
        let builder = super::super::SignatureBuilder::new(
            crate::c14n::C14nAlgorithm::new(crate::c14n::C14nMode::Exclusive1_0, false),
            SignatureAlgorithm::DsaSha256,
        )
        .add_reference(
            super::super::ReferenceBuilder::new(super::super::DigestAlgorithm::Sha256)
                .uri("")
                .transform(super::super::Transform::Enveloped),
        );
        let xml = super::super::SignContext::new(signer).sign_with_builder("<root/>", &builder)?;
        let document = crate::XmlDocument::parse(xml)?;
        let context = super::super::VerifyContext::new().key(&verification_key);
        super::super::with_verified_request(
            &document,
            &context,
            &super::super::VerificationRequest::default(),
            original.memory(),
            |session| {
                let selected =
                    session.select_signature(session.evidence().signatures()[0].identity())?;
                selected
                    .with_key_receipt(|receipt| {
                        for (expected, outcome) in [
                            (standing, crate::provider::KeyAssociation::Unproven),
                            (inherited, crate::provider::KeyAssociation::Same),
                        ] {
                            selected
                                .associate_key(&receipt, expected, |actual| {
                                    assert_eq!(actual, outcome);
                                    Ok::<_, ()>(())
                                })
                                .expect("inherited DSA key association");
                        }
                        Ok::<_, ()>(())
                    })
                    .expect("original successful DSA receipt");
                Ok(())
            },
        )?;
        Ok(())
    }

    #[cfg(feature = "xmldsig-sign")]
    #[test]
    fn authenticated_dsa_target_uses_the_paths_effective_parameters()
    -> Result<(), Box<dyn std::error::Error>> {
        // RFC 5280 6.1.4(e): inherited parameters must reach the actual data
        // verifier, not disappear after certificate-path authentication.
        // https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.4
        let path = inherited_dsa_path()?;
        let InheritedDsaPath {
            private,
            public,
            root,
            leaf,
        } = &path;
        let info = KeyInfo {
            sources: vec![KeyInfoSource::X509Data(X509DataInfo {
                certificates: vec![leaf.clone()],
                parsed_certificates: vec![parse_x509_certificate(leaf)?],
                certificate_chain: vec![0],
                ..Default::default()
            })],
        };
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            trusted_certs: vec![root.clone()],
            ..Default::default()
        });
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.key_trust.verify_x509_chains = true;
        let authorized_key = resolver
            .resolve_with_policy_and_provider(
                Some(&info),
                SignatureAlgorithm::DsaSha256,
                &policy,
                crate::provider::default_provider(),
            )
            .expect("authenticated inherited DSA key")
            .expect("resolved DSA target");
        let effective = authorized_key
            .verification_spki(SignatureAlgorithm::DsaSha256)?
            .expect("effective DSA SPKI is present");
        assert_eq!(
            effective,
            public.as_bytes(),
            "data verification receives the effective SPKI"
        );
        let signer = super::super::DsaSigningKey::from_pkcs8_der(private.as_bytes())?;
        let message = b"authenticated target with inherited DSA parameters";
        let signature = crate::provider::default_provider().sign(
            &signer,
            SignatureAlgorithm::DsaSha256,
            message,
        )?;
        assert!(crate::provider::default_provider().verify(
            &*authorized_key,
            SignatureAlgorithm::DsaSha256,
            message,
            &signature
        )?);
        let original = super::super::pkix::CertificateSession::new(&policy.resources);
        assert!(
            original
                .read(leaf)?
                .tbs()
                .public_key()
                .algorithm()
                .parameters()
                .is_none(),
            "source certificate is not rewritten"
        );
        assert_inherited_dsa_receipt(&original, &path, effective, &signer)
    }

    #[test]
    fn xml_rsa_components_are_bounded_before_bigint_decode() {
        // KeyValue import must reject oversized decoded modulus before conversion.
        let oversized = vec![1_u8; crate::hard_limits::RSA_MODULUS_BIT_CEILING.div_ceil(8) + 1];
        assert!(matches!(
            rsa_key_value_to_spki_der(&oversized, &[1, 0, 1]),
            Err(KeyResolutionError::InvalidPublicKey)
        ));
    }

    #[test]
    fn dsa_spki_structure_preserves_session_work_refusal() {
        // DSA structure must use the same certificate account as RSA/EC,
        // before a crypto decoder can turn the exhausted budget into a bad key.
        let encoded =
            b"\x30\x11\x30\x09\x06\x07\x2a\x86\x48\xce\x38\x04\x01\x03\x04\x00\x02\x01\x07";
        let resources = crate::policy::ResourcePolicy {
            max_x509_work: 0,
            ..crate::policy::ResourcePolicy::default()
        };
        let session = super::super::pkix::CertificateSession::new(&resources);
        let error = validate_spki_algorithm(&session, encoded, SignatureAlgorithm::DsaSha256)
            .expect_err("zero work refuses structural parsing");
        assert!(
            matches!(
                error,
                KeyResolutionError::Chain(super::super::X509ChainError::Policy(
                    crate::policy::PolicyViolation::ResourceLimitExceeded {
                        resource: crate::policy::resource_name::X509_WORK,
                        maximum: 0,
                    }
                ))
            ),
            "{error:?}"
        );
    }

    #[cfg(feature = "xmldsig-sign")]
    #[test]
    fn oversized_dsa_spki_parameter_is_rejected_before_bigint_decode() {
        // A bounded SPKI may still contain a parameter much larger than the
        // non-configurable DSA component ceiling.
        let oversized = vec![1_u8; crate::hard_limits::DSA_KEY_COMPONENT_BYTE_CEILING + 1];
        let one = [1_u8];
        let params = der::Encode::to_der(&super::super::signature::BorrowedDsaPublicParameters {
            p: der::asn1::UintRef::new(&oversized).expect("positive P"),
            q: der::asn1::UintRef::new(&one).expect("positive Q"),
            g: der::asn1::UintRef::new(&one).expect("positive G"),
        })
        .expect("parameters encode");
        let y = der::Encode::to_der(&der::asn1::UintRef::new(&one).expect("positive Y"))
            .expect("public value encodes");
        let spki = pkcs8::SubjectPublicKeyInfoRef {
            algorithm: pkcs8::AlgorithmIdentifierRef {
                oid: dsa::OID,
                parameters: Some(der::asn1::AnyRef::from_der(&params).expect("parameters")),
            },
            subject_public_key: der::asn1::BitStringRef::new(0, &y).expect("bit string"),
        };
        let encoded = der::Encode::to_der(&spki).expect("SPKI encodes");
        let session =
            super::super::pkix::CertificateSession::new(&crate::policy::ResourcePolicy::default());
        assert!(matches!(
            super::super::signature::decode_dsa_verifying_key(&encoded, &session),
            Err(super::super::signature::SignatureVerificationError::InvalidKeyDer)
        ));
        // Ordinary verification must use the same borrowed preflight, not
        // reject only after an allocating crypto decoder reports mismatch.
        assert!(matches!(
            validate_spki_algorithm(&session, &encoded, SignatureAlgorithm::DsaSha256),
            Err(KeyResolutionError::InvalidPublicKey)
        ));
    }

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

        fn begin_digest(
            &self,
            algorithm: super::super::DigestAlgorithm,
        ) -> Result<Box<dyn crate::provider::DigestState + '_>, crate::provider::ProviderError>
        {
            if algorithm == super::super::DigestAlgorithm::Sha512
                && self.sha512_calls.fetch_add(1, Ordering::Relaxed) > 0
            {
                return Err(crate::provider::ProviderError::Unsupported {
                    operation: crate::provider::ProviderOperation::Digest,
                    algorithm: Some(algorithm.uri().to_owned()),
                });
            }
            crate::provider::default_provider().begin_digest(algorithm)
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
                    algorithm: algorithm.oid().map(str::to_owned),
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
        // An explicit time keeps path tests independent of a host clock,
        // which builds without `std` do not have.
        crate::policy::KeyTrustPolicy {
            verify_x509_chains: true,
            verification_time: crate::policy::instant_from_system_time(std::time::SystemTime::now()),
            ..crate::policy::KeyTrustPolicy::default()
        }
    }

    fn cryptographic_policy() -> crate::policy::VerificationPolicy {
        // Key representation/selector tests do not assert signer authorization.
        verification_policy_with_trust(crate::policy::KeyTrustPolicy {
            mode: crate::policy::VerificationTrustMode::CryptographicOnly,
            ..crate::policy::KeyTrustPolicy::default()
        })
    }

    fn chain_policy_at(verification_time: crate::policy::Instant) -> crate::policy::KeyTrustPolicy {
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

    fn fixture_certificate_time() -> crate::policy::Instant {
        // 2027-01-15 UTC, inside the donor certificates' 2026-2126 validity window.
        hours_after_epoch(500_000)
    }

    fn hours_after_epoch(hours: i64) -> crate::policy::Instant {
        crate::policy::Instant::new(hours * 3600, 0).expect("test time")
    }

    fn public_key_der(pem_text: &str) -> Vec<u8> {
        let (rest, pem) = x509_parser::pem::parse_x509_pem(pem_text.as_bytes())
            .expect("fixture public key is PEM");
        assert!(rest.iter().all(u8::is_ascii_whitespace));
        assert_eq!(pem.label, "PUBLIC KEY");
        pem.contents
    }

    fn certificate_der(pem_text: &str) -> Vec<u8> {
        let (rest, pem) = x509_parser::pem::parse_x509_pem(pem_text.as_bytes())
            .expect("fixture certificate is PEM");
        assert!(rest.iter().all(u8::is_ascii_whitespace));
        assert_eq!(pem.label, "CERTIFICATE");
        pem.contents
    }

    fn crl_der(pem_text: &str) -> Vec<u8> {
        let (rest, pem) =
            x509_parser::pem::parse_x509_pem(pem_text.as_bytes()).expect("fixture CRL is PEM");
        assert!(rest.iter().all(u8::is_ascii_whitespace));
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

    fn authorized_revoked_chain() -> (X509DataInfo, Vec<u8>) {
        let mut root_params = generated_certificate_params("revocation root", true);
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let root = rcgen::CertifiedIssuer::self_signed(
            root_params,
            KeyPair::generate().expect("root key generation should succeed"),
        )
        .expect("root should be self-signable");

        let issuer_key = KeyPair::generate().expect("issuer key generation should succeed");
        let mut issuer_params = generated_certificate_params("revocation issuer", true);
        issuer_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let issuer_certificate = issuer_params
            .signed_by(&issuer_key, &root)
            .expect("root should sign issuer certificate");
        let issuer = Issuer::new(issuer_params, issuer_key);

        let mut leaf_params = generated_certificate_params("revoked signer", false);
        leaf_params.serial_number = Some(SerialNumber::from(42_u64));
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let leaf = leaf_params
            .signed_by(
                &KeyPair::generate().expect("leaf key generation should succeed"),
                &issuer,
            )
            .expect("issuer should sign leaf certificate");
        let crl = CertificateRevocationListParams {
            this_update: date_time_ymd(2026, 3, 15),
            next_update: date_time_ymd(2026, 4, 15),
            crl_number: SerialNumber::from(1_u64),
            issuing_distribution_point: None,
            revoked_certs: vec![RevokedCertParams {
                serial_number: SerialNumber::from(42_u64),
                revocation_time: date_time_ymd(2026, 3, 16),
                reason_code: None,
                invalidity_date: None,
            }],
            key_identifier_method: KeyIdMethod::Sha256,
        }
        .signed_by(&issuer)
        .expect("issuer should sign CRL");
        let mut info = x509_info(
            vec![
                leaf.der().to_vec(),
                issuer_certificate.der().to_vec(),
                root.der().to_vec(),
            ],
            0,
        );
        info.crls.push(crl.der().to_vec());
        (info, root.der().to_vec())
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

        assert_eq!(config.trusted_certs, Vec::<Vec<u8>>::new());
        assert_eq!(config.lookup_certs, Vec::<Vec<u8>>::new());
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
        let mut policy = verification_policy_with_trust(chain_policy());

        let Err(error) =
            resolver.resolve_with_policy(Some(&key_info), SignatureAlgorithm::EcdsaSha256, &policy)
        else {
            panic!("unapproved restricted EKU must be rejected");
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
            BTreeSet::from([crate::policy::ExtendedKeyPurpose::ServerAuth]);
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
    fn hmac_key_uses_the_operation_policy_for_truncation() {
        // Output length belongs to SignatureMethod and operation policy, not
        // reusable secret key material. Legacy truncation therefore requires
        // an explicit compatibility policy even on the policy-aware key hook.
        let key = HmacVerificationKey::new(b"secret".to_vec())
            .expect("the fixture HMAC secret is non-empty");
        let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(b"secret")
            .expect("HMAC accepts an arbitrary non-empty secret");
        mac.update(b"data");
        let expected = mac.finalize().into_bytes();

        let policy = crate::policy::VerificationPolicy {
            hmac: crate::policy::HmacPolicy {
                minimum_key_bits: 40,
                minimum_output_bits: 80,
            },
            ..crate::policy::VerificationPolicy::default()
        };
        let certificates = super::super::pkix::CertificateSession::standalone();
        let scope = super::super::VerificationScope::new(&policy, &certificates);
        let context = super::super::SignatureContext::default();
        assert!(
            key.verify_with_policy(
                &scope,
                SignatureAlgorithm::HmacSha1,
                &context,
                b"data",
                &expected[..10],
            )
            .expect("the compatibility policy and algorithm match")
        );
        assert!(
            !key.verify_with_policy(
                &scope,
                SignatureAlgorithm::HmacSha1,
                &context,
                b"data",
                &[0_u8; 10],
            )
            .expect("a mismatched truncated MAC must be rejected")
        );
    }

    #[test]
    fn hmac_key_direct_api_rejects_attacker_selected_short_output() {
        // The policy-free trait method applies secure defaults; signature bytes
        // cannot act as their own one-byte truncation declaration.
        let key = HmacVerificationKey::new([0x42; 16]).expect("fixed HMAC key must parse");
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&[0x42; 16])
            .expect("HMAC accepts the fixed secret");
        mac.update(b"data");
        let expected = mac.finalize().into_bytes();

        assert!(matches!(
            key.verify(SignatureAlgorithm::HmacSha256, b"data", &expected[..1]),
            Err(DsigError::Policy(
                crate::policy::PolicyViolation::HmacOutputLength {
                    minimum: 128,
                    maximum: 256,
                    actual: 8,
                }
            ))
        ));
    }

    #[test]
    fn hmac_key_debug_redacts_secret_material() {
        // Debug output may expose public verification parameters, never caller secrets.
        let secret = b"unique-debug-secret-marker";
        let key = HmacVerificationKey::new(secret.to_vec())
            .expect("the fixture HMAC secret is non-empty");

        let debug = format!("{key:?}");
        assert!(
            !debug
                .contains(std::str::from_utf8(secret).expect("the debug marker is literal ASCII"))
        );
        assert!(!debug.contains(&format!("{secret:?}")));
        assert!(!debug.contains("output_length_bits"));
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
            .policy(cryptographic_policy())
            .key_resolver(&resolver)
            .verify(SIGNED_SAML)
            .expect("embedded certificate should resolve");

        assert_eq!(result.status, super::super::DsigStatus::Valid);
        assert_eq!(
            result.key_trust,
            super::super::KeyTrustEvidence::NotEstablished
        );
    }

    #[test]
    fn embedded_certificate_requires_trust_but_explicit_pin_authorizes_it() {
        // Cryptographic correctness alone must not authorize an embedded signer.
        let untrusted = DefaultKeyResolver::default();
        let error = super::super::VerifyContext::new()
            .key_resolver(&untrusted)
            .verify(SIGNED_SAML)
            .expect_err("an embedded certificate is not a trust declaration");
        assert!(matches!(
            error,
            DsigError::Policy(crate::policy::PolicyViolation::KeyTrust { .. })
        ));

        let xml = roxmltree::Document::parse(SIGNED_SAML).expect("signed SAML fixture must parse");
        let certificate = xml
            .descendants()
            .find(|node| {
                node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "X509Certificate"))
            })
            .expect("signed SAML must embed its certificate");
        let der = STANDARD
            .decode(
                certificate
                    .text()
                    .expect("fixture certificate must contain Base64 text")
                    .split_whitespace()
                    .collect::<String>(),
            )
            .expect("fixture certificate must be valid Base64");
        let trusted = DefaultKeyResolver::new(KeyResolverConfig {
            trusted_certs: vec![der],
            ..KeyResolverConfig::default()
        });
        let result = super::super::VerifyContext::new()
            .key_resolver(&trusted)
            .verify(SIGNED_SAML)
            .expect("an exact caller certificate pin authorizes the key");
        assert_eq!(result.status, super::super::DsigStatus::Valid);
        assert_eq!(
            result.key_trust,
            super::super::KeyTrustEvidence::CallerTrusted
        );

        // A different operation must not retain the previous resolver's trust.
        assert!(
            super::super::VerifyContext::new()
                .key_resolver(&untrusted)
                .verify(SIGNED_SAML)
                .is_err()
        );
    }

    #[test]
    fn certificate_pin_inspections_share_the_candidate_budget() {
        // Authorization is actual key-store work, not a free post-resolution scan.
        let xml = roxmltree::Document::parse(SIGNED_SAML).expect("fixture must parse");
        let text = xml
            .descendants()
            .find(|node| {
                node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "X509Certificate"))
            })
            .and_then(crate::xml::dom::Node::text)
            .expect("fixture embeds a certificate");
        let certificate = STANDARD
            .decode(text.split_whitespace().collect::<String>())
            .expect("fixture certificate must decode");
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            trusted_certs: vec![certificate],
            ..KeyResolverConfig::default()
        });
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.resources.max_key_candidates = 1;
        let error = super::super::VerifyContext::new()
            .policy(policy)
            .key_resolver(&resolver)
            .verify(SIGNED_SAML)
            .expect_err("the certificate and pin are separate inspections");
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
                .policy(cryptographic_policy())
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
                hours_after_epoch(0),
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

        let authorized_key = resolver
            .resolve_with_policy(
                Some(&key_info),
                SignatureAlgorithm::EcdsaSha256,
                &verification_policy_with_trust(chain_policy()),
            )
            .expect("configured self-signed certificate should validate as its own anchor");

        assert!(authorized_key.is_some());
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

        let authorized_key = resolver
            .resolve_with_policy(
                Some(&key_info),
                SignatureAlgorithm::EcdsaSha256,
                &verification_policy_with_trust(chain_policy()),
            )
            .expect("an explicitly trusted selected certificate must terminate its path");

        assert!(authorized_key.is_some());
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

        let authorized_key = resolver
            .resolve_with_policy(
                Some(&key_info),
                SignatureAlgorithm::EcdsaSha256,
                &verification_policy_with_trust(chain_policy()),
            )
            .expect("path construction must stop at the configured anchor");

        assert!(authorized_key.is_some());
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

        let authorized_key = resolver
            .resolve_with_policy(
                Some(&key_info),
                SignatureAlgorithm::EcdsaSha256,
                &verification_policy_with_trust(chain_policy()),
            )
            .expect("selector-resolved leaf should chain through the lookup intermediate");

        assert!(authorized_key.is_some());
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
            let Err(error) = resolver.resolve_with_policy_and_provider(
                Some(&key_info),
                SignatureAlgorithm::EcdsaSha256,
                &policy,
                &provider,
            ) else {
                panic!("the operation provider must gate every X.509 path signature");
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
        let Err(error) = resolver.resolve_with_policy_and_provider(
            Some(&key_info),
            SignatureAlgorithm::EcdsaSha256,
            &policy,
            &provider,
        ) else {
            panic!("complete-path validation must retain the operation provider");
        };
        assert!(matches!(
            error,
            DsigError::KeyResolution(KeyResolutionError::Chain(
                super::super::X509ChainError::Provider(_)
            ))
        ));
        assert_eq!(provider.verification_calls.load(Ordering::Relaxed), 2);
    }

    /// A trusted root (index 0), a purpose-free (1) and a server-only (2)
    /// intermediate sharing one key, and a leaf (3) issued under that key.
    fn purpose_branch_certificates() -> X509DataInfo {
        let root = rcgen::CertifiedIssuer::self_signed(
            generated_certificate_params("resource authority", true),
            rcgen::KeyPair::generate().expect("root key"),
        )
        .expect("root certificate");
        let intermediate_key = rcgen::KeyPair::generate().expect("intermediate key");
        let good_params = generated_certificate_params("resource intermediate", true);
        let good = good_params
            .signed_by(&intermediate_key, &root)
            .expect("good intermediate");
        let mut bad_params = good_params.clone();
        bad_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let bad = bad_params
            .signed_by(&intermediate_key, &root)
            .expect("purpose-restricted intermediate");
        let leaf = generated_certificate_params("resource signer", false)
            .signed_by(
                &rcgen::KeyPair::generate().expect("leaf key"),
                &rcgen::Issuer::from_params(&good_params, &intermediate_key),
            )
            .expect("leaf certificate");
        x509_info(
            vec![
                root.der().to_vec(),
                good.der().to_vec(),
                bad.der().to_vec(),
                leaf.der().to_vec(),
            ],
            3,
        )
    }

    #[test]
    fn path_resource_failure_overrides_an_earlier_semantic_rejection() {
        // An alternative failing application purpose must not mask later
        // exhaustion of the one operation account as another semantic refusal.
        let mut available = purpose_branch_certificates();
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            trusted_certs: vec![available.certificates[0].clone()],
            ..KeyResolverConfig::default()
        });
        let mut trust = chain_policy();
        trust.allowed_extended_key_usages =
            BTreeSet::from([crate::policy::ExtendedKeyPurpose::CodeSigning]);
        let measured =
            super::super::pkix::CertificateSession::new(&crate::policy::ResourcePolicy::default());
        let candidates = build_x509_certificate_paths_to_trusted_prefix(
            &available,
            3,
            1,
            super::super::parse::X509PathBounds {
                max_depth: trust.max_x509_chain_depth,
                max_candidate_paths: trust.max_x509_candidate_paths,
            },
            crate::provider::default_provider(),
            trust.certificate_signature_algorithms.as_ref(),
            &measured,
        )
        .expect("both cryptographic candidates");
        assert_eq!(candidates.len(), 2);
        assert_eq!(
            candidates[0],
            [3, 2, 0],
            "purpose-restricted path must be tried first"
        );
        available.certificate_chain = candidates[0].to_vec();
        let measured_budget = InspectedKeyCandidateBudget::with_ingestion(
            &crate::policy::VerificationPolicy::default(),
            &measured,
            None,
        );
        assert!(matches!(
            resolver.verify_x509_policy(
                &available,
                &trust,
                crate::provider::default_provider(),
                &measured_budget,
            ),
            Err(KeyResolutionError::Chain(
                super::super::X509ChainError::InvalidKeyUsage { position: 1, .. }
            ))
        ));
        let maximum = measured.memory().work_used() + 1;
        let resources = crate::policy::ResourcePolicy {
            max_x509_work: maximum,
            ..Default::default()
        };
        let bounded = super::super::pkix::CertificateSession::new(&resources);
        let bounded_budget = InspectedKeyCandidateBudget::with_ingestion(
            &crate::policy::VerificationPolicy {
                resources,
                ..Default::default()
            },
            &bounded,
            None,
        );
        let mut borrowed = BorrowedX509Pool::new(&available.crls, &bounded);
        for certificate in &available.certificates {
            borrowed
                .insert(certificate, &bounded)
                .expect("borrowed certificate pool");
        }
        let error = resolver
            .select_valid_x509_path(
                &mut borrowed,
                3,
                1,
                &trust,
                None,
                (crate::provider::default_provider(), &bounded_budget),
            )
            .expect_err("later path must exhaust the shared account");
        assert!(
            matches!(error,
                KeyResolutionError::Chain(super::super::X509ChainError::Policy(
                    crate::policy::PolicyViolation::ResourceLimitExceeded {
                        resource: crate::policy::resource_name::X509_WORK, maximum: actual,
                    }
                )) if actual == maximum
            ),
            "semantic rejection masked the resource failure: {error:?}"
        );
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
        let Err(error) =
            resolver.resolve_with_policy(Some(&key_info), SignatureAlgorithm::EcdsaSha256, &policy)
        else {
            panic!("an untrusted lookup intermediate must not become a trust anchor");
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

        let authorized_key = resolver
            .resolve_with_policy(
                Some(&key_info),
                SignatureAlgorithm::EcdsaSha256,
                &verification_policy_with_trust(chain_policy()),
            )
            .expect("the sole path to a configured anchor should be selected");

        assert!(authorized_key.is_some());
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

        let authorized_key = resolver
            .resolve_with_policy(
                Some(&key_info),
                SignatureAlgorithm::EcdsaSha256,
                &verification_policy_with_trust(chain_policy()),
            )
            .expect("same-name rollover path must reach its configured signer");

        assert!(authorized_key.is_some());
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
                super::super::parse::X509PathBounds {
                    max_depth: 9,
                    max_candidate_paths: 2
                },
                crate::provider::default_provider(),
                None,
                &super::super::pkix::CertificateSession::new(
                    &crate::policy::ResourcePolicy::default()
                ),
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

        let authorized_key = resolver
            .resolve_with_policy(
                Some(&key_info),
                SignatureAlgorithm::EcdsaSha256,
                &verification_policy_with_trust(chain_policy()),
            )
            .expect("the leaf signature should select its unique same-subject issuer");

        assert!(authorized_key.is_some());
    }

    #[test]
    fn x509_path_builder_skips_policy_rejected_alternatives() {
        use crate::provider::X509SignatureAlgorithm;
        // One cross-signed issuer has a forbidden parent-edge algorithm;
        // neither its position nor traversal order may hide a permitted path.
        let root = rcgen::CertifiedIssuer::self_signed(
            generated_certificate_params("policy root", true),
            rcgen::KeyPair::generate().expect("root key"),
        )
        .expect("root certificate");
        let alternate_root = rcgen::CertifiedIssuer::self_signed(
            generated_certificate_params("policy alternate root", true),
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)
                .expect("alternate root key"),
        )
        .expect("alternate root certificate");
        let shared_params = generated_certificate_params("policy shared issuer", true);
        let shared_key = rcgen::KeyPair::generate().expect("issuer key");
        let rejected = shared_params
            .signed_by(&shared_key, &alternate_root)
            .expect("cross-signed issuer");
        let shared = rcgen::CertifiedIssuer::signed_by(shared_params, shared_key, &root)
            .expect("issuer certificate");
        let leaf = generated_certificate_params("policy leaf", false)
            .signed_by(&rcgen::KeyPair::generate().expect("leaf key"), &shared)
            .expect("leaf certificate");
        let rejected = rejected.der().to_vec();
        let allowed = crate::policy::CertificateSignatureAlgorithms::Allowlist(BTreeSet::from([
            X509SignatureAlgorithm::Ecdsa(super::super::DigestAlgorithm::Sha256),
        ]));
        for rejected_first in [true, false] {
            let mut alternatives = vec![shared.der().to_vec(), rejected.clone()];
            if rejected_first {
                alternatives.reverse();
            }
            let permitted_index = if rejected_first { 3 } else { 2 };
            let info = x509_info(
                vec![
                    root.der().to_vec(),
                    leaf.der().to_vec(),
                    alternatives.remove(0),
                    alternatives.remove(0),
                    alternate_root.der().to_vec(),
                ],
                1,
            );
            assert_eq!(
                build_x509_certificate_paths_to_trusted_prefix(
                    &info,
                    1,
                    1,
                    super::super::parse::X509PathBounds {
                        max_depth: 4,
                        max_candidate_paths: 8
                    },
                    crate::provider::default_provider(),
                    Some(&allowed),
                    &super::super::pkix::CertificateSession::new(
                        &crate::policy::ResourcePolicy::default()
                    ),
                )
                .expect("forbidden alternative must not abort search")
                .into_iter()
                .map(|path| path.to_vec())
                .collect::<Vec<_>>(),
                vec![vec![1, permitted_index, 0]]
            );
        }
        let info = x509_info(
            vec![
                root.der().to_vec(),
                leaf.der().to_vec(),
                rejected,
                alternate_root.der().to_vec(),
            ],
            1,
        );
        assert!(matches!(
            build_x509_certificate_paths_to_trusted_prefix(
                &info,
                1,
                1,
                super::super::parse::X509PathBounds {
                    max_depth: 4,
                    max_candidate_paths: 8
                },
                crate::provider::default_provider(),
                Some(&allowed),
                &super::super::pkix::CertificateSession::new(
                    &crate::policy::ResourcePolicy::default()
                ),
            ),
            Err(X509ChainBuildError::Policy(_))
        ));
    }

    /// Every candidate path from the leaf at index 1 to the trusted root at 0.
    fn root_anchored_paths(
        info: &X509DataInfo,
        provider: &dyn crate::provider::CryptoProvider,
    ) -> Result<Vec<Vec<usize>>, X509ChainBuildError> {
        build_x509_certificate_paths_to_trusted_prefix(
            info,
            1,
            1,
            super::super::parse::X509PathBounds {
                max_depth: 4,
                max_candidate_paths: 8,
            },
            provider,
            None,
            &super::super::pkix::CertificateSession::new(&crate::policy::ResourcePolicy::default()),
        )
        .map(|paths| paths.into_iter().map(|path| path.to_vec()).collect())
    }

    /// A provider that refuses its first certificate-signature verification.
    fn rejecting_first_verification() -> RejectSecondSha512Provider {
        RejectSecondSha512Provider {
            sha512_calls: AtomicUsize::new(0),
            verification_calls: AtomicUsize::new(0),
            reject_verification_call: Some(0),
            rejected_verification_data: None,
        }
    }

    /// `der` with both ECDSA-SHA256 signature OIDs rewritten to the
    /// unassigned arc 1.2.840.10045.4.3.5.
    fn with_unassigned_ecdsa_signature_oid(der: &[u8]) -> Vec<u8> {
        let mut certificate = der.to_vec();
        let ecdsa_sha256_oid = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
        let offsets = certificate
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
            certificate[offset + ecdsa_sha256_oid.len() - 1] = 0x05;
        }
        certificate
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
        assert_eq!(
            super::super::parse::build_x509_certificate_chain_from(
                &ordered,
                0,
                &rejecting_first_verification(),
                None,
                &super::super::pkix::CertificateSession::new(
                    &crate::policy::ResourcePolicy::default()
                ),
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
        assert_eq!(
            root_anchored_paths(&anchored_same_edge, &rejecting_first_verification())
                .expect("a later same-DN issuer must survive an earlier provider capability miss"),
            vec![vec![1, 3, 0]]
        );

        let anchored = x509_info(
            vec![
                root.der().to_vec(),
                leaf.der().to_vec(),
                signing_intermediate.der().to_vec(),
                with_unassigned_ecdsa_signature_oid(signing_intermediate.der()),
            ],
            1,
        );
        assert_eq!(
            root_anchored_paths(&anchored, crate::provider::default_provider())
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
            root_anchored_paths(&unsupported_only, crate::provider::default_provider()),
            Err(X509ChainBuildError::UnsupportedSignatureAlgorithm { ref oid })
                if oid == "1.2.840.10045.4.3.5"
        ));
    }

    #[test]
    fn selector_resolved_certificate_preserves_supplied_crls() {
        let selector = "<KeyInfo><X509Data><X509SubjectName>CN=Test Key rsa-2048,O=XML Security Library (http://www.aleksey.com/xmlsec),ST=California,C=US</X509SubjectName><X509CRL>CRL_PLACEHOLDER</X509CRL></X509Data></KeyInfo>";
        let crl = crl_der(include_str!(
            "../../tests/fixtures/keys/rsa/rsa-2048-cert-revoked-crl.pem"
        ));
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
            ..chain_policy_at(hours_after_epoch(492_768))
        });

        let error = super::super::VerifyContext::new()
            .policy(policy.clone())
            .key_resolver(&resolver)
            .verify(&xml)
            .expect_err("selector lookup must retain and enforce the supplied CRL");
        // RFC 10007 section 4: the tracked v3 CA lacks KeyUsage, so CRL
        // authorization now fails before its revoked-serial list is consumed.
        // https://www.rfc-editor.org/rfc/rfc10007.html#section-4
        assert!(matches!(
            error,
            DsigError::KeyResolution(KeyResolutionError::Chain(
                super::super::X509ChainError::InvalidKeyUsage {
                    position: 1,
                    required: "cRLSign"
                }
            ))
        ));

        // Match the exact TBSCertList bytes so earlier certificate-edge
        // verification succeeds and the provider rejection occurs at CRL
        // authentication itself.
        let (authorized, root) = authorized_revoked_chain();
        let session = super::super::pkix::CertificateSession::new(&policy.resources);
        let crl_signed_data = session
            .read_crl(&authorized.crls[0])
            .expect("authorized test CRL parses")
            .signed_bytes()
            .to_vec();
        let authorized_resolver = DefaultKeyResolver::new(KeyResolverConfig {
            lookup_certs: vec![authorized.certificates[1].clone()],
            trusted_certs: vec![root],
            ..KeyResolverConfig::default()
        });
        let info = KeyInfo {
            sources: vec![KeyInfoSource::X509Data(authorized)],
        };
        let mut budget = InspectedKeyCandidateBudget::new_with_utc_facts(
            &policy,
            super::super::pkix::test_utc_facts(),
        );
        let provider = RejectSecondSha512Provider {
            sha512_calls: AtomicUsize::new(0),
            verification_calls: AtomicUsize::new(0),
            reject_verification_call: None,
            rejected_verification_data: Some(crl_signed_data),
        };
        let Err(error) = authorized_resolver.resolve_for_verification_with_budget(
            Some(&info),
            SignatureAlgorithm::EcdsaSha256,
            &policy,
            &provider,
            &mut budget,
        ) else {
            panic!("CRL authentication must retain the operation provider");
        };
        assert!(matches!(
            error,
            DsigError::KeyResolution(KeyResolutionError::Chain(
                super::super::X509ChainError::Provider(_)
            ))
        ));
    }

    #[test]
    fn resolver_rejects_revoked_leaf_with_authorized_crl_issuer() {
        // Keep revoked-serial enforcement covered independently from the cRLSign authorization
        // failure exercised by the legacy fixture above.
        let (mut info, root) = authorized_revoked_chain();
        let issuer = info.certificates[1].clone();
        info.certificates.truncate(1);
        info.parsed_certificates.truncate(1);
        let key_info = KeyInfo {
            sources: vec![KeyInfoSource::X509Data(info)],
        };
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            lookup_certs: vec![issuer],
            trusted_certs: vec![root],
            ..KeyResolverConfig::default()
        });
        let policy = verification_policy_with_trust(crate::policy::KeyTrustPolicy {
            check_crls: true,
            max_x509_chain_depth: 3,
            ..chain_policy_at(hours_after_epoch(492_768))
        });

        let mut budget = InspectedKeyCandidateBudget::new_with_utc_facts(
            &policy,
            super::super::pkix::test_utc_facts(),
        );
        let Err(error) = resolver.resolve_for_verification_with_budget(
            Some(&key_info),
            SignatureAlgorithm::EcdsaSha256,
            &policy,
            crate::provider::default_provider(),
            &mut budget,
        ) else {
            panic!("an authenticated CRL must reject its revoked leaf");
        };
        assert!(matches!(
            error,
            DsigError::KeyResolution(KeyResolutionError::Chain(
                super::super::X509ChainError::Revoked(0)
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
                .policy(cryptographic_policy())
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
        let key_info = r"<KeyInfo><X509Data><X509SubjectName>CN=Test Key rsa-2048,O=XML Security Library (http://www.aleksey.com/xmlsec),ST=California,C=US</X509SubjectName><X509SKI>0X0XrEVCio75sBcl1TxymJ2IOiU=</X509SKI></X509Data></KeyInfo>";
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
            .policy(cryptographic_policy())
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
        let super::super::KeyTrustEvidence::ValidatedX509(evidence) = result.key_trust else {
            panic!("successful path validation must retain typed evidence");
        };
        assert_eq!(evidence.verification_time(), fixture_certificate_time());
        assert!(!evidence.revocation_checked());
        assert_eq!(evidence.certificate_fingerprints().len(), 1);
        assert_eq!(
            evidence.anchor_fingerprint(),
            &evidence.certificate_fingerprints()[0]
        );

        // The batch entry point must retain the actual validated path rather
        // than reducing trusted/lookup overlap to a boolean or XML claim.
        let document = crate::XmlDocument::parse(x509_signature_with_leaf_subject())
            .expect("signed certificate selector fixture must parse");
        let report = super::super::VerifyContext::new()
            .policy(verification_policy_with_trust(chain_policy_at(
                fixture_certificate_time(),
            )))
            .key_resolver(&resolver)
            .verify_all(&document)
            .expect("batch verification must preserve the validated path");
        assert!(
            report
                .accepted(&document)
                .expect("current document acceptance")
        );
        assert_eq!(
            report.signatures()[0]
                .result()
                .as_ref()
                .expect("the individually processed Signature must verify")
                .key_trust,
            super::super::KeyTrustEvidence::ValidatedX509(evidence)
        );
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
            .policy(cryptographic_policy())
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
            "<KeyInfo><KeyValue><RSAKeyValue><Modulus>{modulus}</Modulus><Exponent>{exponent}</Exponent></RSAKeyValue></KeyValue></KeyInfo>",
        );
        let xml = replace_unprefixed_key_info(RSA_KEY_VALUE_SIGNATURE, &key_info);
        let resolver = DefaultKeyResolver::default();
        let result = super::super::VerifyContext::new()
            .policy(cryptographic_policy())
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
        policy
            .key_sources
            .remove(crate::policy::KeySourceKind::KeyValue);

        let Err(error) = DefaultKeyResolver::default().resolve_with_policy(
            Some(&key_info),
            SignatureAlgorithm::RsaSha256,
            &policy,
        ) else {
            panic!("disabled KeyValue must fail before key construction");
        };

        assert!(matches!(
            error,
            DsigError::Policy(crate::policy::PolicyViolation::KeyTrust {
                reason: "KeyValue key sources are disabled"
            })
        ));
    }

    #[test]
    fn operation_policy_preflights_every_key_info_source_before_resolution() {
        // A permitted source resolving first must not hide a later source that
        // the immutable operation policy rejects.
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
        let mut policy = crate::policy::VerificationPolicy::default();
        policy
            .key_sources
            .remove(crate::policy::KeySourceKind::X509Data);

        for sources in [
            vec![
                KeyInfoSource::KeyName("idp-signing".into()),
                KeyInfoSource::X509Data(X509DataInfo::default()),
            ],
            vec![
                KeyInfoSource::X509Data(X509DataInfo::default()),
                KeyInfoSource::KeyName("idp-signing".into()),
            ],
        ] {
            let Err(error) = resolver.resolve_with_policy(
                Some(&KeyInfo { sources }),
                SignatureAlgorithm::EcdsaSha256,
                &policy,
            ) else {
                panic!("source order must not hide disabled X509Data");
            };

            assert!(matches!(
                error,
                DsigError::Policy(crate::policy::PolicyViolation::KeyTrust {
                    reason: "X509Data key sources are disabled"
                })
            ));
        }
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
            let Err(error) = resolver.resolve_with_policy(
                Some(&key_info),
                SignatureAlgorithm::EcdsaSha256,
                &policy,
            ) else {
                panic!("candidate ceiling {maximum} must stop resolution");
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
    fn configured_crls_are_bounded_before_der_parsing() {
        // Invalid DER must not be parsed when its size or count already violates policy.
        let key_info = KeyInfo {
            sources: vec![KeyInfoSource::X509Data(X509DataInfo {
                subject_names: vec!["CN=selected".into()],
                ..X509DataInfo::default()
            })],
        };
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.key_trust.check_crls = true;
        policy.key_trust.verify_x509_chains = true;
        policy.resources.max_external_resource_bytes = 4;
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            crls: vec![vec![0; 5]],
            ..KeyResolverConfig::default()
        });
        let error = resolver
            .resolve_with_policy(Some(&key_info), SignatureAlgorithm::RsaSha256, &policy)
            .err()
            .expect("oversized CRL must fail before DER parsing");
        assert!(
            matches!(
                error,
                DsigError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
                    ..
                })
            ),
            "{error:?}"
        );

        policy.resources.max_external_resource_bytes = 4;
        policy.resources.max_external_resource_total_bytes = 7;
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            crls: vec![vec![0; 4], vec![0; 4]],
            ..KeyResolverConfig::default()
        });
        let error = resolver
            .resolve_with_policy(Some(&key_info), SignatureAlgorithm::RsaSha256, &policy)
            .err()
            .expect("aggregate CRL bytes must fail before DER parsing");
        assert!(matches!(
            error,
            DsigError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                ..
            })
        ));

        policy.resources.max_external_resource_total_bytes = 8;
        policy.resources.max_key_candidates = 1;
        let error = resolver
            .resolve_with_policy(Some(&key_info), SignatureAlgorithm::RsaSha256, &policy)
            .err()
            .expect("CRL candidate count must fail before DER parsing");
        assert!(matches!(
            error,
            DsigError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::KEY_CANDIDATES,
                ..
            })
        ));
    }

    #[test]
    fn configured_certificates_and_crls_share_external_byte_budget() {
        // A stricter operation policy must account for all resolver-owned
        // material on a selector path, even when the resolver was built under
        // a broader policy.
        let key_info = KeyInfo {
            sources: vec![KeyInfoSource::X509Data(X509DataInfo {
                subject_names: vec!["CN=selected".into()],
                ..X509DataInfo::default()
            })],
        };
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.key_trust.check_crls = true;
        policy.key_trust.verify_x509_chains = true;
        policy.resources.max_external_resource_bytes = 8;
        policy.resources.max_external_resource_total_bytes = 12;
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            trusted_certs: vec![vec![0; 8]],
            crls: vec![vec![0; 8]],
            ..KeyResolverConfig::default()
        });
        let error = resolver
            .resolve_with_policy(Some(&key_info), SignatureAlgorithm::RsaSha256, &policy)
            .err()
            .expect("combined external material exceeds the operation limit");
        assert!(matches!(
            error,
            DsigError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                ..
            })
        ));
    }

    #[test]
    fn embedded_and_configured_x509_share_one_byte_budget() {
        // Both halves fit separately; their combined live material must fail
        // before attempting to parse the deliberately invalid certificate DER.
        let mut info = KeyInfo {
            sources: vec![KeyInfoSource::X509Data(X509DataInfo {
                certificates: vec![vec![0; 8]],
                certificate_chain: vec![0],
                crls: vec![vec![0; 2]],
                ..X509DataInfo::default()
            })],
        };
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            crls: vec![vec![0; 8]],
            ..KeyResolverConfig::default()
        });
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.key_trust.check_crls = true;
        policy.key_trust.verify_x509_chains = true;
        policy.resources.max_external_resource_total_bytes = 17;
        let error = resolver
            .resolve_with_policy(Some(&info), SignatureAlgorithm::RsaSha256, &policy)
            .err()
            .expect("combined material must be rejected");
        assert!(
            matches!(
                error,
                DsigError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                    actual: 18,
                    ..
                })
            ),
            "{error:?}"
        );
        policy.resources.max_external_resource_total_bytes = 18;
        let error = resolver
            .resolve_with_policy(Some(&info), SignatureAlgorithm::RsaSha256, &policy)
            .err()
            .expect("exact byte allowance reaches DER parsing");
        assert!(
            matches!(
                error,
                DsigError::KeyResolution(KeyResolutionError::Chain(super::super::X509ChainError::Processing(ref error)))
                    if error.code() == structured_pkix::ErrorCode::Encoding(structured_asn1::ErrorCode::MalformedEndOfContents)
                        && error.field() == "certificate" && error.offset() == 0
            ),
            "{error:?}"
        );
        // A prior lookup source may charge configured CRLs once, but cannot
        // suppress the combined-byte preflight of a later embedded source.
        info.sources.insert(
            0,
            KeyInfoSource::X509Data(X509DataInfo {
                subject_names: vec!["CN=absent".into()],
                ..X509DataInfo::default()
            }),
        );
        policy.resources.max_external_resource_total_bytes = 17;
        policy.resources.max_key_candidates = 2;
        assert!(matches!(
            resolver.resolve_with_policy(Some(&info), SignatureAlgorithm::RsaSha256, &policy),
            Err(DsigError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                    actual: 18,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn direct_certificate_does_not_charge_unused_configured_store() {
        // A direct embedded certificate bypasses configured lookup material
        // when chain verification is disabled.
        let certificate = certificate_der(RSA_4096_CERTIFICATE);
        let key_info = KeyInfo {
            sources: vec![KeyInfoSource::X509Data(X509DataInfo {
                certificates: vec![certificate],
                certificate_chain: vec![0],
                subject_names: vec!["CN=unused-selector".into()],
                ..X509DataInfo::default()
            })],
        };
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            lookup_certs: vec![vec![0; 4096]],
            trusted_certs: vec![vec![0; 4096]],
            ..KeyResolverConfig::default()
        });
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.resources.max_external_resource_bytes = 1024;
        policy.resources.max_external_resource_total_bytes = 1024;
        assert!(
            resolver
                .resolve_with_policy(Some(&key_info), SignatureAlgorithm::RsaSha256, &policy)
                .expect("unused configured certificates are not charged")
                .is_some()
        );
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

        let Err(error) = DefaultKeyResolver::default().resolve_with_policy(
            Some(&key_info),
            SignatureAlgorithm::RsaSha256,
            &policy,
        ) else {
            panic!("the second embedded certificate must exceed the candidate budget");
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
    fn operation_policy_charges_duplicate_configured_x509_candidates() {
        // Deduplication may avoid repeated parsing, but inspecting a duplicate
        // resolver entry still consumes work and must not bypass the budget.
        let certificate = certificate_der(RSA_4096_CERTIFICATE);
        let resolver = DefaultKeyResolver::new(KeyResolverConfig {
            lookup_certs: vec![certificate.clone(), certificate],
            ..KeyResolverConfig::default()
        });
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.resources.max_key_candidates = 1;

        let error = super::super::VerifyContext::new()
            .policy(policy)
            .key_resolver(&resolver)
            .verify(&x509_signature_with_leaf_subject())
            .expect_err("the duplicate configured entry must consume candidate work");

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
    fn operation_policy_charges_duplicate_embedded_x509_candidates() {
        // Public callers can construct KeyInfo without passing through parser
        // entry limits, so duplicate embedded entries must consume the budget.
        let certificate = certificate_der(RSA_4096_CERTIFICATE);
        let key_info = KeyInfo {
            sources: vec![KeyInfoSource::X509Data(X509DataInfo {
                certificates: vec![certificate.clone(), certificate],
                certificate_chain: vec![0],
                ..X509DataInfo::default()
            })],
        };
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.resources.max_key_candidates = 1;

        let Err(error) = DefaultKeyResolver::default().resolve_with_policy(
            Some(&key_info),
            SignatureAlgorithm::RsaSha256,
            &policy,
        ) else {
            panic!("the duplicate embedded entry must consume candidate work");
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

        let Err(error) = DefaultKeyResolver::default().resolve_with_policy(
            None,
            SignatureAlgorithm::RsaSha256,
            &policy,
        ) else {
            panic!("invalid resource policy must fail before key resolution");
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

    /// `xml` with its `KeyInfo` moved into an `Object` and reached through a
    /// `KeyInfoReference`, and with its `X509Data` reached through a
    /// `RetrievalMethod`.
    #[cfg(feature = "legacy-algorithms")]
    fn indirect_key_info_variants(xml: &str) -> [String; 2] {
        let start = xml.find("<KeyInfo>").expect("fixture has KeyInfo");
        let end = xml.find("</KeyInfo>").expect("fixture closes KeyInfo") + "</KeyInfo>".len();
        let target = &xml[start..end];
        let referenced = replace_unprefixed_key_info(
            xml,
            &format!(
                "<KeyInfo><KeyInfoReference xmlns=\"http://www.w3.org/2009/xmldsig11#\" URI=\"#selector\"/></KeyInfo><Object>{}</Object>",
                target.replace("<KeyInfo>", "<KeyInfo Id=\"selector\">")
            ),
        );
        let retrieved = replace_unprefixed_key_info(
            xml,
            &format!(
                "<KeyInfo><RetrievalMethod URI=\"#selector\" Type=\"http://www.w3.org/2000/09/xmldsig#X509Data\"/></KeyInfo><Object>{}</Object>",
                target
                    .strip_prefix("<KeyInfo>")
                    .expect("selected range starts at KeyInfo")
                    .strip_suffix("</KeyInfo>")
                    .expect("selected range ends at KeyInfo")
                    .replace("<X509Data>", "<X509Data Id=\"selector\">")
            ),
        );
        [referenced, retrieved]
    }

    #[cfg(feature = "legacy-algorithms")]
    #[test]
    fn x509_digest_selectors_obey_operation_policy() {
        // Both lookup-only and embedded selectors must reject a denied digest
        // before certificate selection; explicit permission must still work.
        for algorithm in [
            super::super::DigestAlgorithm::Md5,
            super::super::DigestAlgorithm::Ripemd160,
        ] {
            let certificate = certificate_der(RSA_4096_CERTIFICATE);
            let digest = super::super::compute_digest(algorithm, &certificate);
            let resolver = DefaultKeyResolver::new(KeyResolverConfig {
                lookup_certs: vec![certificate.clone()],
                trusted_certs: vec![
                    certificate.clone(),
                    certificate_der(include_str!("../../tests/fixtures/keys/ca2cert.pem")),
                    certificate_der(include_str!("../../tests/fixtures/keys/cacert.pem")),
                ],
                ..KeyResolverConfig::default()
            });
            for embedded in [false, true] {
                let cert_xml = if embedded {
                    format!(
                        "<X509Certificate>{}</X509Certificate>",
                        STANDARD.encode(&certificate)
                    )
                } else {
                    String::new()
                };
                let xml = replace_unprefixed_key_info(
                    X509_DIGEST_SIGNATURE,
                    &format!(
                        "<KeyInfo><X509Data>{cert_xml}<X509Digest xmlns=\"http://www.w3.org/2009/xmldsig11#\" Algorithm=\"{}\">{}</X509Digest></X509Data></KeyInfo>",
                        algorithm.uri(),
                        STANDARD.encode(&digest)
                    ),
                );
                let provider = RejectSecondSha512Provider {
                    sha512_calls: AtomicUsize::new(0),
                    verification_calls: AtomicUsize::new(0),
                    reject_verification_call: None,
                    rejected_verification_data: None,
                };
                assert!(
                    matches!(super::super::VerifyContext::new().key_resolver(&resolver).provider(&provider).verify(&xml),
                    Err(DsigError::Policy(crate::policy::PolicyViolation::Algorithm { algorithm: uri, .. })) if uri == algorithm.uri())
                );
                assert_eq!(provider.sha512_calls.load(Ordering::SeqCst), 0);
                assert_eq!(provider.verification_calls.load(Ordering::SeqCst), 0);
                // Direct resolver callers must not bypass the same snapshot.
                let info = KeyInfo {
                    sources: vec![KeyInfoSource::X509Data(X509DataInfo {
                        digests: vec![(algorithm.uri().into(), digest.clone())],
                        ..X509DataInfo::default()
                    })],
                };
                assert!(matches!(
                    resolver.resolve_with_policy(
                        Some(&info),
                        SignatureAlgorithm::RsaSha512,
                        &crate::policy::VerificationPolicy::default()
                    ),
                    Err(DsigError::Policy(_))
                ));
                let policy = crate::policy::VerificationPolicy {
                    digest_algorithms: Some(
                        [algorithm, super::super::DigestAlgorithm::Sha512].into(),
                    ),
                    ..crate::policy::VerificationPolicy::default()
                };
                assert_eq!(
                    super::super::VerifyContext::new()
                        .key_resolver(&resolver)
                        .policy(policy.clone())
                        .verify(&xml)
                        .expect("explicitly permitted selector must verify")
                        .status,
                    super::super::DsigStatus::Valid
                );
                // Referenced KeyInfo and retrieved X509Data must not create a
                // separate algorithm permission path during materialization.
                for indirect in indirect_key_info_variants(&xml) {
                    assert!(
                        matches!(super::super::VerifyContext::new().key_resolver(&resolver).verify(&indirect),
                        Err(DsigError::Policy(crate::policy::PolicyViolation::Algorithm { algorithm: uri, .. })) if uri == algorithm.uri())
                    );
                    assert_eq!(
                        super::super::VerifyContext::new()
                            .key_resolver(&resolver)
                            .policy(policy.clone())
                            .verify(&indirect)
                            .expect("permitted indirect selector must verify")
                            .status,
                        super::super::DsigStatus::Valid
                    );
                }
            }
        }
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
            named_keys: BTreeMap::from([("legacy".into(), named_key.clone())]),
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
            "<ds:KeyInfo><ds:KeyValue><ds:RSAKeyValue><ds:Modulus>{modulus}</ds:Modulus><ds:Exponent>{exponent}</ds:Exponent></ds:RSAKeyValue></ds:KeyValue></ds:KeyInfo>",
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
            .policy(cryptographic_policy())
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
            .policy(cryptographic_policy())
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
            r#"<KeyInfo xmlns:dsig11="http://www.w3.org/2009/xmldsig11#"><KeyValue><dsig11:ECKeyValue><dsig11:NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/><dsig11:PublicKey>BJ/yaXNlq4FRObyJCBhb5jAz8GVzinK3bBGLjSDfjbJwNfydtgjnlS4EsDmxSRhWyJWq6GIqy5wvnaiARK04uB4=</dsig11:PublicKey></dsig11:ECKeyValue></KeyValue><KeyValue><RSAKeyValue><Modulus>{modulus}</Modulus><Exponent>{exponent}</Exponent></RSAKeyValue></KeyValue></KeyInfo>"#,
        );
        let xml = replace_unprefixed_key_info(RSA_KEY_VALUE_SIGNATURE, &key_info);
        let resolver = DefaultKeyResolver::default();
        let result = super::super::VerifyContext::new()
            .policy(cryptographic_policy())
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
            .policy(cryptographic_policy())
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
            .policy(cryptographic_policy())
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
