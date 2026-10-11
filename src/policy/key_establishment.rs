//! Shared key-establishment domain: capability is not permission.

use super::PolicyViolation;
use crate::xmldsig::DigestAlgorithm;
use std::collections::HashSet;

/// Agreement mechanisms identified by their XML algorithm URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyAgreementAlgorithm {
    /// Named-curve ECDH-ES.
    EcdhEs,
    /// RFC 7748 X25519.
    X25519,
    /// RFC 7748 X448; requires explicit agreement permission.
    X448,
    /// Finite-field DH-ES with a separate KDF.
    DhEs,
    /// Legacy finite-field DH and its SHA-based derivation.
    LegacyDh,
}

impl KeyAgreementAlgorithm {
    /// Stable wire identifier; this does not grant algorithm permission.
    pub const fn uri(self) -> &'static str {
        match self {
            Self::EcdhEs => "http://www.w3.org/2009/xmlenc11#ECDH-ES",
            Self::X25519 => "http://www.w3.org/2021/04/xmldsig-more#x25519",
            Self::X448 => "http://www.w3.org/2021/04/xmldsig-more#x448",
            Self::DhEs => "http://www.w3.org/2009/xmlenc11#dh-es",
            Self::LegacyDh => "http://www.w3.org/2001/04/xmlenc#dh",
        }
    }

    /// Recognize the exact URI, without normalizing or aliasing algorithms.
    pub fn from_uri(uri: &str) -> Option<Self> {
        [
            Self::EcdhEs,
            Self::X25519,
            Self::X448,
            Self::DhEs,
            Self::LegacyDh,
        ]
        .into_iter()
        .find(|algorithm| algorithm.uri() == uri)
    }
}

/// KDF mechanisms accepted by the shared policy domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyDerivationAlgorithm {
    /// XMLEnc 1.1 ConcatKDF with bit-string context.
    ConcatKdf,
    /// RFC 5869 HKDF.
    Hkdf,
    /// RFC 8018 PBKDF2.
    Pbkdf2,
    /// XMLEnc's legacy DH derivation.
    LegacyDh,
}

impl KeyDerivationAlgorithm {
    /// Stable wire identifier.
    pub const fn uri(self) -> &'static str {
        match self {
            Self::ConcatKdf => "http://www.w3.org/2009/xmlenc11#ConcatKDF",
            Self::Hkdf => "http://www.w3.org/2021/04/xmldsig-more#hkdf",
            Self::Pbkdf2 => "http://www.w3.org/2009/xmlenc11#pbkdf2",
            Self::LegacyDh => "http://www.w3.org/2001/04/xmlenc#dh",
        }
    }

    /// Recognize the exact URI.
    pub fn from_uri(uri: &str) -> Option<Self> {
        [Self::ConcatKdf, Self::Hkdf, Self::Pbkdf2, Self::LegacyDh]
            .into_iter()
            .find(|algorithm| algorithm.uri() == uri)
    }
}

/// Authentication boundary for content encrypted directly with a KEM secret.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum KemContentAuthentication {
    /// Require an authenticated content cipher, such as AES-GCM.
    #[default]
    RequireAuthenticatedCipher,
    /// Compatibility permission: the caller authenticates the complete encrypted
    /// input before decryption and binds external integrity protection of output
    /// to its encryption key. CBC padding never proves KEM ciphertext validity
    /// or sender identity.
    ExternalAuthenticated,
}

/// Immutable permission and limits shared by encryption and decryption.
///
/// These are deployment decisions, not specification requirements. Requests
/// supply private keys and expected party identities separately; XML input must
/// never select this policy or reset its operation-wide budget.
#[derive(Debug, Clone)]
pub struct KeyEstablishmentPolicy {
    /// Exact experimental KEM permissions. Empty denies all parameter sets.
    pub encapsulation_algorithms: HashSet<crate::provider::KeyEncapsulationAlgorithm>,
    /// Separate permission for unauthenticated direct KEM content composition.
    pub kem_content_authentication: KemContentAuthentication,
    /// Cumulative KEM attempts; failed provider calls consume allowance too.
    pub max_encapsulation_operations: usize,
    /// Exact agreement permissions. None permits only ECDH-ES and X25519.
    pub agreement_algorithms: Option<HashSet<KeyAgreementAlgorithm>>,
    /// Exact KDF permissions. None permits ConcatKDF/HKDF/PBKDF2, not legacy DH.
    pub derivation_algorithms: Option<HashSet<KeyDerivationAlgorithm>>,
    /// Underlying digest permission, including HMAC PRFs. None permits SHA-2.
    /// SHA-1 requires an explicit grant even when required by a legacy profile.
    pub digest_algorithms: Option<HashSet<DigestAlgorithm>>,
    /// Cumulative conservative hash compression-block allowance per operation.
    pub max_hash_blocks: usize,
    /// Cumulative shared-secret, derived-key and finite-field validation
    /// allocations reserved before provider work, including boxed workspace.
    /// Failed attempts consume the allowance too; no retry may reset it.
    pub max_owned_bytes: usize,
    /// Maximum finite-field modulus width; capability alone grants no permission.
    pub max_dh_modulus_bits: usize,
    /// Product strength baseline, not XMLEnc's 512-bit wire-format minimum.
    /// Legacy interoperability requires an explicit caller-selected lower value.
    pub minimum_dh_modulus_bits: usize,
    /// Minimum prime-order subgroup width, independent of the modulus width.
    pub minimum_dh_subgroup_bits: usize,
    /// Cumulative modular work, in batches of up to 64 limb products. Charged
    /// conservatively for validation and exponentiation before their execution.
    pub max_modular_work: usize,
}

impl Default for KeyEstablishmentPolicy {
    fn default() -> Self {
        Self {
            encapsulation_algorithms: HashSet::new(),
            kem_content_authentication: KemContentAuthentication::default(),
            max_encapsulation_operations: 64,
            agreement_algorithms: None,
            derivation_algorithms: None,
            digest_algorithms: None,
            max_hash_blocks: 1_000_000,
            max_owned_bytes: 8 * 1024 * 1024,
            max_dh_modulus_bits: 8_192,
            minimum_dh_modulus_bits: 2_048,
            minimum_dh_subgroup_bits: 224,
            max_modular_work: 64_000_000,
        }
    }
}

impl KeyEstablishmentPolicy {
    /// Enforce the direct-content boundary independently of KEM capability.
    #[cfg(feature = "xmlenc")]
    pub(crate) fn check_kem_content(
        &self,
        algorithm: crate::xmlenc::DataEncryptionAlgorithm,
    ) -> Result<(), PolicyViolation> {
        // FIPS 203 §6.3 forbids exporting the implicit-rejection flag; CBC
        // padding therefore cannot confirm a decapsulated key. Requiring an
        // authenticated cipher by default is product policy, not a FIPS ban
        // on CBC. The explicit exception requires caller-owned authentication.
        // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
        // XMLEnc 1.1 §6.1.1: https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-edata-attacks
        permission(
            algorithm.is_authenticated()
                || self.kem_content_authentication
                    == KemContentAuthentication::ExternalAuthenticated,
            "direct KEM content without external authentication",
            algorithm.uri(),
        )
    }

    /// Reject configuration exceeding implementation ceilings before any work.
    pub fn validate(&self) -> Result<(), PolicyViolation> {
        super::ResourcePolicy::within(
            "key encapsulation operations",
            self.max_encapsulation_operations,
            crate::hard_limits::KEY_ENCAPSULATION_OPERATION_CEILING,
        )?;
        for (value, minimum, resource) in [
            (
                self.minimum_dh_modulus_bits,
                512,
                super::resource_name::DH_MODULUS_BITS,
            ),
            (
                self.minimum_dh_subgroup_bits,
                160,
                super::resource_name::DH_SUBGROUP_BITS,
            ),
        ] {
            if value < minimum || value > self.max_dh_modulus_bits {
                return Err(PolicyViolation::InvalidResourceLimit {
                    resource,
                    actual: value,
                    requirement: "minimum must respect the wire floor and modulus maximum",
                });
            }
        }
        // XMLEnc 1.1 §5.6.1: p = j*q + 1, j >= 2, hence q needs fewer
        // bits than p. Equality is valid for the modulus minimum, not q's.
        // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-DHKeyValue
        if self.minimum_dh_subgroup_bits >= self.max_dh_modulus_bits {
            return Err(PolicyViolation::InvalidResourceLimit {
                resource: super::resource_name::DH_SUBGROUP_BITS,
                actual: self.minimum_dh_subgroup_bits,
                requirement: "subgroup minimum must be strictly below modulus maximum",
            });
        }
        super::ResourcePolicy::within(
            super::resource_name::DH_MODULUS_BITS,
            self.max_dh_modulus_bits,
            crate::hard_limits::DH_MODULUS_BIT_CEILING,
        )?;
        super::ResourcePolicy::within(
            super::resource_name::KEY_ESTABLISHMENT_MODULAR_WORK,
            self.max_modular_work,
            crate::hard_limits::KEY_ESTABLISHMENT_MODULAR_WORK_CEILING,
        )?;
        super::ResourcePolicy::within(
            super::resource_name::KEY_ESTABLISHMENT_HASH_BLOCKS,
            self.max_hash_blocks,
            crate::hard_limits::KEY_ESTABLISHMENT_HASH_BLOCK_CEILING,
        )?;
        super::ResourcePolicy::within(
            super::resource_name::KEY_ESTABLISHMENT_OWNED_BYTES,
            self.max_owned_bytes,
            crate::hard_limits::KEY_ESTABLISHMENT_BYTE_CEILING,
        )
    }

    /// Enforce domain strength at import and again at operation dispatch.
    #[cfg(feature = "xmlenc")]
    pub(crate) fn check_dh_domain(
        &self,
        p_bits: usize,
        q_bits: usize,
    ) -> Result<(), PolicyViolation> {
        for (actual_bits, minimum_bits, key_type) in [
            (p_bits, self.minimum_dh_modulus_bits, "DH modulus"),
            (q_bits, self.minimum_dh_subgroup_bits, "DH subgroup"),
        ] {
            if actual_bits < minimum_bits || actual_bits > self.max_dh_modulus_bits {
                return Err(PolicyViolation::KeySize {
                    operation: "key agreement",
                    key_type,
                    minimum_bits,
                    maximum_bits: self.max_dh_modulus_bits,
                    actual_bits,
                });
            }
        }
        Ok(())
    }

    /// Check permission independently of the selected provider's capability.
    pub fn check_agreement(&self, algorithm: KeyAgreementAlgorithm) -> Result<(), PolicyViolation> {
        let allowed = match &self.agreement_algorithms {
            Some(allowed) => allowed.contains(&algorithm),
            None => matches!(
                algorithm,
                KeyAgreementAlgorithm::EcdhEs | KeyAgreementAlgorithm::X25519
            ),
        };
        permission(allowed, "key agreement", algorithm.uri())
    }

    /// Capability does not grant experimental key-establishment permission.
    pub fn check_encapsulation(
        &self,
        algorithm: crate::provider::KeyEncapsulationAlgorithm,
    ) -> Result<(), PolicyViolation> {
        permission(
            self.encapsulation_algorithms.contains(&algorithm),
            "key encapsulation",
            algorithm.uri(),
        )
    }

    /// Check KDF and its underlying digest independently. An HMAC URI does not
    /// make a digest permission apply to signatures or certificate validation.
    pub fn check_derivation(
        &self,
        algorithm: KeyDerivationAlgorithm,
        digest: DigestAlgorithm,
    ) -> Result<(), PolicyViolation> {
        let allowed = match &self.derivation_algorithms {
            Some(allowed) => allowed.contains(&algorithm),
            None => algorithm != KeyDerivationAlgorithm::LegacyDh,
        };
        permission(allowed, "key derivation", algorithm.uri())?;
        let allowed = match &self.digest_algorithms {
            Some(allowed) => allowed.contains(&digest),
            None => matches!(
                digest,
                DigestAlgorithm::Sha224
                    | DigestAlgorithm::Sha256
                    | DigestAlgorithm::Sha384
                    | DigestAlgorithm::Sha512
            ),
        };
        permission(allowed, "key derivation digest", digest.uri())
    }
}

fn permission(allowed: bool, operation: &'static str, uri: &str) -> Result<(), PolicyViolation> {
    if allowed {
        Ok(())
    } else {
        Err(PolicyViolation::Algorithm {
            operation,
            algorithm: uri.to_owned(),
        })
    }
}
