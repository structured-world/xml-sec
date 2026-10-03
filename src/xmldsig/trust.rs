//! Key discovery and authorization are distinct from signature validation.

use std::{ops::Deref, time::SystemTime};

use super::{DsigError, SignatureAlgorithm, VerifyingKey};
use crate::policy::{KeyTrustPolicy, PolicyViolation, VerificationPolicy};

/// Evidence of key authorization, independent of the signature's validity.
#[derive(Debug, Clone, PartialEq, Eq)]
// The fixed path bound avoids a heap allocation for every verification result.
#[expect(
    clippy::large_enum_variant,
    reason = "bounded inline path evidence avoids heap allocation"
)]
pub enum KeyTrustEvidence {
    /// Verification stopped before key authorization.
    NotEvaluated,
    /// Only mathematical signature verification was requested.
    NotEstablished,
    /// The application explicitly supplied or authorized this key.
    CallerTrusted,
    /// A certificate path was validated to a caller-provided anchor.
    ValidatedX509(X509TrustEvidence),
}

/// Immutable identity of the exact path that established key authorization.
/// Fields cannot be constructed or changed by a certificate parser or caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509TrustEvidence {
    fingerprints: [[u8; 32]; crate::hard_limits::X509_CHAIN_DEPTH_CEILING],
    path_len: usize,
    verification_time: SystemTime,
    revocation_checked: bool,
}

impl X509TrustEvidence {
    pub(crate) fn new(
        certificates: impl ExactSizeIterator<Item = impl AsRef<[u8]>>,
        verification_time: SystemTime,
        revocation_checked: bool,
    ) -> Result<Self, DsigError> {
        use sha2::{Digest, Sha256};
        let path_len = certificates.len();
        if path_len == 0 || path_len > crate::hard_limits::X509_CHAIN_DEPTH_CEILING {
            return Err(PolicyViolation::KeyTrust {
                reason: "invalid validated certificate path",
            }
            .into());
        }
        // Path identity is bounded by the same hard depth ceiling as validation.
        // Fixed storage avoids an unmetered post-validation allocation.
        let mut fingerprints = [[0; 32]; crate::hard_limits::X509_CHAIN_DEPTH_CEILING];
        for (fingerprint, certificate) in fingerprints.iter_mut().zip(certificates) {
            *fingerprint = Sha256::digest(certificate.as_ref()).into();
        }
        Ok(Self {
            fingerprints,
            path_len,
            verification_time,
            revocation_checked,
        })
    }

    /// SHA-256 identities in leaf-to-anchor order, including the trust anchor.
    pub fn certificate_fingerprints(&self) -> &[[u8; 32]] {
        &self.fingerprints[..self.path_len]
    }

    /// SHA-256 identity of the caller-supplied anchor that terminated the path.
    pub fn anchor_fingerprint(&self) -> &[u8; 32] {
        &self.fingerprints[self.path_len - 1]
    }

    /// The single time captured for all candidate-path validation in the operation.
    pub fn verification_time(&self) -> SystemTime {
        self.verification_time
    }

    /// Whether the policy requested and validation enforced CRL processing.
    pub fn revocation_checked(&self) -> bool {
        self.revocation_checked
    }
}

/// A public key authorized by certificate path validation, not just DER parsing.
/// Only the validating resolver can create it; callers may inspect evidence.
pub struct TrustedPublicKey {
    key: Box<dyn VerifyingKey>,
    trust: KeyTrustPolicy,
    evidence: X509TrustEvidence,
}

impl TrustedPublicKey {
    pub(crate) fn new(
        key: Box<dyn VerifyingKey>,
        mut trust: KeyTrustPolicy,
        evidence: X509TrustEvidence,
    ) -> Self {
        // RFC 5280 §6.1.1: a proof is tied to an actual validation time, never
        // to a reusable "choose now later" placeholder.
        // https://www.rfc-editor.org/rfc/rfc5280#section-6.1.1
        trust.verification_time = Some(evidence.verification_time);
        Self {
            key,
            trust,
            evidence,
        }
    }

    /// Validated certificate identities and the operation's validation time.
    pub fn evidence(&self) -> &X509TrustEvidence {
        &self.evidence
    }
}

impl VerifyingKey for TrustedPublicKey {
    fn verify_with_context(
        &self,
        algorithm: SignatureAlgorithm,
        context: &super::SignatureContext,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, DsigError> {
        self.key
            .verify_with_context(algorithm, context, data, signature)
    }
    fn validate_policy(&self, policy: &VerificationPolicy) -> Result<(), DsigError> {
        if self.trust != policy.key_trust {
            return Err(PolicyViolation::KeyTrust {
                reason: "validated key belongs to a different trust policy",
            }
            .into());
        }
        self.key.validate_policy(policy)
    }

    fn validate_signature_value(
        &self,
        algorithm: SignatureAlgorithm,
        signature: &[u8],
    ) -> Result<bool, DsigError> {
        self.key.validate_signature_value(algorithm, signature)
    }

    fn validate_signature_value_with_policy(
        &self,
        policy: &VerificationPolicy,
        algorithm: SignatureAlgorithm,
        signature: &[u8],
    ) -> Result<bool, DsigError> {
        self.validate_policy(policy)?;
        self.key
            .validate_signature_value_with_policy(policy, algorithm, signature)
    }

    fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, DsigError> {
        self.key.verify(algorithm, data, signature)
    }

    fn verify_with_policy(
        &self,
        policy: &VerificationPolicy,
        algorithm: SignatureAlgorithm,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, DsigError> {
        self.validate_policy(policy)?;
        self.key
            .verify_with_policy(policy, algorithm, data, signature)
    }
}

/// Resolver output: finding a key does not implicitly authorize its signer.
#[expect(
    clippy::large_enum_variant,
    reason = "one bounded resolver result per operation needs no extra box"
)]
pub enum ResolvedVerificationKey<'a> {
    /// Document-supplied or otherwise unauthenticated key material.
    Candidate(Box<dyn VerifyingKey + 'a>),
    /// An explicit trust declaration made by application-owned resolver code.
    CallerTrusted(Box<dyn VerifyingKey + 'a>),
    /// An unforgeable result of the built-in certificate validation boundary.
    Validated(TrustedPublicKey),
}

impl<'a> ResolvedVerificationKey<'a> {
    /// Extract the mathematical verifier without establishing signer trust.
    pub fn into_key(self) -> Box<dyn VerifyingKey + 'a> {
        match self {
            Self::Candidate(key) | Self::CallerTrusted(key) => key,
            Self::Validated(key) => Box::new(key),
        }
    }

    pub(crate) fn authorize(
        &self,
        policy: &VerificationPolicy,
    ) -> Result<KeyTrustEvidence, DsigError> {
        use crate::policy::VerificationTrustMode;
        // XMLDSig 1.1 §4.5 leaves key trust to the application:
        // https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-KeyInfo
        // This explicit mode is application policy, not a conformance requirement.
        if policy.key_trust.mode == VerificationTrustMode::CryptographicOnly {
            return Ok(KeyTrustEvidence::NotEstablished);
        }
        match self {
            Self::Candidate(_) => Err(PolicyViolation::KeyTrust {
                reason: "verification requires an authorized key",
            }
            .into()),
            Self::CallerTrusted(_) => Ok(KeyTrustEvidence::CallerTrusted),
            Self::Validated(key) => {
                key.validate_policy(policy)?;
                Ok(KeyTrustEvidence::ValidatedX509(key.evidence.clone()))
            }
        }
    }
}

impl<'a> AsRef<dyn VerifyingKey + 'a> for ResolvedVerificationKey<'a> {
    fn as_ref(&self) -> &(dyn VerifyingKey + 'a) {
        match self {
            Self::Candidate(key) | Self::CallerTrusted(key) => key.as_ref(),
            Self::Validated(key) => key,
        }
    }
}

impl<'a> Deref for ResolvedVerificationKey<'a> {
    type Target = dyn VerifyingKey + 'a;
    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NeverExecuted;
    impl VerifyingKey for NeverExecuted {
        fn verify(&self, _: SignatureAlgorithm, _: &[u8], _: &[u8]) -> Result<bool, DsigError> {
            panic!("stale authorization must fail before mathematical work");
        }
    }

    #[test]
    fn validated_key_is_bound_to_time_purpose_and_policy() {
        // A validated key must not be reusable under another time or purpose,
        // or through a caller policy whose implicit clock has not been captured.
        let time = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_000);
        let evidence =
            X509TrustEvidence::new([b"bounded certificate identity"].into_iter(), time, false)
                .expect("a one-certificate proof fits the hard path bound");
        let mut policy = VerificationPolicy::default();
        policy.key_trust.verify_x509_chains = true;
        let key =
            TrustedPublicKey::new(Box::new(NeverExecuted), policy.key_trust.clone(), evidence);
        assert!(key.validate_policy(&policy).is_err());
        policy.key_trust.verification_time = Some(time);
        key.validate_policy(&policy)
            .expect("the exact captured snapshot must match");
        let mut changed = policy.clone();
        changed.key_trust.verification_time = Some(time + std::time::Duration::from_secs(1));
        assert!(
            key.verify_with_policy(
                &changed,
                SignatureAlgorithm::RsaSha256,
                b"data",
                b"signature"
            )
            .is_err()
        );
        changed = policy.clone();
        changed
            .key_trust
            .allowed_extended_key_usages
            .insert(crate::policy::ExtendedKeyPurpose::CodeSigning);
        assert!(key.validate_policy(&changed).is_err());
        changed = policy;
        changed.key_trust.check_crls = true;
        assert!(key.validate_policy(&changed).is_err());
    }
}
