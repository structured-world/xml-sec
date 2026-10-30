//! CMS `SignedData` and RFC 3161 signature checks through the selected provider.
//!
//! [`CmsProvider`] implements the `structured-cms` provider contract over one
//! [`CryptoProvider`] and one compiled [`VerificationPolicy`]: digests start
//! through [`SessionDigest`] under the digest policy, and signature identifiers
//! resolve through the shared PKIX mapping under the certificate-signature
//! permissions and RSA/DSA key policy. Trust in the signer remains the
//! caller's decision.
//!
//! The provider interface verifies contiguous signed bytes, so every signature
//! is processed in raw mode: the signed octets are admitted against the
//! operation's memory and verified in one call. CMS timestamp tokens sign only
//! their small `signedAttrs` set (RFC 3161 §2.4.2).

use core::cmp::Ordering;

use structured_asn1::digest::{Digest, Resolution};
use structured_asn1::memory::{MemoryError, OwnedVec, Work};
use structured_asn1::{Encoding, Reader};
use structured_cms::Octets;
use structured_cms::provider::{Prehash, SignatureAnswer, SignatureMode, SignatureProvider};
use structured_pkix::AlgorithmIdentifier;
use structured_pkix::algorithm::digest::{Algorithm, AsnDigest};
use structured_pkix::path::WorkingKey;

use super::pkix::CertificateSession;
use super::verify::SessionDigest;
use super::{DigestAlgorithm, DsigError, X509ChainError};
use crate::policy::{KeyTrustPolicy, PolicyViolation, VerificationPolicy};
use crate::provider::{CryptoProvider, ProviderCapability, X509SignatureAlgorithm};

/// RFC 8017 Appendix A.1 `rsaEncryption`, 1.2.840.113549.1.1.1.
const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

/// The `structured-cms` provider of one verification operation.
///
/// One value serves one CMS processing session: its signer key checks share
/// one [`ResourcePolicy::max_x509_work`](crate::policy::ResourcePolicy) account.
pub struct CmsProvider<'p> {
    provider: &'p dyn CryptoProvider,
    policy: &'p VerificationPolicy,
    certificates: CertificateSession,
}

impl core::fmt::Debug for CmsProvider<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CmsProvider")
            .field("provider", &self.provider.name())
            .finish_non_exhaustive()
    }
}

impl<'p> CmsProvider<'p> {
    /// Bind `provider` and `policy` and open the session's certificate account.
    #[must_use]
    pub fn new(provider: &'p dyn CryptoProvider, policy: &'p VerificationPolicy) -> Self {
        Self {
            provider,
            policy,
            certificates: CertificateSession::new(&policy.resources),
        }
    }
}

/// A CMS provider failure, distinct from an invalid signature or digest mismatch.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CmsProviderError {
    /// The operation policy refuses the algorithm or the signer's key strength.
    #[error(transparent)]
    Policy(#[from] PolicyViolation),
    /// The signer's key could not be processed.
    #[error(transparent)]
    Certificate(X509ChainError),
    /// Digest execution failed in the selected provider.
    #[error(transparent)]
    Digest(DsigError),
    /// The current execution refused work or storage.
    #[error("CMS provider resource refusal: {0}")]
    Resource(MemoryError),
    /// A finalized prehash reached a provider that only selects raw mode.
    #[error("finalized-prehash verification is not selected by this provider")]
    PrehashNotSelected,
}

impl From<MemoryError> for CmsProviderError {
    fn from(error: MemoryError) -> Self {
        Self::Resource(error)
    }
}

impl From<X509ChainError> for CmsProviderError {
    fn from(error: X509ChainError) -> Self {
        match error {
            X509ChainError::Policy(violation)
            | X509ChainError::KeyPolicy {
                source: violation, ..
            } => Self::Policy(violation),
            other => Self::Certificate(other),
        }
    }
}

impl From<DsigError> for CmsProviderError {
    fn from(error: DsigError) -> Self {
        match error {
            DsigError::Policy(violation) => Self::Policy(violation),
            other => Self::Digest(other),
        }
    }
}

/// A finished digest, held inline.
#[derive(Debug, Clone, Copy)]
pub struct DigestOutput {
    bytes: [u8; 64],
    len: usize,
}

impl AsRef<[u8]> for DigestOutput {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl<'a> Digest<'a> for CmsProvider<'_> {
    type Identity = DigestAlgorithm;
    type State = SessionDigest<'a>;
    type Output = DigestOutput;
    type Error = CmsProviderError;

    fn width(&self, identity: &DigestAlgorithm) -> Option<usize> {
        Some(identity.output_len())
    }

    fn compare<Q: Work>(
        &self,
        left: &DigestAlgorithm,
        right: &DigestAlgorithm,
        execution: &Q,
    ) -> Result<Ordering, CmsProviderError> {
        execution.charge_work(1)?;
        Ok(left.cmp(right))
    }

    fn start<Q: Work>(
        &'a self,
        identity: &DigestAlgorithm,
        execution: &Q,
    ) -> Result<Resolution<SessionDigest<'a>>, CmsProviderError> {
        execution.charge_work(1)?;
        Ok(Resolution::Supported(SessionDigest::begin(
            self.provider,
            self.policy,
            *identity,
        )?))
    }

    fn update<Q: Work>(
        &self,
        state: &mut SessionDigest<'a>,
        bytes: &[u8],
        execution: &Q,
    ) -> Result<(), CmsProviderError> {
        Ok(state.update(bytes, execution)?)
    }

    fn finish<Q: Work>(
        &self,
        state: SessionDigest<'a>,
        execution: &Q,
    ) -> Result<DigestOutput, CmsProviderError> {
        let mut output = DigestOutput {
            bytes: [0; 64],
            len: state.output_len(),
        };
        state.finish(&mut output.bytes[..output.len], execution)?;
        Ok(output)
    }

    fn matches<Q: Work>(
        &self,
        _identity: &DigestAlgorithm,
        output: &DigestOutput,
        expected: &[u8],
        execution: &Q,
    ) -> Result<bool, CmsProviderError> {
        execution.charge_work(expected.len() as u64)?;
        Ok(super::constant_time_eq(output.as_ref(), expected))
    }
}

impl AsnDigest<'_> for CmsProvider<'_> {
    // A digest the policy refuses keeps its identity here and fails as a
    // typed policy violation when it starts, rather than as unsupported.
    fn identity(&self, algorithm: Algorithm) -> Option<DigestAlgorithm> {
        super::pkix::digest_algorithm(algorithm)
    }
}

/// Raw signature input admitted against the operation's memory.
pub struct RawSignature<'a> {
    algorithm: X509SignatureAlgorithm,
    key: WorkingKey<'a>,
    signature: &'a Octets<'a>,
    signed: OwnedVec<u8>,
}

impl core::fmt::Debug for RawSignature<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawSignature")
            .field("algorithm", &self.algorithm)
            .field("signed_len", &self.signed.len())
            .finish_non_exhaustive()
    }
}

impl CmsProvider<'_> {
    /// The provider algorithm `identifier` names for a signer whose
    /// `digestAlgorithm` resolved to `digest`, or why there is none.
    fn signature_algorithm(
        identifier: AlgorithmIdentifier<'_>,
        digest: DigestAlgorithm,
        parent: &Reader<'_>,
    ) -> Result<Resolution<X509SignatureAlgorithm>, CmsProviderError> {
        let execution = parent.execution();
        execution.charge_work(identifier.algorithm().as_bytes().len() as u64)?;
        if identifier.algorithm().as_bytes() == RSA_ENCRYPTION {
            // RFC 3370 §3.2: rsaEncryption identifies PKCS #1 v1.5 signatures
            // whatever the digest, which digestAlgorithm names; its
            // parameters MUST be NULL.
            // https://www.rfc-editor.org/rfc/rfc3370#section-3.2
            return Ok(if identifier.has_null_parameter() {
                Resolution::Supported(X509SignatureAlgorithm::RsaPkcs1v15(digest))
            } else {
                Resolution::Malformed
            });
        }
        let Some(algorithm) = super::pkix::known_signature_algorithm(identifier, &execution)?
        else {
            return Ok(Resolution::Unsupported);
        };
        // Raw verification never reads digestAlgorithm, so only this check
        // binds it. RFC 5754 sets no such rule for PKCS #1 v1.5 or DSA.
        let consistent = match algorithm {
            // RFC 5753 §2.1.1: the hash named by an ECDSA signature algorithm
            // MUST be the same as digestAlgorithm.
            // https://www.rfc-editor.org/rfc/rfc5753#section-2.1.1
            // RFC 4056 §3: signedAttrs and the RSASSA-PSS hashAlgorithm MUST
            // use the same hash.
            // https://www.rfc-editor.org/rfc/rfc4056#section-3
            X509SignatureAlgorithm::Ecdsa(hash)
            | X509SignatureAlgorithm::RsaPss { digest: hash, .. } => hash == digest,
            // RFC 8419 §3.1 and §3.2: digestAlgorithm MUST be id-sha512 for
            // Ed25519, and a SHAKE256 identifier for Ed448, which never
            // resolves to a DigestAlgorithm.
            // https://www.rfc-editor.org/rfc/rfc8419#section-3
            X509SignatureAlgorithm::Ed25519 => digest == DigestAlgorithm::Sha512,
            X509SignatureAlgorithm::Ed448 => false,
            _ => true,
        };
        Ok(if consistent {
            Resolution::Supported(algorithm)
        } else {
            Resolution::Malformed
        })
    }
}

impl<'a> SignatureProvider<'a> for CmsProvider<'_> {
    type SignatureIdentity = X509SignatureAlgorithm;
    type RawState = RawSignature<'a>;

    fn resolve_signature(
        &'a self,
        identifier: AlgorithmIdentifier<'a>,
        digest: &DigestAlgorithm,
        key: WorkingKey<'a>,
        _encoding: Encoding,
        parent: &Reader<'a>,
    ) -> Result<Resolution<SignatureMode<X509SignatureAlgorithm>>, CmsProviderError> {
        let algorithm = match Self::signature_algorithm(identifier, *digest, parent)? {
            Resolution::Supported(algorithm) => algorithm,
            Resolution::Unsupported => return Ok(Resolution::Unsupported),
            Resolution::Malformed => return Ok(Resolution::Malformed),
        };
        // Permission precedes capability, as for certificate signatures.
        KeyTrustPolicy::check_certificate_signature_algorithm(
            algorithm,
            self.policy
                .key_trust
                .certificate_signature_algorithms
                .as_ref(),
        )?;
        if !self
            .provider
            .supports(ProviderCapability::VerifyCertificate(algorithm))
        {
            return Ok(Resolution::Unsupported);
        }
        // Key strength is checked before any signed byte is read.
        super::pkix::with_effective_spki(key, &parent.execution(), |spki| {
            super::x509::validate_issuer_spki_policy(
                spki,
                0,
                self.policy.key_trust.rsa_keys,
                self.policy.key_trust.dsa_keys,
                &self.certificates,
            )
        })?;
        Ok(Resolution::Supported(SignatureMode::Raw(algorithm)))
    }

    fn compare_signature<W: Work>(
        &self,
        left: &X509SignatureAlgorithm,
        right: &X509SignatureAlgorithm,
        execution: &W,
    ) -> Result<Ordering, CmsProviderError> {
        execution.charge_work(1)?;
        Ok(left.cmp(right))
    }

    fn start_raw<W: Work>(
        &'a self,
        identity: &X509SignatureAlgorithm,
        key: WorkingKey<'a>,
        signature: &'a Octets<'a>,
        execution: &W,
    ) -> Result<RawSignature<'a>, CmsProviderError> {
        execution.charge_work(1)?;
        Ok(RawSignature {
            algorithm: *identity,
            key,
            signature,
            signed: execution.vector().into_owned(),
        })
    }

    fn update_raw<W: Work>(
        &self,
        state: &mut RawSignature<'a>,
        bytes: &[u8],
        execution: &W,
    ) -> Result<(), CmsProviderError> {
        execution.charge_work(bytes.len() as u64)?;
        state.signed.try_extend_from_slice(bytes)?;
        Ok(())
    }

    fn finish_raw<W: Work>(
        &self,
        state: RawSignature<'a>,
        execution: &W,
    ) -> Result<SignatureAnswer, CmsProviderError> {
        let RawSignature {
            algorithm,
            key,
            signature,
            signed,
        } = state;
        execution.charge_work((signed.len() + signature.len()) as u64)?;
        // A BER constructed OCTET STRING is joined once, admitted first.
        let joined;
        let signature = if let Some(bytes) = signature.as_one() {
            bytes
        } else {
            let mut bytes = execution.vector();
            bytes.try_reserve_exact(signature.len())?;
            for piece in signature.pieces() {
                bytes.try_extend_from_slice(piece.as_bytes())?;
            }
            joined = bytes;
            &joined[..]
        };
        let valid = super::pkix::with_effective_spki(key, execution, |spki| {
            self.provider
                .verify_x509_signature(algorithm, &signed, signature, spki)
                .map_err(X509ChainError::from)
        })?;
        Ok(if valid {
            SignatureAnswer::Valid
        } else {
            SignatureAnswer::Invalid
        })
    }

    fn verify_prehashed<W: Work>(
        &'a self,
        _identity: &X509SignatureAlgorithm,
        _key: WorkingKey<'a>,
        _signature: &Octets<'a>,
        _digest: Prehash<'_, '_, Self, DigestAlgorithm>,
        _execution: &W,
    ) -> Result<SignatureAnswer, CmsProviderError> {
        // resolve_signature selects raw mode for every algorithm.
        Err(CmsProviderError::PrehashNotSelected)
    }
}
