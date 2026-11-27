//! Signature policy digests a technical specification defines, rather than
//! the `XMLDSig` transforms of `SignaturePolicyId` (EN 319 132-1 §5.2.9.2,
//! `SPDocDigestAsInSpecification`).

use super::PropertyError;
use crate::draft::DraftError;
use core::cmp::Ordering;
use structured_asn1::Parser;
use structured_asn1::digest::{Digest, Resolution};
use structured_asn1::memory::Work;
use structured_cms::signature_policy::Asn1Policy;
use structured_pkix::algorithm::digest::{Algorithm, AsnDigest};
use xml_sec::policy::SigningPolicy;
use xml_sec::provider::CryptoProvider;
use xml_sec::xmldsig::{
    DigestAlgorithm, DigestOutput, IncrementalDigest, MAX_DIGEST_OUTPUT, constant_time_eq,
};

/// The specification a policy's `SPDocSpecification` names and the digest
/// rule xml-sec applies for it. Which identifier denotes a specification is
/// the caller's knowledge of its own policy: the `XAdES` schema assigns none.
#[derive(Debug, Clone, Copy)]
pub struct SpecifiedDigest<'a> {
    /// The `SPDocSpecification` identifier, compared with the written one.
    pub specification: &'a str,
    /// How the policy document is digested under that specification.
    pub rule: DigestRule,
}

/// A policy digest rule a technical specification defines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DigestRule {
    /// The DER `SignaturePolicy` of ETSI TR 102 272 V1.1.1 §6.1: the digest
    /// covers the original `signPolicyHashAlg` and `signPolicyInfo`, under
    /// the hash algorithm the document itself names, which must be the
    /// policy digest method; a stored `signPolicyHash` must equal it.
    Asn1Policy,
}

/// A finished policy digest, whichever rule computed it.
#[derive(Debug, Clone, Copy)]
pub struct PolicyHash {
    bytes: [u8; MAX_DIGEST_OUTPUT],
    len: usize,
}

impl PolicyHash {
    fn copied(digest: &[u8]) -> Self {
        let mut bytes = [0; MAX_DIGEST_OUTPUT];
        // Every width the provider adapter admits is an XMLDSig digest width.
        bytes[..digest.len()].copy_from_slice(digest);
        Self {
            bytes,
            len: digest.len(),
        }
    }
}

impl From<DigestOutput> for PolicyHash {
    fn from(digest: DigestOutput) -> Self {
        Self::copied(&digest)
    }
}

impl AsRef<[u8]> for PolicyHash {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// The ETSI TR 102 272 digest of the DER policy `document` under `method`.
pub(super) fn asn1_policy<W: Work>(
    document: &[u8],
    method: DigestAlgorithm,
    provider: &dyn CryptoProvider,
    policy: &SigningPolicy,
    work: &W,
) -> Result<PolicyHash, PropertyError> {
    let parser = Parser::der(work.memory().clone());
    let mut reader = parser.read(document, 0).map_err(PropertyError::Der)?;
    let read = Asn1Policy::read(&mut reader).map_err(PropertyError::Asn1)?;
    let selected = pkix_algorithm(method).ok_or(PropertyError::Asn1Method)?;
    let digests = SigningDigests { provider, policy };
    let output = read
        .digest(&digests, selected, work)
        .map_err(|error| PropertyError::Asn1Digest(alloc::boxed::Box::new(error)))?;
    Ok(PolicyHash::copied(output.as_bytes()))
}

/// The ASN.1 identity of an `XMLDSig` digest the specification may name.
fn pkix_algorithm(method: DigestAlgorithm) -> Option<Algorithm> {
    [
        Algorithm::Sha1,
        Algorithm::Sha224,
        Algorithm::Sha256,
        Algorithm::Sha384,
        Algorithm::Sha512,
        Algorithm::Sha3_224,
        Algorithm::Sha3_256,
        Algorithm::Sha3_384,
        Algorithm::Sha3_512,
    ]
    .into_iter()
    .find(|candidate| DigestAlgorithm::from_pkix(*candidate) == Some(method))
}

/// The signer's provider under its signing policy, as the shared ASN.1
/// digest contract expects.
struct SigningDigests<'p> {
    provider: &'p dyn CryptoProvider,
    policy: &'p SigningPolicy,
}

impl<'a, 'p: 'a> Digest<'a> for SigningDigests<'p> {
    type Identity = DigestAlgorithm;
    type State = IncrementalDigest<'a>;
    type Output = DigestOutput;
    type Error = PropertyError;

    fn width(&self, identity: &DigestAlgorithm) -> Option<usize> {
        Some(identity.output_len())
    }

    fn compare<W: Work>(
        &self,
        left: &DigestAlgorithm,
        right: &DigestAlgorithm,
        execution: &W,
    ) -> Result<Ordering, PropertyError> {
        execution.charge_work(1).map_err(DraftError::from)?;
        Ok(left.cmp(right))
    }

    fn start<W: Work>(
        &'a self,
        identity: &DigestAlgorithm,
        execution: &W,
    ) -> Result<Resolution<IncrementalDigest<'a>>, PropertyError> {
        self.policy.check_digest_algorithm(*identity)?;
        execution.charge_work(1).map_err(DraftError::from)?;
        Ok(Resolution::Supported(IncrementalDigest::begin(
            self.provider,
            *identity,
        )?))
    }

    fn update<W: Work>(
        &self,
        state: &mut IncrementalDigest<'a>,
        bytes: &[u8],
        execution: &W,
    ) -> Result<(), PropertyError> {
        execution
            .charge_work(bytes.len() as u64)
            .map_err(DraftError::from)?;
        Ok(state.update(bytes)?)
    }

    fn finish<W: Work>(
        &self,
        state: IncrementalDigest<'a>,
        execution: &W,
    ) -> Result<DigestOutput, PropertyError> {
        execution.charge_work(1).map_err(DraftError::from)?;
        Ok(state.finish()?)
    }

    fn matches<W: Work>(
        &self,
        _identity: &DigestAlgorithm,
        output: &DigestOutput,
        expected: &[u8],
        execution: &W,
    ) -> Result<bool, PropertyError> {
        execution
            .charge_work(expected.len() as u64)
            .map_err(DraftError::from)?;
        Ok(constant_time_eq(output, expected))
    }
}

impl<'a, 'p: 'a> AsnDigest<'a> for SigningDigests<'p> {
    // A digest the signing policy refuses keeps its identity here and fails
    // as a policy violation when it starts, rather than as unsupported.
    fn identity(&self, algorithm: Algorithm) -> Option<DigestAlgorithm> {
        DigestAlgorithm::from_pkix(algorithm)
    }
}
