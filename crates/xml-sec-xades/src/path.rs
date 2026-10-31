//! The certificate paths xml-sec validated, re-checked by the shared processor.

use crate::Error;
use structured_asn1::Parser;
use structured_asn1::memory::{HashWork, Memory, MemoryError, OwnedVec, Work};
use structured_ltv::pki::{CheckedPath, PathOutcome};
use structured_pkix::path::{
    Anchor, Bounds, BuildError, Context as PathContext, Interval, Policy, Truncation,
    ValidationContext, Verified, Verify as PathVerify, WorkingKey,
};
use structured_pkix::signature::SignatureValue;
use structured_pkix::temporal::Instant;
use structured_pkix::{AlgorithmIdentifier, Certificate};
use xml_sec::document::NodeIdentity;
use xml_sec::xmldsig::extension::{self, NodeView};
use xml_sec::xmldsig::{KeyTrustEvidence, VerifiedSession, X509ChainError, X509TrustEvidence};

#[cfg(test)]
mod tests;

const DS: &str = "http://www.w3.org/2000/09/xmldsig#";

/// Why a signer has no certificate path for baseline validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathFailure {
    /// Verification established no X.509 path for this signer (for example a
    /// caller-trusted key or cryptographic-only verification).
    NotValidated,
    /// The validated path consists of the trust anchor alone, so it has no
    /// certification path to check (RFC 5280 §6.1 excludes the anchor).
    AnchorOnly,
    /// A certificate of the validated path is neither in this Signature's
    /// `KeyInfo` nor in the caller's certificate pool.
    MissingCertificate,
    /// The shared path processor rejected the validated path.
    Rejected,
    /// The shared path processor stopped at an explicit bound.
    Incomplete(Truncation),
}

/// Why a countersignature's checked path could not be supplied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterPathError {
    /// The countersigner has no checked path.
    Missing(PathFailure),
    /// The current execution refused the lookup.
    Resource(MemoryError),
}

/// Refuse an identity that is not a Signature of the verified request.
pub(crate) fn require_member<W: Work, Q: Work>(
    session: &VerifiedSession<'_, '_, '_, W>,
    signature: NodeIdentity,
    work: &Q,
) -> Result<(), Error> {
    for entry in session.evidence().signatures() {
        work.charge_work(signature.hash_work()?)?;
        if entry.identity() == signature {
            return Ok(());
        }
    }
    Err(Error::UnknownSignature)
}

/// The root and each incorporated countersignature whose verification
/// validated an X.509 path. Other signatures of the document, including ones
/// nested inside signed content, are not actors of this root.
pub(crate) fn signers<'e, W: Work, Q: Work>(
    session: &'e VerifiedSession<'_, '_, '_, W>,
    root: NodeIdentity,
    counters: &[NodeIdentity],
    work: &Q,
) -> Result<OwnedVec<(NodeIdentity, &'e X509TrustEvidence)>, Error> {
    let mut signers = work.vector();
    for entry in session.evidence().signatures() {
        let identity = entry.identity();
        work.charge_work(
            identity
                .hash_work()?
                .checked_mul(
                    u64::try_from(counters.len() + 1).map_err(|_| MemoryError::WorkExceeded)?,
                )
                .ok_or(MemoryError::WorkExceeded)?,
        )?;
        if identity != root && !counters.contains(&identity) {
            continue;
        }
        if let Ok(result) = entry.result()
            && let KeyTrustEvidence::ValidatedX509(evidence) = &result.key_trust
        {
            signers.try_push((identity, evidence))?;
        }
    }
    Ok(signers.into_owned())
}

/// Decode the `X509Certificate` values in each signer's direct `KeyInfo`.
pub(crate) fn key_info_certificates<W: Work, Q: Work>(
    session: &VerifiedSession<'_, '_, '_, W>,
    signers: &[(NodeIdentity, &X509TrustEvidence)],
    storage: &Q,
) -> Result<OwnedVec<OwnedVec<u8>>, Error> {
    // Navigation and base64 decoding are XML queries on the request's own
    // execution; only the retained certificate bytes belong to `storage`.
    let (view, work) = (session.view(), session.execution());
    let mut decoded = storage.vector();
    for (signature, _) in signers {
        for key_info in &children(session, *signature, "KeyInfo", work)? {
            for data in &children(session, *key_info, "X509Data", work)? {
                for value in &children(session, *data, "X509Certificate", work)? {
                    let bytes = extension::with_base64(view, *value, work, |bytes| {
                        let mut copy = storage.vector();
                        copy.try_extend_from_slice(bytes)
                            .map(|()| copy.into_owned())
                    })??;
                    decoded.try_push(bytes)?;
                }
            }
        }
    }
    Ok(decoded.into_owned())
}

/// The instant verification validated `signature`'s path at, if it did.
pub(crate) fn verification_time(
    signers: &[(NodeIdentity, &X509TrustEvidence)],
    signature: NodeIdentity,
) -> Option<Instant> {
    signers
        .iter()
        .find(|(identity, _)| *identity == signature)
        .map(|(_, evidence)| evidence.verification_time())
}

/// The decoded `KeyInfo` certificates followed by each of the caller's lists.
pub(crate) fn candidates<'c, Q: Work>(
    decoded: &'c [OwnedVec<u8>],
    [first, second]: [&[&'c [u8]]; 2],
    work: &Q,
) -> Result<OwnedVec<&'c [u8], Q>, Error> {
    let mut candidates = work.vector();
    candidates.try_reserve_exact(decoded.len() + first.len() + second.len())?;
    for bytes in decoded {
        candidates.try_push(&bytes[..])?;
    }
    candidates.try_extend_from_slice(first)?;
    candidates.try_extend_from_slice(second)?;
    Ok(candidates)
}

fn children<W: Work, Q: Work>(
    session: &VerifiedSession<'_, '_, '_, W>,
    parent: NodeIdentity,
    local: &str,
    work: &Q,
) -> Result<OwnedVec<NodeIdentity>, Error> {
    let view = session.view();
    let mut found = work.vector();
    let mut next = extension::first_child(view, parent, work)?;
    while let Some(node) = next {
        let matches = extension::inspect_node(view, node, work, |value| {
            matches!(
                value,
                NodeView::Element { namespace: Some(namespace), local_name }
                    if namespace == DS && local_name == local
            )
        })?;
        if matches {
            found.try_push(node)?;
        }
        next = extension::next_sibling(view, parent, node, work)?;
    }
    Ok(found.into_owned())
}

/// One signer, its trust evidence and its path as positions into the parsed
/// certificates, leaf to anchor.
type SignerPath<'d> = (
    NodeIdentity,
    &'d X509TrustEvidence,
    Result<OwnedVec<usize>, PathFailure>,
);

/// The parsed certificates of every signer's validated path.
pub(crate) struct Selection<'d> {
    certificates: OwnedVec<Certificate<'d>>,
    signers: OwnedVec<SignerPath<'d>>,
}

/// Identify the exact certificates of each validated path among `candidates`
/// by their recorded path identities, and parse each certificate once with
/// the operation's policy-bounded certificate parser.
pub(crate) fn select<'d, Q: Work>(
    signers: &[(NodeIdentity, &'d X509TrustEvidence)],
    candidates: &[&'d [u8]],
    parser: &'d Parser,
    work: &Q,
) -> Result<Selection<'d>, Error> {
    let mut identities: OwnedVec<Option<[u8; 32]>, Q> = work.vector();
    identities.try_reserve_exact(candidates.len())?;
    for _ in candidates {
        identities.try_push(None)?;
    }
    // Candidate index of each parsed certificate, parallel to `certificates`.
    let mut sources: OwnedVec<usize, Q> = work.vector();
    let mut certificates = work.vector();
    let mut selected = work.vector();
    for (signature, evidence) in signers {
        let mut path = work.vector();
        let mut missing = false;
        for fingerprint in evidence.certificate_fingerprints() {
            let Some(index) = find(candidates, &mut identities, fingerprint, work)? else {
                missing = true;
                break;
            };
            work.charge_work(u64::try_from(sources.len()).map_err(|_| MemoryError::WorkExceeded)?)?;
            let position =
                if let Some(position) = sources.iter().position(|source| *source == index) {
                    position
                } else {
                    let certificate = Certificate::read(parser, candidates[index], 0)
                        .map_err(X509ChainError::Processing)?;
                    sources.try_push(index)?;
                    certificates.try_push(certificate)?;
                    certificates.len() - 1
                };
            path.try_push(position)?;
        }
        selected.try_push((
            *signature,
            *evidence,
            if missing {
                Err(PathFailure::MissingCertificate)
            } else {
                Ok(path.into_owned())
            },
        ))?;
    }
    Ok(Selection {
        certificates: certificates.into_owned(),
        signers: selected.into_owned(),
    })
}

fn find<Q: Work>(
    candidates: &[&[u8]],
    identities: &mut [Option<[u8; 32]>],
    fingerprint: &[u8; 32],
    work: &Q,
) -> Result<Option<usize>, Error> {
    for (index, candidate) in candidates.iter().enumerate() {
        let identity = if let Some(identity) = identities[index] {
            identity
        } else {
            // The same internal identity the trust evidence recorded,
            // independent of the document's digest policy.
            let identity = X509TrustEvidence::certificate_identity_in(candidate, work)?;
            identities[index] = Some(identity);
            identity
        };
        work.charge_work(32)?;
        if identity == *fingerprint {
            return Ok(Some(index));
        }
    }
    Ok(None)
}

/// Checked paths keyed by their signer.
pub(crate) struct Paths<'d> {
    entries: OwnedVec<(NodeIdentity, Result<CheckedPath<'d>, PathFailure>)>,
}

impl<'d> Paths<'d> {
    /// The checked path of `signature`, or why it has none. Every identity
    /// comparison is charged to `work` first.
    pub(crate) fn get<Q: Work>(
        &self,
        signature: NodeIdentity,
        work: &Q,
    ) -> Result<&CheckedPath<'d>, CounterPathError> {
        for (signer, path) in &self.entries {
            work.charge_work(
                signature
                    .hash_work()
                    .and_then(|cost| cost.checked_mul(2).ok_or(MemoryError::WorkExceeded))
                    .map_err(CounterPathError::Resource)?,
            )
            .map_err(CounterPathError::Resource)?;
            if *signer == signature {
                return path
                    .as_ref()
                    .map_err(|failure| CounterPathError::Missing(*failure));
            }
        }
        Err(CounterPathError::Missing(PathFailure::NotValidated))
    }
}

/// Re-check each selected path with the operation's provider, certificate
/// policy and path bounds.
pub(crate) fn check<'d, W: Work, Q: Work>(
    session: &VerifiedSession<'_, '_, '_, W>,
    selection: &'d Selection<'d>,
    (root, span): (NodeIdentity, Option<Interval>),
    work: &Q,
) -> Result<Paths<'d>, Error> {
    let mut entries = work.vector();
    for (signature, evidence, path) in &selection.signers {
        let interval = span
            .filter(|_| *signature == root)
            .unwrap_or_else(|| Interval::at_instant(evidence.verification_time()));
        let outcome = match path {
            Ok(path) => checked(session, &selection.certificates, interval, path, work)?,
            Err(failure) => Err(*failure),
        };
        entries.try_push((*signature, outcome))?;
    }
    Ok(Paths {
        entries: entries.into_owned(),
    })
}

fn checked<'d, W: Work, Q: Work>(
    session: &VerifiedSession<'_, '_, '_, W>,
    certificates: &'d [Certificate<'d>],
    interval: Interval,
    path: &[usize],
    work: &Q,
) -> Result<Result<CheckedPath<'d>, PathFailure>, Error> {
    let Some((anchor, members)) = path.split_last() else {
        return Ok(Err(PathFailure::MissingCertificate));
    };
    if members.is_empty() {
        return Ok(Err(PathFailure::AnchorOnly));
    }
    let mut chain = work.vector();
    for position in members {
        chain.try_push(&certificates[*position])?;
    }
    check_chain(session, &chain, &certificates[*anchor], interval, work)
}

/// One leaf-first chain through the shared processor over `interval`, with the
/// operation's provider, certificate policy and path bounds.
pub(crate) fn check_chain<'d, W: Work, Q: Work>(
    session: &VerifiedSession<'_, '_, '_, W>,
    chain: &[&'d Certificate<'d>],
    anchor: &'d Certificate<'d>,
    interval: Interval,
    work: &Q,
) -> Result<Result<CheckedPath<'d>, PathFailure>, Error> {
    let verifier = session.certificate_path_verifier(chain, anchor);
    let context = ValidationContext {
        execution: work,
        interval,
        policy: Policy::default(),
        bounds: session.certificate_path_bounds(),
        verifier: &verifier,
        watch: &(),
        recognizer: &(),
    };
    match structured_ltv::pki::check_path(chain, Anchor::from_certificate(anchor), &context) {
        Ok(PathOutcome::Accepted(path)) => Ok(Ok(path)),
        Ok(PathOutcome::Rejected(_)) => Ok(Err(PathFailure::Rejected)),
        Ok(PathOutcome::Incomplete(reason)) => Ok(Err(PathFailure::Incomplete(reason))),
        Err(BuildError::Processing(error)) => Err(X509ChainError::Processing(error).into()),
        Err(BuildError::Verification(error)) => Err(error.into()),
        Err(BuildError::Recognition(never)) => match never {},
    }
}

/// Discovery answers which issuers name each other; it proves nothing.
/// [`check_chain`] authenticates every edge of a candidate once, so a forged
/// issuer can only cost its own path's rejection.
struct Unverified;

impl PathVerify for Unverified {
    type Error = core::convert::Infallible;

    fn verify(
        &self,
        _algorithm: &AlgorithmIdentifier<'_>,
        _key: WorkingKey<'_>,
        _signed: &[u8],
        _signature: SignatureValue<'_>,
        _execution: &Memory,
    ) -> Result<Verified, Self::Error> {
        Ok(Verified::Yes)
    }
}

/// The caller's trust anchors, the certificates every issuer may come from
/// and the account path work spends.
pub(crate) struct Authorities<'d> {
    pub(crate) anchors: &'d [Certificate<'d>],
    /// `anchors` in the form path building takes, built once per validation.
    pub(crate) anchored: &'d [Anchor<'d>],
    pub(crate) pool: &'d [&'d Certificate<'d>],
    pub(crate) responders: &'d [crate::level::ConfiguredResponder<'d>],
    pub(crate) memory: &'d Memory,
}

/// The first candidate path from `target` to a caller anchor that the shared
/// processor accepts over `interval`.
pub(crate) fn discover<'d, W: Work>(
    session: &VerifiedSession<'_, '_, '_, W>,
    authorities: &Authorities<'d>,
    target: &'d Certificate<'d>,
    interval: Interval,
) -> Result<Result<CheckedPath<'d>, PathFailure>, Error> {
    let memory = authorities.memory;
    let bounds = session.certificate_path_bounds();
    let context = PathContext {
        execution: memory,
        anchors: authorities.anchored,
        interval,
        bounds: Bounds {
            depth: bounds.depth,
            work: bounds.work,
            policies: bounds.policies,
            ..Bounds::default()
        },
        policy: Policy::default(),
        verifier: &Unverified,
        watch: &(),
        recognizer: &(),
    };
    let found = match structured_pkix::path::build(target, authorities.pool, &context) {
        Ok(found) => found,
        Err(BuildError::Processing(error)) => return Err(X509ChainError::Processing(error).into()),
        Err(BuildError::Verification(never) | BuildError::Recognition(never)) => match never {},
    };
    let mut failure = found
        .truncated()
        .map_or(PathFailure::NotValidated, PathFailure::Incomplete);
    for candidate in found.paths() {
        let Some(anchor) = candidate.anchor().certificate() else {
            continue;
        };
        match check_chain(session, candidate.certificates(), anchor, interval, memory)? {
            Ok(path) => return Ok(Ok(path)),
            Err(reason) => failure = reason,
        }
    }
    Ok(Err(failure))
}
