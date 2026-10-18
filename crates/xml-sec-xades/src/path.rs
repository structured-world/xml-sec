//! The certificate paths xml-sec validated, re-checked by the shared processor.

use crate::Error;
use structured_asn1::Parser;
use structured_asn1::memory::{Memory, OwnedVec, Work};
use structured_pkix::Certificate;
use structured_pkix::path::{
    Anchor, BuildError, Interval, Policy, Truncation, ValidationBounds, ValidationContext,
};
use structured_xades::pki::{CheckedPath, PathOutcome};
use xml_sec::document::NodeIdentity;
use xml_sec::xmldsig::extension::{self, NodeView};
use xml_sec::xmldsig::{
    DigestAlgorithm, KeyTrustEvidence, VerifiedSession, X509ChainError, X509TrustEvidence,
    constant_time_eq,
};

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

/// Every signer of `root`'s subtree whose verification validated an X.509 path.
pub(crate) fn signers<'e, W: Work>(
    session: &'e VerifiedSession<'_, '_, '_, W>,
    root: NodeIdentity,
    memory: &Memory,
) -> Result<OwnedVec<(NodeIdentity, &'e X509TrustEvidence)>, Error> {
    let mut signers = memory.vector();
    for entry in session.evidence().signatures() {
        memory.charge_work(1)?;
        if !extension::subtree_contains(session.view(), root, entry.identity(), memory)? {
            continue;
        }
        if let Ok(result) = entry.result()
            && let KeyTrustEvidence::ValidatedX509(evidence) = &result.key_trust
        {
            signers.try_push((entry.identity(), evidence))?;
        }
    }
    Ok(signers)
}

/// Decode the `X509Certificate` values in each signer's direct `KeyInfo`.
pub(crate) fn key_info_certificates<W: Work>(
    session: &VerifiedSession<'_, '_, '_, W>,
    signers: &[(NodeIdentity, &X509TrustEvidence)],
    memory: &Memory,
) -> Result<OwnedVec<OwnedVec<u8>>, Error> {
    let view = session.view();
    let mut decoded = memory.vector();
    for (signature, _) in signers {
        for key_info in children(session, *signature, "KeyInfo", memory)?.iter() {
            for data in children(session, *key_info, "X509Data", memory)?.iter() {
                for value in children(session, *data, "X509Certificate", memory)?.iter() {
                    let bytes = extension::with_base64(view, *value, memory, |bytes| {
                        let mut copy = memory.vector();
                        copy.try_extend_from_slice(bytes).map(|()| copy)
                    })??;
                    decoded.try_push(bytes)?;
                }
            }
        }
    }
    Ok(decoded)
}

fn children<W: Work>(
    session: &VerifiedSession<'_, '_, '_, W>,
    parent: NodeIdentity,
    local: &str,
    memory: &Memory,
) -> Result<OwnedVec<NodeIdentity>, Error> {
    let view = session.view();
    let mut found = memory.vector();
    let mut next = extension::first_child(view, parent, memory)?;
    while let Some(node) = next {
        let matches = extension::inspect_node(view, node, memory, |value| {
            matches!(
                value,
                NodeView::Element { namespace: Some(namespace), local_name }
                    if namespace == DS && local_name == local
            )
        })?;
        if matches {
            found.try_push(node)?;
        }
        next = extension::next_sibling(view, parent, node, memory)?;
    }
    Ok(found)
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
/// by their recorded SHA-256 identities, and parse each certificate once.
pub(crate) fn select<'d, W: Work>(
    session: &VerifiedSession<'_, '_, '_, W>,
    signers: &[(NodeIdentity, &'d X509TrustEvidence)],
    candidates: &[&'d [u8]],
    parser: &'d Parser,
    memory: &Memory,
) -> Result<Selection<'d>, Error> {
    let mut fingerprints: OwnedVec<Option<OwnedVec<u8>>> = memory.vector();
    for _ in candidates {
        fingerprints.try_push(None)?;
    }
    // Candidate index of each parsed certificate, parallel to `certificates`.
    let mut sources: OwnedVec<usize> = memory.vector();
    let mut certificates = memory.vector();
    let mut selected = memory.vector();
    for (signature, evidence) in signers {
        let mut path = memory.vector();
        let mut missing = false;
        for fingerprint in evidence.certificate_fingerprints() {
            let Some(index) = find(session, candidates, &mut fingerprints, fingerprint, memory)?
            else {
                missing = true;
                break;
            };
            let position = match sources.iter().position(|source| *source == index) {
                Some(position) => position,
                None => {
                    let certificate = Certificate::read(parser, candidates[index], 0)
                        .map_err(X509ChainError::Processing)?;
                    sources.try_push(index)?;
                    certificates.try_push(certificate)?;
                    certificates.len() - 1
                }
            };
            path.try_push(position)?;
        }
        selected.try_push((
            *signature,
            *evidence,
            if missing {
                Err(PathFailure::MissingCertificate)
            } else {
                Ok(path)
            },
        ))?;
    }
    Ok(Selection {
        certificates,
        signers: selected,
    })
}

fn find<W: Work>(
    session: &VerifiedSession<'_, '_, '_, W>,
    candidates: &[&[u8]],
    fingerprints: &mut [Option<OwnedVec<u8>>],
    fingerprint: &[u8; 32],
    memory: &Memory,
) -> Result<Option<usize>, Error> {
    for (index, candidate) in candidates.iter().enumerate() {
        if fingerprints[index].is_none() {
            let digest = session.digest_in(DigestAlgorithm::Sha256, candidate, memory)?;
            fingerprints[index] = Some(digest.into_owned());
        }
        memory.charge_work(32)?;
        if fingerprints[index]
            .as_deref()
            .is_some_and(|candidate| constant_time_eq(candidate, fingerprint))
        {
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
    /// The checked path of `signature`, or why it has none.
    pub(crate) fn get(&self, signature: NodeIdentity) -> Result<&CheckedPath<'d>, PathFailure> {
        match self.entries.iter().find(|(signer, _)| *signer == signature) {
            Some((_, Ok(path))) => Ok(path),
            Some((_, Err(failure))) => Err(*failure),
            None => Err(PathFailure::NotValidated),
        }
    }
}

/// Re-check each selected path with the operation's provider and policy.
pub(crate) fn check<'d, W: Work>(
    session: &VerifiedSession<'_, '_, '_, W>,
    selection: &'d Selection<'d>,
    memory: &Memory,
) -> Result<Paths<'d>, Error> {
    let mut entries = memory.vector();
    for (signature, evidence, path) in selection.signers.iter() {
        let outcome = match path {
            Ok(path) => checked(session, &selection.certificates, evidence, path, memory)?,
            Err(failure) => Err(*failure),
        };
        entries.try_push((*signature, outcome))?;
    }
    Ok(Paths { entries })
}

fn checked<'d, W: Work>(
    session: &VerifiedSession<'_, '_, '_, W>,
    certificates: &'d [Certificate<'d>],
    evidence: &X509TrustEvidence,
    path: &[usize],
    memory: &Memory,
) -> Result<Result<CheckedPath<'d>, PathFailure>, Error> {
    let Some((anchor, members)) = path.split_last() else {
        return Ok(Err(PathFailure::MissingCertificate));
    };
    if members.is_empty() {
        return Ok(Err(PathFailure::AnchorOnly));
    }
    let mut chain = memory.vector();
    for position in members {
        chain.try_push(&certificates[*position])?;
    }
    let anchor = &certificates[*anchor];
    let verifier = session.certificate_path_verifier(&chain, anchor);
    let context = ValidationContext {
        execution: memory,
        interval: Interval::at_instant(evidence.validation_instant()?),
        policy: Policy::default(),
        bounds: ValidationBounds {
            // The exact validated path is re-checked; the operation account,
            // not these mechanism bounds, limits the work.
            depth: chain.len(),
            work: u64::MAX,
            policies: usize::MAX,
        },
        verifier: &verifier,
        watch: &(),
        recognizer: &(),
    };
    match structured_xades::pki::check_path(&chain, Anchor::from_certificate(anchor), &context) {
        Ok(PathOutcome::Accepted(path)) => Ok(Ok(path)),
        Ok(PathOutcome::Rejected(_)) => Ok(Err(PathFailure::Rejected)),
        Ok(PathOutcome::Incomplete(reason)) => Ok(Err(PathFailure::Incomplete(reason))),
        Err(BuildError::Processing(error)) => Err(X509ChainError::Processing(error).into()),
        Err(BuildError::Verification(error)) => Err(error.into()),
        Err(BuildError::Recognition(never)) => match never {},
    }
}
