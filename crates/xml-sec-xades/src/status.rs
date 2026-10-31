//! Original CRL and OCSP evidence bound to every member of every actor path.
//!
//! Each stage borrows only the frozen stages before it: authenticated sources,
//! then one selected status per path member (which may require further
//! authority paths), then the receipts binding those selections to the paths.

use crate::Error;
use crate::path::{self, Authorities, PathFailure};
use structured_asn1::memory::{Memory, OwnedVec, Work};
use structured_ltv::pki::{
    AuthorityNode, CheckedPath, CrlAuthorities, CrlAuthority, CrlBindingError, CrlBindingFailure,
    CrlCoverage, CrlCoverageBinding, CrlCoverageError, CrlReading, CrlReadingBinding,
    CrlReadingTarget, MemberStatus, OcspBinding, OcspBindingError, OcspBindingFailure, OcspTarget,
    PathStatuses, ResponderBinding, ResponderError, ResponderFailure, ResponderPath,
    StatusCensusError,
};
use structured_pkix::Certificate;
use structured_pkix::crl::{
    Authenticated, Authentication, CertificateList, CombinedEntry, CompleteEvidence, CompleteFacts,
    Coverage, CoverageAdmission, DeltaBinding, DeltaEvidence, DeltaFacts, EntryLookup, Evaluation,
    SourceOrigin,
};
use structured_pkix::error::CallbackError;
use structured_pkix::ocsp::{
    self, AuthorityBinding, BasicResponse, BoundEvidence, Delegation, Request, ResponderRevocation,
    SignatureAuthentication, SignatureError, SignedResponse, check_delegate,
};
use structured_pkix::path::{Anchor, BuildError, Interval, Policy, ValidationContext, WorkingKey};
use structured_pkix::temporal::{Instant, LeapTable, Reading};
use xml_sec::xmldsig::VerifiedSession;
use xml_sec::xmldsig::X509ChainError;
use xml_sec::xmldsig::cms::{CmsProvider, CmsProviderError};

/// A status source that could not be processed, with its original cause.
#[derive(Debug, thiserror::Error)]
pub enum StatusError {
    /// Shared CRL or OCSP processing failed.
    #[error(transparent)]
    Pkix(#[from] structured_pkix::Error),
    /// A signature could not be checked.
    #[error(transparent)]
    Verification(#[from] X509ChainError),
    /// An OCSP identity hash could not be computed.
    #[error(transparent)]
    Digest(#[from] CmsProviderError),
    /// Adapter or resource failure.
    #[error(transparent)]
    Adapter(#[from] Error),
    /// A CRL could not be associated with its path member.
    #[error("CRL binding failed: {0:?}")]
    CrlBinding(CrlBindingError),
    /// A CRL's contributors could not be associated with their path member.
    #[error("CRL coverage binding failed: {0:?}")]
    CrlCoverage(CrlCoverageError),
    /// An OCSP response could not be associated with its path member.
    #[error("OCSP binding failed: {0:?}")]
    OcspBinding(OcspBindingError),
    /// A delegated responder could not be associated with its full path.
    #[error("OCSP responder binding failed: {0:?}")]
    Responder(ResponderError),
    /// A path's status inputs are not its complete census.
    #[error("status census failed: {0:?}")]
    Census(StatusCensusError),
}

/// Why a path member has no usable status input. None of these says that the
/// certificate is revoked: a revoked or stale status is a retained fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusFailure {
    /// No supplied CRL or OCSP response speaks about this certificate.
    NoSource,
    /// The authority of an applicable source has no accepted path.
    AuthorityPath(PathFailure),
    /// A CRL does not belong to the path member it was selected for.
    Crl(CrlBindingFailure),
    /// An OCSP response does not belong to the path member it was selected for.
    Ocsp(OcspBindingFailure),
    /// A delegated responder does not belong to the full path it was given.
    Responder(ResponderFailure),
}

/// Who signed a selected list.
#[derive(Clone, Copy)]
enum Signer {
    /// The target path's own anchor.
    Anchor,
    /// The path at this ordinal.
    Path(usize),
}

/// The signers of one contributor to a CRL coverage.
#[derive(Clone, Copy)]
enum CrlAuthoritySource {
    Complete(Signer),
    Delta(Signer, Signer),
}

/// A selection that could not be established, or the selection and whether a
/// delegated responder is exempt from its own status.
type Selection<'f, 'x> = Option<Result<(Selected<'f, 'x>, bool), PathFailure>>;

/// One member's selected status, independent of any path receipt.
#[expect(
    clippy::large_enum_variant,
    reason = "retained by value in one frozen accounted plan rather than boxed per member"
)]
enum Selected<'f, 'x> {
    Ocsp {
        evidence: BoundEvidence<'x, 'x, 'x, 'x>,
        /// The delegated responder's full path, for a response it signed.
        responder: Option<usize>,
    },
    Absent {
        coverage: Coverage<'x, 'x>,
        /// The range of this coverage's source signers in the shared list.
        signers: (usize, usize),
    },
    Complete {
        facts: CompleteFacts<'f, 'x, 'x>,
        signer: Signer,
    },
    Delta {
        facts: DeltaFacts<'f, 'x, 'x>,
        base: Signer,
        delta: Signer,
    },
    /// The final member of a responder path whose response carries noCheck.
    NoCheck {
        /// The plan of the response that responder signed.
        plan: usize,
    },
}

struct Plan<'f, 'x> {
    path: usize,
    member: usize,
    selected: Selected<'f, 'x>,
}

struct Engine<'e, 'x, 'v, 's, 'i, W: Work> {
    session: &'e VerifiedSession<'v, 's, 'i, W>,
    cms: &'e CmsProvider<'e>,
    authorities: &'e Authorities<'x>,
    lists: &'e [Authenticated<'x, 'x>],
    deltas: &'e [Authenticated<'x, 'x>],
    responses: &'e [SignedResponse<'x, 'x>],
    utc: &'x LeapTable<'x>,
    at: Instant,
}

/// Every supplied list its issuer's own key authenticates. Lists no available
/// certificate authenticates stay unused: nothing here may rely on them.
fn authenticated_lists<'x, W: Work>(
    session: &VerifiedSession<'_, '_, '_, W>,
    authorities: &Authorities<'x>,
    lists: &[&'x CertificateList<'x>],
) -> Result<
    (
        OwnedVec<Authenticated<'x, 'x>>,
        OwnedVec<Authenticated<'x, 'x>>,
    ),
    StatusError,
> {
    let memory = authorities.memory;
    let verifier = session.revocation_verifier();
    let (mut complete, mut delta) = (memory.vector(), memory.vector());
    for list in lists {
        for candidate in authorities
            .anchors
            .iter()
            .chain(authorities.pool.iter().copied())
        {
            if !list
                .tbs()
                .issuer()
                .matches(candidate.tbs().subject(), memory)?
            {
                continue;
            }
            let key = WorkingKey::standing(candidate.tbs().public_key());
            let answer = list
                .authenticate(candidate, key, &verifier, memory)
                .map_err(|error| match error {
                    CallbackError::Processing(error) => StatusError::Pkix(error),
                    CallbackError::Callback(error) => StatusError::Verification(error),
                })?;
            let Authentication::Authenticated(proof) = answer else {
                continue;
            };
            let is_delta = list
                .tbs()
                .extensions()
                .get(structured_pkix::oid::DELTA_CRL_INDICATOR, memory)?
                .is_some();
            if is_delta {
                delta.try_push(proof).map_err(Error::from)?;
            } else {
                complete.try_push(proof).map_err(Error::from)?;
            }
            break;
        }
    }
    Ok((complete.into_owned(), delta.into_owned()))
}

/// Every supplied response with the certificate whose key signed it.
/// RFC 6960 §4.2.2.2 authorization is a separate per-target decision.
fn signed_responses<'x, W: Work>(
    session: &VerifiedSession<'_, '_, '_, W>,
    cms: &CmsProvider<'_>,
    authorities: &Authorities<'x>,
    responses: &[&'x BasicResponse<'x>],
) -> Result<OwnedVec<SignedResponse<'x, 'x>>, StatusError> {
    let memory = authorities.memory;
    let verifier = session.revocation_verifier();
    let mut signed = memory.vector();
    for response in responses {
        for candidate in response
            .certificates()
            .iter()
            .chain(authorities.pool.iter().copied())
        {
            let key = WorkingKey::standing(candidate.tbs().public_key());
            let answer = response
                .authenticate_signature(candidate, key, &verifier, cms, memory)
                .map_err(|error| match error {
                    SignatureError::Processing(error) => StatusError::Pkix(error),
                    SignatureError::Verification(error) => StatusError::Verification(error),
                    SignatureError::Digest(error) => StatusError::Digest(error),
                })?;
            if let SignatureAuthentication::Signed(value) = answer {
                signed.try_push(value).map_err(Error::from)?;
                break;
            }
        }
    }
    Ok(signed.into_owned())
}

impl<'e, 'x, W: Work> Engine<'e, 'x, '_, '_, '_, W> {
    fn evaluation(&self) -> Evaluation<'_, structured_asn1::memory::Memory> {
        Evaluation {
            now: Reading::from(self.at),
            utc: self.utc,
            execution: self.authorities.memory,
            // Material incorporated in a document is held, not newly fetched
            // (RFC 5280 §6.3.3(a)).
            // https://www.rfc-editor.org/rfc/rfc5280#section-6.3.3
            origin: SourceOrigin::Cached,
        }
    }

    /// The ordinal of the accepted path to `target` at the evaluation instant,
    /// reusing a path already built for it.
    fn authority_path(
        &self,
        target: &'x Certificate<'x>,
        roots: usize,
        extra: &mut OwnedVec<CheckedPath<'x>, structured_asn1::memory::Memory>,
    ) -> Result<Result<usize, PathFailure>, StatusError> {
        for (index, path) in extra.iter().enumerate() {
            let member = path.members().last().expect("a checked path has a target");
            if member.certificate().as_bytes() == target.as_bytes() {
                return Ok(Ok(roots + index));
            }
        }
        let interval = Interval::at_instant(self.at);
        match path::discover(self.session, self.authorities, target, interval)? {
            Ok(path) => {
                extra.try_push(path).map_err(Error::from)?;
                Ok(Ok(roots + extra.len() - 1))
            }
            Err(failure) => Ok(Err(failure)),
        }
    }

    fn signer(
        &self,
        anchor: Anchor<'x>,
        issuer: &'x Certificate<'x>,
        roots: usize,
        extra: &mut OwnedVec<CheckedPath<'x>, structured_asn1::memory::Memory>,
    ) -> Result<Result<Signer, PathFailure>, StatusError> {
        if anchor
            .certificate()
            .is_some_and(|certificate| certificate.as_bytes() == issuer.as_bytes())
        {
            return Ok(Ok(Signer::Anchor));
        }
        Ok(self.authority_path(issuer, roots, extra)?.map(Signer::Path))
    }

    /// Whether an authenticated complete list, or a delta bound to one, names
    /// `target`.
    fn listed(&self, target: &'x Certificate<'x>) -> Result<bool, StatusError> {
        let memory = self.authorities.memory;
        let time = self.evaluation();
        for list in self.lists {
            let CompleteEvidence::Facts(facts) = list.evaluate(target, &time)? else {
                continue;
            };
            if !matches!(facts.entry(), EntryLookup::Absent) {
                return Ok(true);
            }
            for delta in self.deltas {
                let DeltaBinding::Bound(pair) = list.bind_delta(delta, memory)? else {
                    continue;
                };
                if let DeltaEvidence::Facts(facts) = pair.evaluate(target, &time)?
                    && !matches!(
                        facts.entry(),
                        CombinedEntry::Absent | CombinedEntry::Removed { .. }
                    )
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// An OCSP response for `target` its issuer, a delegate of that issuer or a
    /// responder the caller configured for it signed. Configured trust is never
    /// inferred from a document.
    fn ocsp(
        &self,
        target: &'x Certificate<'x>,
        issuer: &'x Certificate<'x>,
        issuing: WorkingKey<'x>,
        roots: usize,
        extra: &mut OwnedVec<CheckedPath<'x>, structured_asn1::memory::Memory>,
    ) -> Result<Selection<'e, 'x>, StatusError> {
        let memory = self.authorities.memory;
        for signed in self.responses {
            let delegated = signed.signer().as_bytes() != issuer.as_bytes();
            let configured = delegated
                && self.authorities.responders.iter().any(|entry| {
                    entry.responder == signed.signer().as_bytes()
                        && entry.issuer == issuer.as_bytes()
                });
            let (binding, no_check) = if configured {
                // RFC 6960 §4.2.2.2: local configuration, the branch that needs
                // neither a delegation certificate nor the responder's own path.
                (
                    AuthorityBinding::Bound(signed.trust_for_issuer(issuer)),
                    false,
                )
            } else if delegated {
                let chain = [signed.signer()];
                let verifier = self.session.certificate_path_verifier(&chain, issuer);
                let context = ValidationContext {
                    execution: memory,
                    interval: Interval::at_instant(self.at),
                    policy: Policy::default(),
                    bounds: self.session.certificate_path_bounds(),
                    verifier: &verifier,
                    watch: &(),
                    recognizer: &(),
                };
                let delegation = match check_delegate(signed.signer(), issuer, issuing, &context) {
                    Ok(delegation) => delegation,
                    Err(BuildError::Processing(error)) => return Err(error.into()),
                    Err(BuildError::Verification(error)) => return Err(error.into()),
                    Err(BuildError::Recognition(never)) => match never {},
                };
                let Delegation::Accepted(facts) = delegation else {
                    continue;
                };
                let no_check = facts.revocation() == ResponderRevocation::NoCheck;
                (signed.bind_delegate(facts, memory)?, no_check)
            } else {
                (signed.bind_issuer(issuer, issuing, memory)?, false)
            };
            let AuthorityBinding::Bound(scoped) = binding else {
                continue;
            };
            let request = Request {
                target,
                nonce: None,
                intended_signer: None,
            };
            let time = ocsp::Evaluation {
                now: Reading::from(self.at),
                utc: self.utc,
                execution: memory,
            };
            let reading = scoped
                .evaluate_with_target(&request, &time, self.cms)
                .map_err(|error| match error {
                    CallbackError::Processing(error) => StatusError::Pkix(error),
                    CallbackError::Callback(error) => StatusError::Digest(error),
                })?;
            let Some(evidence) = reading.evidence() else {
                continue;
            };
            let responder = if delegated && !configured {
                match self.authority_path(signed.signer(), roots, extra)? {
                    Ok(path) => Some(path),
                    Err(failure) => return Ok(Some(Err(failure))),
                }
            } else {
                None
            };
            return Ok(Some(Ok((
                Selected::Ocsp {
                    evidence,
                    responder,
                },
                no_check,
            ))));
        }
        Ok(None)
    }

    /// The CRL evidence for `target`, combining every applicable complete list
    /// with its newest bound delta (RFC 5280 §6.3.3).
    fn crl(
        &self,
        anchor: Anchor<'x>,
        target: &'x Certificate<'x>,
        roots: usize,
        extra: &mut OwnedVec<CheckedPath<'x>, structured_asn1::memory::Memory>,
        signers: &mut OwnedVec<CrlAuthoritySource, structured_asn1::memory::Memory>,
    ) -> Result<Option<Result<Selected<'e, 'x>, PathFailure>>, StatusError> {
        let memory = self.authorities.memory;
        let time = self.evaluation();
        let first = signers.len();
        let mut coverage: Option<Coverage<'x, 'x>> = None;
        let mut negative = None;
        for list in self.lists {
            let CompleteEvidence::Facts(facts) = list.evaluate(target, &time)? else {
                continue;
            };
            let signer = match self.signer(anchor, list.issuer(), roots, extra)? {
                Ok(signer) => signer,
                Err(failure) => return Ok(Some(Err(failure))),
            };
            let mut newest = None;
            for delta in self.deltas {
                let DeltaBinding::Bound(pair) = list.bind_delta(delta, memory)? else {
                    continue;
                };
                let newer = match newest {
                    None => true,
                    Some(current) => pair.compare_delta_number(current, memory)?.is_gt(),
                };
                if newer {
                    newest = Some(pair);
                }
            }
            let (absence, source) = if let Some(pair) = newest {
                let DeltaEvidence::Facts(facts) = pair.evaluate(target, &time)? else {
                    continue;
                };
                let absence = facts.absence();
                if absence.is_none() {
                    let listed = !matches!(
                        facts.entry(),
                        CombinedEntry::Absent | CombinedEntry::Removed { .. }
                    );
                    let selected = Selected::Delta {
                        base: signer,
                        delta: signer,
                        facts,
                    };
                    if listed {
                        return Ok(Some(Ok(selected)));
                    }
                    negative = Some(selected);
                }
                (absence, CrlAuthoritySource::Delta(signer, signer))
            } else {
                let absence = facts.absence();
                if absence.is_none() {
                    // A listed entry decides whatever another list omits
                    // (RFC 5280 §6.3.3(i)); a stale list decides nothing
                    // while a current one covers the target.
                    // https://www.rfc-editor.org/rfc/rfc5280#section-6.3.3
                    let selected = Selected::Complete { facts, signer };
                    if !matches!(facts.entry(), EntryLookup::Absent) {
                        return Ok(Some(Ok(selected)));
                    }
                    negative = Some(selected);
                }
                (absence, CrlAuthoritySource::Complete(signer))
            };
            let Some(absence) = absence else {
                continue;
            };
            let added = if let Some(value) = &mut coverage {
                value.add(absence, memory)? == CoverageAdmission::Added
            } else {
                coverage = Some(Coverage::new(absence, memory)?);
                true
            };
            if added {
                signers.try_push(source).map_err(Error::from)?;
            }
        }
        Ok(match coverage {
            Some(coverage) => Some(Ok(Selected::Absent {
                signers: (first, signers.len()),
                coverage,
            })),
            None => negative.map(Ok),
        })
    }
}

/// The path at `cursor` of the roots followed by the reached authorities.
fn path_at<'p, 'x>(
    roots: &'p [&'x CheckedPath<'x>],
    extra: &'p [CheckedPath<'x>],
    cursor: usize,
) -> &'p CheckedPath<'x> {
    match roots.get(cursor) {
        Some(path) => path,
        None => &extra[cursor - roots.len()],
    }
}

/// Select and bind status for each of `roots`' members and every authority they
/// reach, then hand `then` the census of each root and all authority nodes.
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is one frozen pool of this operation"
)]
pub(crate) fn with_statuses<'x, W: Work, R>(
    session: &VerifiedSession<'_, '_, '_, W>,
    cms: &CmsProvider<'_>,
    authorities: &'x Authorities<'x>,
    lists: &[&'x CertificateList<'x>],
    responses: &[&'x BasicResponse<'x>],
    roots: &'x [&'x CheckedPath<'x>],
    utc: &'x LeapTable<'x>,
    at: Instant,
    then: impl for<'v> FnOnce(&'v [&'v PathStatuses<'v, 'x, 'x>], &'v [AuthorityNode<'v, 'x, 'x>]) -> R,
) -> Result<Result<R, StatusFailure>, StatusError> {
    let memory = authorities.memory;
    let (complete, deltas) = authenticated_lists(session, authorities, lists)?;
    let signed = signed_responses(session, cms, authorities, responses)?;
    let engine = Engine {
        session,
        cms,
        authorities,
        lists: &complete,
        deltas: &deltas,
        responses: &signed,
        utc,
        at,
    };
    let mut extra = memory.vector();
    let mut signers = memory.vector();
    let mut plans: OwnedVec<Plan<'_, 'x>, _> = memory.vector();
    // Responder paths and the plan of the response each one signed.
    let mut exempt: OwnedVec<(usize, usize), _> = memory.vector();
    let mut cursor = 0;
    // Selection may append to `extra`, so each member is read through the index.
    while cursor < roots.len() + extra.len() {
        let (anchor, count) = {
            let path = path_at(roots, &extra, cursor);
            (path.anchor(), path.members().len())
        };
        for index in 0..count {
            let target = path_at(roots, &extra, cursor).members()[index].certificate();
            if index + 1 == count
                && let Some((_, plan)) = exempt.iter().find(|(path, _)| *path == cursor)
            {
                plans
                    .try_push(Plan {
                        path: cursor,
                        member: index,
                        selected: Selected::NoCheck { plan: *plan },
                    })
                    .map_err(Error::from)?;
                continue;
            }
            let (issuer, issuing) = if let Some(index) = index.checked_sub(1) {
                let member = &path_at(roots, &extra, cursor).members()[index];
                (Some(member.certificate()), member.key())
            } else {
                (anchor.certificate(), WorkingKey::standing(anchor.key()))
            };
            // A listed entry decides whatever another source omits (RFC 5280
            // §6.3.3(i)), so a good OCSP answer cannot hide it from the report.
            let ocsp = match issuer {
                Some(issuer) if !engine.listed(target)? => {
                    engine.ocsp(target, issuer, issuing, roots.len(), &mut extra)?
                }
                _ => None,
            };
            let selected = match ocsp {
                Some(Ok((selected, no_check))) => {
                    if no_check
                        && let Selected::Ocsp {
                            responder: Some(path),
                            ..
                        } = selected
                    {
                        exempt.try_push((path, plans.len())).map_err(Error::from)?;
                    }
                    selected
                }
                Some(Err(failure)) => return Ok(Err(StatusFailure::AuthorityPath(failure))),
                None => match engine.crl(anchor, target, roots.len(), &mut extra, &mut signers)? {
                    Some(Ok(selected)) => selected,
                    Some(Err(failure)) => return Ok(Err(StatusFailure::AuthorityPath(failure))),
                    None => return Ok(Err(StatusFailure::NoSource)),
                },
            };
            plans
                .try_push(Plan {
                    path: cursor,
                    member: index,
                    selected,
                })
                .map_err(Error::from)?;
        }
        cursor += 1;
    }
    let mut every: OwnedVec<&CheckedPath<'x>, _> = memory.vector();
    every
        .try_reserve_exact(roots.len() + extra.len())
        .map_err(Error::from)?;
    every.try_extend_from_slice(roots).map_err(Error::from)?;
    for path in &extra {
        every.try_push(path).map_err(Error::from)?;
    }
    let frozen = Frozen {
        memory,
        every: &every,
        roots: roots.len(),
        plans: &plans,
        utc,
        at,
    };
    bind_authorities(&frozen, &signers, then)
}

/// The selections and the paths they may name, frozen for every receipt.
struct Frozen<'b, 'x> {
    memory: &'b Memory,
    every: &'b [&'b CheckedPath<'x>],
    roots: usize,
    plans: &'b [Plan<'b, 'x>],
    utc: &'b LeapTable<'x>,
    at: Instant,
}

/// Each CRL source's checked signer, ahead of the receipts that borrow them.
fn bind_authorities<'b, 'x, R>(
    frozen: &Frozen<'b, 'x>,
    signers: &[CrlAuthoritySource],
    then: impl for<'v> FnOnce(&'v [&'v PathStatuses<'v, 'x, 'x>], &'v [AuthorityNode<'v, 'x, 'x>]) -> R,
) -> Result<Result<R, StatusFailure>, StatusError> {
    let Frozen {
        memory,
        every,
        plans,
        ..
    } = *frozen;
    let resolve = |signer: Signer| -> CrlAuthority<'_, 'x> {
        match signer {
            Signer::Anchor => CrlAuthority::Anchor,
            Signer::Path(path) => CrlAuthority::Path(every[path]),
        }
    };
    let mut authorities = memory.vector();
    let mut delta_authorities = memory.vector();
    for plan in plans {
        match &plan.selected {
            Selected::Absent {
                signers: (first, last),
                ..
            } => {
                for source in &signers[*first..*last] {
                    authorities
                        .try_push(match *source {
                            CrlAuthoritySource::Complete(signer) => {
                                CrlAuthorities::Complete(resolve(signer))
                            }
                            CrlAuthoritySource::Delta(base, delta) => CrlAuthorities::Delta {
                                base: resolve(base),
                                delta: resolve(delta),
                            },
                        })
                        .map_err(Error::from)?;
                }
            }
            Selected::Complete { signer, .. } => {
                delta_authorities
                    .try_push(CrlAuthorities::Complete(resolve(*signer)))
                    .map_err(Error::from)?;
            }
            Selected::Delta { base, delta, .. } => {
                delta_authorities
                    .try_push(CrlAuthorities::Delta {
                        base: resolve(*base),
                        delta: resolve(*delta),
                    })
                    .map_err(Error::from)?;
            }
            Selected::Ocsp { .. } | Selected::NoCheck { .. } => {}
        }
    }
    bind_sources(frozen, &authorities, &delta_authorities, then)
}

/// A receipt for every selected source, or the mismatch that refuses one.
fn bind_sources<'b, 'x, R>(
    frozen: &Frozen<'b, 'x>,
    authorities: &[CrlAuthorities<'_, 'x>],
    delta_authorities: &[CrlAuthorities<'_, 'x>],
    then: impl for<'v> FnOnce(&'v [&'v PathStatuses<'v, 'x, 'x>], &'v [AuthorityNode<'v, 'x, 'x>]) -> R,
) -> Result<Result<R, StatusFailure>, StatusError> {
    let Frozen {
        memory,
        every,
        plans,
        utc,
        ..
    } = *frozen;
    let (mut coverages, mut readings, mut targets) =
        (memory.vector(), memory.vector(), memory.vector());
    let (mut authority, mut negative) = (0, 0);
    for plan in plans {
        let path = every[plan.path];
        match &plan.selected {
            Selected::Absent {
                coverage,
                signers: (first, last),
            } => {
                let count = last - first;
                let used = &authorities[authority..authority + count];
                authority += count;
                match path
                    .bind_crl_coverage(plan.member, coverage, used, utc, memory)
                    .map_err(StatusError::CrlCoverage)?
                {
                    CrlCoverageBinding::Bound(value) => {
                        coverages.try_push(value).map_err(Error::from)?;
                    }
                    CrlCoverageBinding::Rejected { cause, .. } => {
                        return Ok(Err(StatusFailure::Crl(cause)));
                    }
                }
            }
            Selected::Complete { facts, .. } => {
                let used = delta_authorities[negative];
                negative += 1;
                match path
                    .bind_crl_reading(plan.member, CrlReading::Complete(facts), used, utc, memory)
                    .map_err(StatusError::CrlBinding)?
                {
                    CrlReadingBinding::Bound(value) => {
                        readings.try_push(value).map_err(Error::from)?;
                    }
                    CrlReadingBinding::Rejected(cause) => {
                        return Ok(Err(StatusFailure::Crl(cause)));
                    }
                }
            }
            Selected::Delta { facts, .. } => {
                let used = delta_authorities[negative];
                negative += 1;
                match path
                    .bind_crl_reading(plan.member, CrlReading::Delta(facts), used, utc, memory)
                    .map_err(StatusError::CrlBinding)?
                {
                    CrlReadingBinding::Bound(value) => {
                        readings.try_push(value).map_err(Error::from)?;
                    }
                    CrlReadingBinding::Rejected(cause) => {
                        return Ok(Err(StatusFailure::Crl(cause)));
                    }
                }
            }
            Selected::Ocsp { evidence, .. } => {
                match path
                    .bind_ocsp(plan.member, evidence, memory)
                    .map_err(StatusError::OcspBinding)?
                {
                    OcspBinding::Bound(value) => targets.try_push(value).map_err(Error::from)?,
                    OcspBinding::Rejected(cause) => {
                        return Ok(Err(StatusFailure::Ocsp(cause)));
                    }
                }
            }
            Selected::NoCheck { .. } => {}
        }
    }
    bind_responders(frozen, &coverages, &readings, &targets, then)
}

/// A full-path receipt for every delegated responder.
fn bind_responders<'x, R>(
    frozen: &Frozen<'_, 'x>,
    coverages: &[CrlCoverage<'_, 'x, 'x>],
    readings: &[CrlReadingTarget<'_, 'x, 'x>],
    targets: &[OcspTarget<'_, 'x, 'x>],
    then: impl for<'v> FnOnce(&'v [&'v PathStatuses<'v, 'x, 'x>], &'v [AuthorityNode<'v, 'x, 'x>]) -> R,
) -> Result<Result<R, StatusFailure>, StatusError> {
    let Frozen {
        memory,
        every,
        plans,
        utc,
        ..
    } = *frozen;
    let mut responders = memory.vector();
    let mut target = 0;
    let mut response_targets: OwnedVec<Option<usize>, _> = memory.vector();
    for plan in plans {
        let mut ordinal = None;
        if let Selected::Ocsp { responder, .. } = &plan.selected {
            let bound: &OcspTarget<'_, 'x, 'x> = &targets[target];
            target += 1;
            if let Some(responder) = responder {
                match bound
                    .bind_responder_path(every[*responder], utc, memory)
                    .map_err(StatusError::Responder)?
                {
                    ResponderBinding::Bound(value) => {
                        ordinal = Some(responders.len());
                        responders.try_push(value).map_err(Error::from)?;
                    }
                    ResponderBinding::Rejected(cause) => {
                        return Ok(Err(StatusFailure::Responder(cause)));
                    }
                }
            }
        }
        response_targets.try_push(ordinal).map_err(Error::from)?;
    }
    let sources = Sources {
        coverages,
        readings,
        targets,
        responders: &responders,
        response_targets: &response_targets,
    };
    conclude(frozen, &sources, then)
}

/// Every receipt of one operation, in plan order per kind.
struct Sources<'b, 'v, 'x> {
    coverages: &'b [CrlCoverage<'v, 'x, 'x>],
    readings: &'b [CrlReadingTarget<'v, 'x, 'x>],
    targets: &'b [OcspTarget<'v, 'x, 'x>],
    responders: &'b [ResponderPath<'b, 'v, 'x, 'x>],
    response_targets: &'b [Option<usize>],
}

/// One status input per plan, in plan order.
fn member_statuses<'b, 'x>(
    plans: &[Plan<'_, 'x>],
    sources: &Sources<'b, 'b, 'x>,
    memory: &Memory,
) -> Result<OwnedVec<MemberStatus<'b, 'x, 'x>>, Error> {
    let (mut coverage, mut reading, mut target) = (0, 0, 0);
    let mut entries = memory.vector();
    for plan in plans {
        entries.try_push(match &plan.selected {
            Selected::Absent { .. } => {
                coverage += 1;
                MemberStatus::Crl(&sources.coverages[coverage - 1])
            }
            Selected::Complete { .. } | Selected::Delta { .. } => {
                reading += 1;
                MemberStatus::CrlReading(&sources.readings[reading - 1])
            }
            Selected::Ocsp { .. } => {
                target += 1;
                MemberStatus::Ocsp(&sources.targets[target - 1])
            }
            Selected::NoCheck { plan } => {
                let ordinal =
                    sources.response_targets[*plan].expect("a noCheck plan names its response");
                MemberStatus::ResponderNoCheck(&sources.responders[ordinal])
            }
        })?;
    }
    Ok(entries.into_owned())
}

/// Each path's census and its authority node.
fn conclude<'x, R>(
    frozen: &Frozen<'_, 'x>,
    sources: &Sources<'_, '_, 'x>,
    then: impl for<'v> FnOnce(&'v [&'v PathStatuses<'v, 'x, 'x>], &'v [AuthorityNode<'v, 'x, 'x>]) -> R,
) -> Result<Result<R, StatusFailure>, StatusError> {
    let Frozen {
        memory,
        every,
        roots,
        plans,
        at,
        ..
    } = *frozen;
    let responders = sources.responders;
    let entries = member_statuses(plans, sources, memory)?;
    let reading_at = Reading::from(at);
    let mut statuses = memory.vector();
    statuses
        .try_reserve_exact(every.len())
        .map_err(Error::from)?;
    let mut first = 0;
    for (ordinal, path) in every.iter().enumerate() {
        let count = plans[first..]
            .iter()
            .take_while(|plan| plan.path == ordinal)
            .count();
        statuses
            .try_push(
                path.status_census(reading_at, &entries[first..first + count], memory)
                    .map_err(StatusError::Census)?,
            )
            .map_err(Error::from)?;
        first += count;
    }
    let mut references = memory.vector();
    for plan in plans {
        if let Selected::Ocsp {
            responder: Some(_), ..
        } = plan.selected
        {
            references.try_push(plan.path).map_err(Error::from)?;
        }
    }
    let mut delegated = memory.vector();
    delegated
        .try_reserve_exact(responders.len())
        .map_err(Error::from)?;
    for responder in responders {
        delegated.try_push(responder).map_err(Error::from)?;
    }
    let mut nodes = memory.vector();
    nodes
        .try_reserve_exact(statuses.len())
        .map_err(Error::from)?;
    let mut cursor = 0;
    for (ordinal, statuses) in statuses.iter().enumerate() {
        let count = references[cursor..]
            .iter()
            .take_while(|path| **path == ordinal)
            .count();
        nodes
            .try_push(AuthorityNode {
                statuses,
                responders: &delegated[cursor..cursor + count],
            })
            .map_err(Error::from)?;
        cursor += count;
    }
    let mut root_statuses = memory.vector();
    root_statuses
        .try_reserve_exact(roots)
        .map_err(Error::from)?;
    for status in statuses.iter().take(roots) {
        root_statuses.try_push(status).map_err(Error::from)?;
    }
    Ok(Ok(then(&root_statuses, &nodes)))
}
