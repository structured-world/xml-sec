//! ETSI TS 101 903 augmentation beyond T: the complete validation data
//! references of `XAdES-C` and the X and archive timestamps over them.

use super::{
    AugmentError, Completion, Gate, PendingTimestamp, Publication, Repeat, Staging, StagingError,
    Stamp, TimestampRequest, construction, gated, pooled, publish, selected, signed_method,
    unproven, with_algorithm, with_response_check,
};
use crate::basic::{Outcome, Stage, Vocabulary};
use crate::create::Assessment;
use crate::draft::Draft;
use crate::level::{Census, ExtendedLevel, Inputs, Level, Visit, unrecognized, validate_with};
use crate::placement::{self, Unsigned};
use crate::signature::hash_class;
use alloc::{boxed::Box, string::String, vec::Vec};
use core::convert::Infallible;
use structured_asn1::digest::Resolution;
use structured_asn1::memory::{OwnedVec, Work};
use structured_ltv::material::{ArtifactRef, artifact_uses};
use structured_ltv::pki::ParticipantClosure;
use structured_ltv::pki::authority_uses;
use structured_pkix::ocsp::{BasicResponse, ResponseBytes};
use structured_xades::Xades;
use structured_xades::produce::{
    ContentRequest, ExtendedAugmentation, ReferenceArtifact, ReferenceError, ReferenceRole,
    References,
};
pub use structured_xades::timestamp::{ExtendedKind, ReferenceSyntax};
use structured_xades::unsigned::Requirements;
use structured_xades::xml::{Access, Xml};
use xml_sec::IdAttributeRegistration;
use xml_sec::document::{NodeIdentity, XmlDocument};
use xml_sec::xmldsig::DigestAlgorithm;
use xml_sec::xmldsig::with_verified_request;

/// The complete references to add to one signature.
pub struct CompleteReferences<'a, 'inputs> {
    /// ID of the `Signature` to extend.
    pub signature: &'a str,
    /// The TS 101 903 names (`CompleteCertificateRefs`) or the EN 319 132
    /// ones (`CompleteCertificateRefsV2`).
    pub syntax: ReferenceSyntax,
    /// Digest of every reference; the operation's digest policy must allow it.
    pub digest: DigestAlgorithm,
    /// The verification that assesses the document before and after the
    /// references are added.
    pub assessment: &'a Assessment<'a, 'inputs>,
    /// The caller's anchors, certificates, CRLs and OCSP responses the
    /// signer's path and statuses are established from; the new generation
    /// must meet `requirements`, B-T or above.
    pub inputs: &'a Inputs<'a>,
    /// ID attributes beyond the standard spellings.
    pub id_attributes: &'a [IdAttributeRegistration],
}

/// Add to `request.signature` a `CompleteCertificateRefs` (or `…V2`) of every
/// CA certificate of its signer's path and a `CompleteRevocationRefs` of every
/// CRL and OCSP response that path's statuses come from (ETSI TS 101 903
/// V1.4.2 §§7.4.1 and 7.4.2), as one new generation.
///
/// The signer's path and statuses are the ones the B-LT census of the
/// signature establishes from `request.inputs`; the values themselves are not
/// added. The new generation is published only if it meets
/// `request.inputs.requirements`.
///
/// # Errors
/// Returns the original cause and leaves the document unchanged:
/// [`AugmentError::BelowTimestamped`] for a request below B-T and
/// [`AugmentError::Unmet`] when a path or a status cannot be established.
///
/// # Examples
///
/// ```no_run
/// use xml_sec::xmldsig::DigestAlgorithm;
/// use xml_sec_xades::{
///     Assessment, CompleteReferences, Inputs, ReferenceSyntax, add_complete_references,
/// };
/// # fn extend(
/// #     document: &mut xml_sec::XmlDocument,
/// #     assessment: &Assessment<'_, '_>,
/// #     inputs: &Inputs<'_>,
/// #     work: &structured_asn1::memory::Memory,
/// # ) -> Result<(), xml_sec_xades::AugmentError> {
/// add_complete_references(
///     document,
///     &CompleteReferences {
///         signature: "sig",
///         syntax: ReferenceSyntax::Original,
///         digest: DigestAlgorithm::Sha256,
///         assessment,
///         inputs,
///         id_attributes: &[],
///     },
///     work,
/// )
/// # }
/// ```
pub fn add_complete_references<W: Work>(
    document: &mut XmlDocument,
    request: &CompleteReferences<'_, '_>,
    work: &W,
) -> Result<(), AugmentError> {
    let requirements = request.inputs.requirements;
    if requirements == Requirements::Basic {
        return Err(AugmentError::BelowTimestamped(requirements));
    }
    let assessment = request.assessment;
    let unsigned = document.with_view(|view| {
        placement::locate(view, request.signature, request.id_attributes, work)
            .map(|located| located.unsigned)
    })?;
    let certificates = pooled(request.inputs, assessment, work)?;
    let inputs = Inputs {
        certificates: &certificates,
        ..*request.inputs
    };
    // The B-LT census establishes the signer's path and statuses; the
    // document need not carry their values.
    let census = Inputs {
        requirements: Requirements::LongTerm,
        ..inputs
    };
    let vocabulary = match request.syntax {
        ReferenceSyntax::V2 => Vocabulary::ExtendedV2,
        ReferenceSyntax::Original => Vocabulary::Baseline,
    };
    let properties = with_verified_request(
        document,
        assessment.context,
        assessment.request,
        work,
        |session| {
            Ok(
                selected(document, &session, request.signature, request.id_attributes).and_then(
                    |node| {
                        let visitor = Referenced {
                            unsigned,
                            syntax: request.syntax,
                            digest: request.digest,
                        };
                        match validate_with(&session, node, &census, vocabulary, visitor)? {
                            Outcome::Assessed(properties) => properties,
                            outcome => Err(AugmentError::Unmet(outcome.map(|_| ()))),
                        }
                    },
                ),
            )
        },
    )??;
    publish(
        document,
        &Publication {
            assessment,
            inputs: &inputs,
            vocabulary,
            signature: request.signature,
            id_attributes: request.id_attributes,
            unsigned,
        },
        &properties,
        work,
    )
}

/// The census visitor: the reference properties as markup.
struct Referenced {
    unsigned: Unsigned,
    syntax: ReferenceSyntax,
    digest: DigestAlgorithm,
}

impl<W: Work> Visit<W> for Referenced {
    type Output = Result<Vec<String>, AugmentError>;

    // Only a validation that ended before its census reaches these.
    fn level(self, _stage: &Stage<'_, '_, '_, '_, W>, level: &Level<'_>) -> Self::Output {
        Err(AugmentError::BelowLongTerm(level.requested()))
    }

    fn extended(self, _stage: &Stage<'_, '_, '_, '_, W>, level: ExtendedLevel) -> Self::Output {
        Err(AugmentError::BelowLongTerm(level.requested()))
    }

    fn census(self, census: &Census<'_, '_, '_, '_, '_, '_, '_, W>) -> Result<Self::Output, Self> {
        Ok(references(census, &self))
    }
}

/// The reference properties of the signer's path and statuses.
fn references<W: Work>(
    census: &Census<'_, '_, '_, '_, '_, '_, '_, W>,
    request: &Referenced,
) -> Result<Vec<String>, AugmentError> {
    let stage = census.stage();
    let work = stage.session.execution();
    let artifacts = signer_artifacts(
        census.closure(),
        stage.access,
        stage.certificate.selected().certificate().as_bytes(),
        |value| census.envelope(value),
        work,
    )?;
    let cms = stage.session.cms_provider();
    let mut staging = Staging {
        session: stage.session,
        base: stage.document.snapshot(),
        signature: stage.prepared.bound().containers().signature(),
        unsigned: request.unsigned.signature_properties(),
        draft: Draft::siblings(),
    };
    References {
        syntax: request.syntax,
        role: ReferenceRole::Signature,
        method: request.digest.uri(),
        artifacts: &artifacts,
    }
    .write(&mut staging, &cms, work, |uri, _| {
        // The method is the one the caller named; its URI resolves to it.
        Ok(match DigestAlgorithm::from_uri(uri) {
            Some(algorithm) => Resolution::Supported((algorithm, hash_class(algorithm))),
            None => Resolution::Unsupported,
        })
    })
    .map_err(reference_error)?;
    Ok(staging.draft.finish_siblings()?)
}

/// The CA certificates and statuses the signer's path in `closure` uses, in
/// the order the census first met them: never the `signer`'s own
/// certificate, which `SigningCertificate` already binds. `envelope` finds
/// the whole `OCSPResponse` of a basic response.
pub(super) fn signer_artifacts<'r, X: Xml<Id = NodeIdentity>, A: Work, Q: Work>(
    closure: &'r ParticipantClosure<'r, 'r, 'r, 'r, X::Id, X::Document, X::Generation, Xades>,
    access: &Access<'_, X, A>,
    signer: &[u8],
    envelope: impl Fn(&BasicResponse<'_>) -> Option<&'r ResponseBytes<'r>>,
    work: &Q,
) -> Result<OwnedVec<ReferenceArtifact<'r, 'r>>, AugmentError> {
    let purposes = authority_uses(closure, access).map_err(AugmentError::Uses)?;
    let uses = artifact_uses(&purposes, access).map_err(AugmentError::Uses)?;
    let mut artifacts = work.vector();
    for entry in uses.entries() {
        work.charge_work(1)?;
        if !entry.uses().signature() {
            continue;
        }
        let artifact = match entry.artifact() {
            ArtifactRef::Certificate(value) if value.as_bytes() == signer => continue,
            ArtifactRef::Certificate(value) => ReferenceArtifact::certificate(value),
            ArtifactRef::Crl(value) => ReferenceArtifact::crl(value),
            ArtifactRef::Ocsp(value) => {
                let envelope = envelope(value).ok_or(AugmentError::MissingEnvelope)?;
                ReferenceArtifact::ocsp::<Infallible, _>(envelope, value, work)
                    .map_err(AugmentError::Construction)?
            }
        };
        artifacts.try_push(artifact)?;
    }
    Ok(artifacts.into_owned())
}

/// Compute the input of a new `kind` timestamp of `request.signature` (ETSI
/// TS 101 903 V1.4.2 §§7.5 and 8.2: an X timestamp over the signature and its
/// references, or over the references only, or an archive timestamp) and
/// encode the RFC 3161 request for it.
///
/// The signature must meet `inputs.requirements`, B-T or above, under
/// `assessment`; the properties the timestamp covers, such as the complete
/// references of [`add_complete_references`], are added first. The input is
/// canonicalized with the signature's own `CanonicalizationMethod`. Pass the
/// response to [`super::complete_timestamp`].
///
/// # Errors
/// Returns the original cause, [`AugmentError::BelowTimestamped`] for a level
/// below B-T; the document is never changed.
///
/// # Examples
///
/// ```no_run
/// use structured_pkix::algorithm::digest::Algorithm;
/// use xml_sec_xades::{
///     Assessment, ExtendedKind, Inputs, ReferenceSyntax, TimestampRequest,
///     request_extended_timestamp,
/// };
/// # fn x(
/// #     document: &xml_sec::XmlDocument,
/// #     assessment: &Assessment<'_, '_>,
/// #     inputs: &Inputs<'_>,
/// #     work: &structured_asn1::memory::Memory,
/// # ) -> Result<xml_sec_xades::PendingTimestamp, xml_sec_xades::AugmentError> {
/// request_extended_timestamp(
///     document,
///     &TimestampRequest {
///         signature: "sig",
///         digest: Algorithm::Sha256,
///         policy: None,
///         nonce: Some(&[0x2a; 8]),
///         id_attributes: &[],
///     },
///     ExtendedKind::SignatureAndReferences(ReferenceSyntax::V2),
///     assessment,
///     inputs,
///     work,
/// )
/// # }
/// ```
pub fn request_extended_timestamp<W: Work>(
    document: &XmlDocument,
    request: &TimestampRequest<'_>,
    kind: ExtendedKind,
    assessment: &Assessment<'_, '_>,
    inputs: &Inputs<'_>,
    work: &W,
) -> Result<PendingTimestamp, AugmentError> {
    if inputs.requirements == Requirements::Basic {
        return Err(AugmentError::BelowTimestamped(inputs.requirements));
    }
    let certificates = pooled(inputs, assessment, work)?;
    let inputs = Inputs {
        certificates: &certificates,
        ..*inputs
    };
    let gate = Gate::Extended(&inputs);
    let (identity, generation) = document.with_view(|view| {
        placement::locate(view, request.signature, request.id_attributes, work)?;
        Ok::<_, AugmentError>((view.identity(), view.generation()))
    })?;
    let encoded = with_verified_request(
        document,
        assessment.context,
        assessment.request,
        work,
        |session| {
            Ok(
                selected(document, &session, request.signature, request.id_attributes).and_then(
                    |node| {
                        gated(&session, node, &gate, |stage, _| {
                            extended_request(stage, request, kind)
                        })
                    },
                ),
            )
        },
    )??;
    Ok(PendingTimestamp {
        document: identity,
        generation,
        signature: request.signature.into(),
        kind: Stamp::Extended(kind),
        basis: gate.requirements(),
        request: encoded,
        renewal: None,
        repeat: Some(Repeat::of(request)),
    })
}

/// The prepared input of a new `kind` timestamp over the stage's generation,
/// with the DER request for it.
fn extended_request<W: Work>(
    stage: &Stage<'_, '_, '_, '_, W>,
    request: &TimestampRequest<'_>,
    kind: ExtendedKind,
) -> Result<OwnedVec<u8>, AugmentError> {
    with_prepared(stage, request, kind, |_, encoded| {
        let execution = stage.session.execution();
        let mut copy = execution.memory().vector();
        copy.try_extend_from_slice(encoded)?;
        Ok(copy.into_owned())
    })
}

/// Run `then` with the input of a new `kind` timestamp prepared over the
/// stage's generation and the DER request it encodes for `request`.
fn with_prepared<W: Work, R>(
    stage: &Stage<'_, '_, '_, '_, W>,
    request: &TimestampRequest<'_>,
    kind: ExtendedKind,
    then: impl FnOnce(
        &mut ExtendedAugmentation<'_, crate::Document<'_, '_, '_, '_, W>>,
        &[u8],
    ) -> Result<R, AugmentError>,
) -> Result<R, AugmentError> {
    let method = signed_method(stage, request.signature)?;
    let execution = stage.session.execution();
    let mut augmentation = ExtendedAugmentation::prepare(
        stage.document,
        stage.prepared.bound(),
        kind,
        method,
        execution,
    )
    .map_err(|error| AugmentError::Input(Box::new(error)))?;
    let cms = stage.session.cms_provider();
    with_algorithm(stage.parser, request.digest, |reader, algorithm| {
        let encoded = augmentation
            .request(
                &cms,
                reader,
                &ContentRequest {
                    algorithm,
                    policy: request.policy,
                    nonce: request.nonce,
                    cert_req: true,
                    extensions: &[],
                },
            )
            .map_err(|error| AugmentError::ExtendedRequest(Box::new(error)))?;
        let mut owned = execution.memory().vector();
        owned.try_extend_from_slice(encoded)?;
        let owned = owned.into_owned();
        then(&mut augmentation, &owned)
    })
}

impl PendingTimestamp {
    /// The parameters an extended request was made with.
    pub(super) fn repeated(&self) -> Result<&Repeat, AugmentError> {
        self.repeat.as_ref().ok_or(AugmentError::Construction(
            structured_xades::produce::Error::Prerequisites,
        ))
    }
}

/// The `kind` timestamp property of a checked response, as markup: the
/// request made again over the current generation must be the pending one.
pub(super) fn timestamped<W: Work>(
    stage: &Stage<'_, '_, '_, '_, W>,
    kind: ExtendedKind,
    pending: &PendingTimestamp,
    response: &[u8],
    completion: &Completion<'_, '_>,
    unsigned: Unsigned,
) -> Result<String, AugmentError> {
    let repeated = pending.repeated()?;
    with_prepared(
        stage,
        &repeated.request(&pending.signature),
        kind,
        |augmentation, encoded| {
            if encoded != pending.request() {
                return Err(AugmentError::Changed);
            }
            with_response_check(stage, pending, response, completion, |check, status| {
                let checked = augmentation
                    .check_response(check, unrecognized())
                    .map_err(|error| AugmentError::Check(Box::new(error)))?;
                if checked.timestamp().is_none() {
                    return Err(unproven(checked.facts(), status));
                }
                let mut staging = Staging::over(stage, unsigned);
                augmentation
                    .write_timestamp(&checked, &mut staging, stage.session.execution())
                    .map_err(construction)?;
                Ok(staging.draft.finish()?.0)
            })
        },
    )
}

/// A refusal of the shared reference construction, with its original cause.
pub(super) fn reference_error(
    error: ReferenceError<StagingError, xml_sec::xmldsig::cms::CmsProviderError>,
) -> AugmentError {
    match error {
        ReferenceError::Write(error) => construction(error),
        ReferenceError::Digest(error) => AugmentError::ReferenceDigest(Box::new(error)),
        ReferenceError::Method(_) => AugmentError::UnsupportedDigest,
        ReferenceError::Prohibited(_) => AugmentError::ProhibitedReferenceDigest,
        ReferenceError::Pki(error) => AugmentError::Pkix(error),
    }
}
