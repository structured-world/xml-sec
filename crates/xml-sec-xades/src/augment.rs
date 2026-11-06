//! `XAdES` augmentation to B-T, B-LT and B-LTA over a caller-owned
//! timestamp exchange.
//!
//! [`request_timestamp`] computes the `SignatureTimeStamp` input of one
//! signature that meets B-B (EN 319 132-1 §5.3) and encodes the RFC 3161
//! request over it; the caller sends that request to its TSA.
//! [`complete_timestamp`] checks the TSA response against that exact request
//! and the unchanged document, appends the token as a `SignatureTimeStamp`
//! and publishes the new generation only after it meets the requested level.
//! [`add_validation_data`] then appends the certificates and statuses a B-T
//! signature lacks for B-LT, and [`request_archive_timestamp`] requests the
//! `ArchiveTimeStamp` of B-LTA or of its renewal, which [`complete_timestamp`]
//! completes in the same way. Nothing is fetched and no clock is read here.

mod validation_data;

pub use validation_data::{DataAdded, ValidationData, add_validation_data};

use crate::accuracy;
use crate::basic::{Outcome, Stage, ValidationError, with_stage};
use crate::create::{Assessment, Carried};
use crate::draft::{Draft, DraftError};
use crate::level::{
    Inputs, Level, Visit, read_certificates, unrecognized, validate, validate_with,
};
use crate::placement::{self, DS, PlacementError, Unsigned};
use crate::{Error, Snapshot};
use alloc::{boxed::Box, string::String};
use core::convert::Infallible;
use structured_asn1::digest::{Digest, Resolution};
use structured_asn1::memory::{MemoryError, OwnedVec, Work};
use structured_asn1::{Oid, Parser, Reader, Tag, universal};
use structured_cms::directory::{CertificateAgreement, matches_certificate_in};
use structured_cms::stream::{self, Sink, StreamError};
use structured_cms::timestamp::response::Status;
use structured_cms::timestamp::{
    CheckContext, ImprintAgreement, NewRequest, Request, RequestAgreement, RequestEncodingError,
    RequestFields, RequestWindow, Requested, Response, Timeliness, Token,
};
use structured_pkix::Certificate;
use structured_pkix::algorithm::digest::{self, AsnDigest};
use structured_pkix::path::WorkingKey;
use structured_xades::baseline::{self, Evidence};
use structured_xades::produce::{
    self, Augmentation, Event, PreparationError, ResponseCheck, ResponseError, TimestampKind,
    Transaction, Writer,
};
use structured_xades::timestamp::InputError;
use structured_xades::unsigned::Requirements;
use structured_xades::xml::Xml;
use xml_sec::IdAttributeRegistration;
use xml_sec::document::{DocumentIdentity, NodeIdentity, XmlDocument, XmlDocumentError};
use xml_sec::xmldsig::DigestAlgorithm;
use xml_sec::xmldsig::cms::{CmsProvider, CmsProviderError, DigestOutput};
use xml_sec::xmldsig::extension::{ScalarError, TreeError};
use xml_sec::xmldsig::{DsigError, ReplayError, VerifiedSession, with_verified_request};

/// The timestamp to request for one signature.
pub struct TimestampRequest<'a> {
    /// ID of the `Signature` to timestamp.
    pub signature: &'a str,
    /// Hash of the message imprint; the operation's digest policy must allow it.
    pub digest: digest::Algorithm,
    /// TSA policy to request, if any.
    pub policy: Option<Oid<'a>>,
    /// Unsigned nonce magnitude from the caller's entropy source. Without it,
    /// [`Completion::window`] has to establish that the response is fresh.
    pub nonce: Option<&'a [u8]>,
    /// ID attributes beyond the standard spellings.
    pub id_attributes: &'a [IdAttributeRegistration],
}

/// A timestamp request bound to the document generation it covers.
///
/// Send [`PendingTimestamp::request`] to the TSA and pass the response to
/// [`complete_timestamp`]. Any change to the document in between makes the
/// request stale.
#[derive(Debug)]
pub struct PendingTimestamp {
    document: DocumentIdentity,
    generation: u64,
    signature: String,
    kind: TimestampKind,
    /// The level the signature met when the request was made, and must still
    /// meet when it is completed.
    basis: Requirements,
    request: OwnedVec<u8>,
}

impl PendingTimestamp {
    /// The DER `TimeStampReq` (RFC 3161 §2.4.1) to send to the TSA.
    #[must_use]
    pub fn request(&self) -> &[u8] {
        &self.request
    }
}

/// What a TSA response is checked with and what the result must meet.
pub struct Completion<'a, 'inputs> {
    /// The verification that assesses the document before and after the token
    /// is added.
    pub assessment: &'a Assessment<'a, 'inputs>,
    /// Evidence of the level the new generation must meet, B-T or above:
    /// anchors of the TSA's path, UTC facts and authority accuracies.
    pub inputs: &'a Inputs<'a>,
    /// Caller-established window in which the request was uniquely
    /// outstanding (RFC 3161 §6); it proves freshness when no nonce was sent.
    pub window: Option<RequestWindow>,
    /// ID attributes beyond the standard spellings.
    pub id_attributes: &'a [IdAttributeRegistration],
}

/// What the checker found about a token that is not evidence for the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenFacts {
    /// Whether the token's imprint covers the signature's timestamp input.
    pub imprint: ImprintAgreement,
    /// Whether the token's imprint is the requested one.
    pub requested_imprint: Option<RequestAgreement>,
    /// Whether the token repeats the requested nonce and policy.
    pub requested_fields: Option<RequestFields>,
    /// What establishes, or fails to establish, that the token is fresh.
    pub timeliness: Timeliness,
}

/// An augmentation that published nothing, with its original cause.
#[derive(Debug, thiserror::Error)]
pub enum AugmentError {
    /// No `Signature` element has the ID.
    #[error("no Signature has the ID {0:?}")]
    UnknownSignature(String),
    /// The signature has no `XAdES` qualifying properties targeting it.
    #[error("signature {0:?} has no XAdES qualifying properties")]
    NotXades(String),
    /// The document changed since the request was made.
    #[error("the document changed since the timestamp was requested")]
    Changed,
    /// The completion asks for a level below B-T.
    #[error("a completed timestamp is assessed at B-T or above, not {0:?}")]
    BelowTimestamped(Requirements),
    /// The completion of an archive timestamp asks for a level below B-LTA.
    #[error("a completed archive timestamp is assessed at B-LTA, not {0:?}")]
    BelowArchival(Requirements),
    /// Added validation data is assessed at a level below B-LT.
    #[error("added validation data is assessed at B-LT or above, not {0:?}")]
    BelowLongTerm(Requirements),
    /// A required OCSP response has no whole `OCSPResponse` among the caller's
    /// responses or the document's values.
    #[error("a required OCSP response has no whole OCSPResponse to incorporate")]
    MissingEnvelope,
    /// The document does not satisfy the assessment's verification request.
    #[error("the document does not satisfy the verification request")]
    NotAccepted,
    /// Verification could not complete.
    #[error(transparent)]
    Verification(#[from] DsigError),
    /// A baseline assessment could not complete.
    #[error(transparent)]
    Validation(#[from] ValidationError),
    /// The signature does not meet B-B before the token is added, or the new
    /// generation does not meet the requested level; the outcome names why.
    #[error("the required level is not met: {0:?}")]
    Unmet(Outcome<()>),
    /// The shared augmentation rules refused the step.
    #[error("augmentation refused: {0:?}")]
    Construction(produce::Error<Infallible>),
    /// The timestamp input could not be produced.
    #[error("timestamp input failed: {0:?}")]
    Input(Box<InputError<Error, NodeIdentity>>),
    /// The provider has no implementation of the requested digest.
    #[error("the requested imprint digest is not supported")]
    UnsupportedDigest,
    /// The provider could not compute the imprint.
    #[error(transparent)]
    Imprint(CmsProviderError),
    /// The request could not be encoded.
    #[error("timestamp request encoding failed: {0:?}")]
    Encoding(Box<RequestEncodingError>),
    /// ASN.1 processing could not start or failed.
    #[error("ASN.1 processing failed: {0:?}")]
    Asn1(structured_asn1::Error),
    /// The hash algorithm identifier could not be read.
    #[error("algorithm identifier failed: {0:?}")]
    Pkix(structured_pkix::Error),
    /// The request or response is not a conforming RFC 3161 message.
    #[error("timestamp message failed: {0:?}")]
    Message(structured_cms::Error),
    /// The TSA granted no token; the status is unauthenticated.
    #[error("the TSA granted no token: {0:?}")]
    Refused(Status),
    /// No supplied or carried certificate is the token's signer.
    #[error("no available certificate is the token's signer")]
    MissingAuthority,
    /// The token signer could not be compared with a certificate.
    #[error("timestamp signer comparison failed: {0:?}")]
    Signer(structured_cms::directory::Error),
    /// The response check could not complete.
    #[error("timestamp response check failed: {0:?}")]
    Check(Box<ResponseError<Error, NodeIdentity, CmsProviderError, Infallible>>),
    /// The token is not evidence for this request and document.
    #[error("the token is not evidence for the request: {0:?}")]
    Unproven(TokenFacts),
    /// The property draft could not be completed.
    #[error(transparent)]
    Draft(#[from] DraftError),
    /// The signature's canonicalization method could not be copied.
    #[error("canonicalization method copy failed: {0}")]
    Method(DsigError),
    /// The document refused the mutation.
    #[error(transparent)]
    Document(#[from] XmlDocumentError),
    /// The document could not be read.
    #[error(transparent)]
    Tree(#[from] TreeError),
    /// An attribute of the document could not be read.
    #[error(transparent)]
    Scalar(#[from] ScalarError),
    /// A supplied certificate could not be read.
    #[error(transparent)]
    Adapter(#[from] Error),
    /// The current execution refused work or storage.
    #[error("augmentation resource refusal: {0}")]
    Resource(MemoryError),
}

impl From<MemoryError> for AugmentError {
    fn from(error: MemoryError) -> Self {
        Self::Resource(error)
    }
}

impl From<PlacementError> for AugmentError {
    fn from(error: PlacementError) -> Self {
        match error {
            PlacementError::UnknownSignature(id) => Self::UnknownSignature(id),
            PlacementError::NotXades(id) => Self::NotXades(id),
            PlacementError::Tree(error) => Self::Tree(error),
            PlacementError::Scalar(error) => Self::Scalar(error),
            PlacementError::Resource(error) => Self::Resource(error),
        }
    }
}

/// Compute the `SignatureTimeStamp` input of `request.signature` and encode
/// the RFC 3161 request for it.
///
/// The signature must meet every B-B requirement under `assessment`. The
/// input is canonicalized with the signature's own `CanonicalizationMethod`,
/// which the completed property repeats. The request asks the TSA to include
/// its certificate.
///
/// # Errors
/// Returns the original cause; the document is never changed.
pub fn request_timestamp<W: Work>(
    document: &XmlDocument,
    request: &TimestampRequest<'_>,
    assessment: &Assessment<'_, '_>,
    work: &W,
) -> Result<PendingTimestamp, AugmentError> {
    requested(
        document,
        request,
        assessment,
        &Gate::Basic(assessment.certificates),
        TimestampKind::Signature,
        work,
    )
}

/// Compute the input of a new `ArchiveTimeStamp` (EN 319 132-1 §5.5.2.3) of
/// `request.signature` and encode the RFC 3161 request for it.
///
/// The signature must meet `inputs.requirements`, B-LT for its first archive
/// and B-LTA to renew earlier ones, under `assessment` and the caller's
/// evidence in `inputs`. The archive input covers every earlier unsigned
/// property, archives included, so each renewal protects all that came before.
/// Validation data the next archive needs is added first with
/// [`add_validation_data`]. Pass the response to [`complete_timestamp`].
///
/// # Errors
/// Returns the original cause, [`AugmentError::BelowLongTerm`] for a level
/// below B-LT; the document is never changed.
///
/// # Examples
///
/// ```no_run
/// use structured_pkix::algorithm::digest::Algorithm;
/// use xml_sec_xades::{
///     Assessment, Completion, Inputs, Requirements, TimestampRequest, complete_timestamp,
///     request_archive_timestamp,
/// };
/// # fn archive(
/// #     document: &mut xml_sec::XmlDocument,
/// #     assessment: &Assessment<'_, '_>,
/// #     evidence: &Inputs<'_>,
/// #     tsa: impl Fn(&[u8]) -> Vec<u8>,
/// #     work: &structured_asn1::memory::Memory,
/// # ) -> Result<(), xml_sec_xades::AugmentError> {
/// let pending = request_archive_timestamp(
///     document,
///     &TimestampRequest {
///         signature: "sig",
///         digest: Algorithm::Sha256,
///         policy: None,
///         nonce: Some(&[0x2a; 8]),
///         id_attributes: &[],
///     },
///     assessment,
///     &Inputs { requirements: Requirements::LongTerm, ..*evidence },
///     work,
/// )?;
/// let response = tsa(pending.request());
/// complete_timestamp(
///     document,
///     &pending,
///     &response,
///     &Completion {
///         assessment,
///         inputs: &Inputs { requirements: Requirements::Archival, ..*evidence },
///         window: None,
///         id_attributes: &[],
///     },
///     work,
/// )
/// # }
/// ```
pub fn request_archive_timestamp<W: Work>(
    document: &XmlDocument,
    request: &TimestampRequest<'_>,
    assessment: &Assessment<'_, '_>,
    inputs: &Inputs<'_>,
    work: &W,
) -> Result<PendingTimestamp, AugmentError> {
    if matches!(
        inputs.requirements,
        Requirements::Basic | Requirements::Timestamped
    ) {
        return Err(AugmentError::BelowLongTerm(inputs.requirements));
    }
    let certificates = pooled(inputs, assessment, work)?;
    let inputs = Inputs {
        certificates: &certificates,
        ..*inputs
    };
    requested(
        document,
        request,
        assessment,
        &Gate::LongTerm(&inputs),
        TimestampKind::Archive,
        work,
    )
}

/// The request of a `kind` timestamp over a signature that passes `gate`.
fn requested<W: Work>(
    document: &XmlDocument,
    request: &TimestampRequest<'_>,
    assessment: &Assessment<'_, '_>,
    gate: &Gate<'_>,
    kind: TimestampKind,
    work: &W,
) -> Result<PendingTimestamp, AugmentError> {
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
                        gated(&session, node, gate, |stage, level| {
                            let method = signed_method(stage, request.signature)?;
                            let execution = stage.session.execution();
                            let mut input = Augmentation::new(stage.document, stage.prepared)
                                .input(level, kind, method, execution)
                                .map_err(|error| match error {
                                    PreparationError::Admission(error) => {
                                        AugmentError::Construction(error)
                                    }
                                    PreparationError::Input(error) => {
                                        AugmentError::Input(Box::new(error))
                                    }
                                })?;
                            let cms = stage.session.cms_provider();
                            let identity = cms
                                .identity(request.digest)
                                .ok_or(AugmentError::UnsupportedDigest)?;
                            let hashed = imprint(&cms, identity, &mut input, execution)?;
                            encode(stage.parser, request, hashed.as_ref())
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
        kind,
        basis: gate.requirements(),
        request: encoded,
    })
}

/// Check `response` against `pending` and publish its token as the
/// `SignatureTimeStamp` or `ArchiveTimeStamp` the request was for, as one new
/// generation of `document`, after that generation meets
/// `completion.inputs.requirements`: B-T or above for a signature timestamp,
/// B-LTA for an archive one.
///
/// The unchanged generation must still meet the level it met at the request.
/// The response must carry a token that the shared RFC 3161 checker accepts
/// for the exact request and for the signature's current timestamp input,
/// signed by a certificate the token carries or the caller supplies in
/// `completion.inputs`. Freshness comes from the request nonce or from
/// `completion.window`.
///
/// # Errors
/// Returns the original cause, and [`AugmentError::Changed`] when the
/// document is not the generation the request was made for; the document is
/// unchanged.
pub fn complete_timestamp<W: Work>(
    document: &mut XmlDocument,
    pending: &PendingTimestamp,
    response: &[u8],
    completion: &Completion<'_, '_>,
    work: &W,
) -> Result<(), AugmentError> {
    let requirements = completion.inputs.requirements;
    match pending.kind {
        TimestampKind::Signature if requirements == Requirements::Basic => {
            return Err(AugmentError::BelowTimestamped(requirements));
        }
        TimestampKind::Archive if requirements != Requirements::Archival => {
            return Err(AugmentError::BelowArchival(requirements));
        }
        TimestampKind::Signature | TimestampKind::Archive => {}
    }
    if document.with_view(|view| (view.identity(), view.generation()))
        != (pending.document, pending.generation)
    {
        return Err(AugmentError::Changed);
    }
    let assessment = completion.assessment;
    let signature = pending.signature.as_str();
    let unsigned = document.with_view(|view| {
        placement::locate(view, signature, completion.id_attributes, work)
            .map(|located| located.unsigned)
    })?;
    let certificates = pooled(completion.inputs, assessment, work)?;
    let inputs = Inputs {
        certificates: &certificates,
        ..*completion.inputs
    };
    let basis = Inputs {
        requirements: pending.basis,
        ..inputs
    };
    let gate = match pending.kind {
        TimestampKind::Signature => Gate::Basic(assessment.certificates),
        TimestampKind::Archive => Gate::LongTerm(&basis),
    };
    let property = with_verified_request(
        document,
        assessment.context,
        assessment.request,
        work,
        |session| {
            Ok(
                selected(document, &session, signature, completion.id_attributes).and_then(
                    |node| {
                        gated(&session, node, &gate, |stage, level| {
                            timestamped(stage, level, pending, response, completion, unsigned)
                        })
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
            signature,
            id_attributes: completion.id_attributes,
            unsigned,
        },
        Some(&property),
        work,
    )
}

/// The input certificates, then the ones the assessment's B-B path used.
///
/// The signer's path forms from the certificates its B-B assessment used, as
/// it did before anything was added. They join the pool any path may use,
/// never the anchors: every other path still has to end at an input anchor.
fn pooled<'c, W: Work>(
    inputs: &Inputs<'c>,
    assessment: &Assessment<'c, '_>,
    work: &W,
) -> Result<OwnedVec<&'c [u8]>, AugmentError> {
    let mut certificates = work.memory().vector();
    certificates.try_reserve_exact(inputs.certificates.len() + assessment.certificates.len())?;
    for certificate in inputs.certificates.iter().chain(assessment.certificates) {
        certificates.try_push(*certificate)?;
    }
    Ok(certificates.into_owned())
}

/// Where a new generation is published and what it must meet.
struct Publication<'p, 'a, 'inputs> {
    assessment: &'p Assessment<'a, 'inputs>,
    inputs: &'p Inputs<'p>,
    signature: &'p str,
    id_attributes: &'p [IdAttributeRegistration],
    unsigned: Unsigned,
}

/// Insert `property`, if any, among the unsigned signature properties and
/// keep the result only if it satisfies the assessment's verification request
/// and meets `inputs.requirements`. Without a property nothing is committed,
/// so the document keeps its generation either way.
fn publish<W: Work>(
    document: &mut XmlDocument,
    publication: &Publication<'_, '_, '_>,
    property: Option<&str>,
    work: &W,
) -> Result<(), AugmentError> {
    let Publication {
        assessment,
        inputs,
        signature,
        id_attributes,
        unsigned,
    } = *publication;
    document.transaction(|document| {
        if let Some(property) = property {
            unsigned.insert(document, property)?;
        }
        // The caller's targets and keys name elements of the requested
        // generation; they hold for the same elements in the new one.
        let carried = Carried::new::<_, AugmentError>(document, assessment.request, work)?;
        let outcome = with_verified_request(
            document,
            assessment.context,
            &carried.request(assessment.request),
            work,
            |session| {
                Ok(
                    selected(document, &session, signature, id_attributes).and_then(|node| {
                        Ok(validate(&session, node, inputs, |level| {
                            level.all_requirements_met()
                        })?)
                    }),
                )
            },
        )??;
        match outcome {
            Outcome::Assessed(true) => Ok(()),
            outcome => Err(AugmentError::Unmet(outcome.map(|_| ()))),
        }
    })
}

/// The signature `id` of a generation that satisfies the verification request.
fn selected<W: Work>(
    document: &XmlDocument,
    session: &VerifiedSession<'_, '_, '_, W>,
    id: &str,
    registrations: &[IdAttributeRegistration],
) -> Result<NodeIdentity, AugmentError> {
    if !session.evidence().accepted(document)? {
        return Err(AugmentError::NotAccepted);
    }
    session
        .view()
        .node_for_id(id, registrations)
        .ok_or_else(|| AugmentError::UnknownSignature(id.into()))
}

/// The level a signature must meet before a timestamp is requested or added.
enum Gate<'g> {
    /// B-B, with these certificates beyond `KeyInfo` for the signer's path.
    Basic(&'g [&'g [u8]]),
    /// `inputs.requirements`, B-LT or B-LTA, with the caller's evidence.
    LongTerm(&'g Inputs<'g>),
}

impl Gate<'_> {
    fn requirements(&self) -> Requirements {
        match self {
            Self::Basic(_) => Requirements::Basic,
            Self::LongTerm(inputs) => inputs.requirements,
        }
    }
}

/// Run `then` over the assessment of `signature` at `gate`. The shared rules
/// refuse an assessment whose requirements are not all met.
fn gated<W: Work, R>(
    session: &VerifiedSession<'_, '_, '_, W>,
    signature: NodeIdentity,
    gate: &Gate<'_>,
    then: impl for<'a, 'l> FnOnce(&Stage<'a, '_, '_, '_, W>, &Level<'l>) -> Result<R, AugmentError>,
) -> Result<R, AugmentError> {
    let outcome = match gate {
        Gate::Basic(certificates) => with_stage(
            session,
            signature,
            Requirements::Basic,
            [certificates, &[]],
            None,
            |stage, report| {
                let level =
                    baseline::assess(Evidence::Basic(report)).map_err(ValidationError::Level)?;
                Ok(Outcome::Assessed(then(stage, &level)))
            },
        )?,
        Gate::LongTerm(inputs) => validate_with(session, signature, inputs, Then(then))?,
    };
    match outcome {
        Outcome::Assessed(result) => result,
        outcome => Err(AugmentError::Unmet(outcome.map(|_| ()))),
    }
}

/// A level visitor that runs a step over the stage and its assessment.
struct Then<F>(F);

impl<W: Work, F, R> Visit<W> for Then<F>
where
    F: for<'a, 'l> FnOnce(&Stage<'a, '_, '_, '_, W>, &Level<'l>) -> Result<R, AugmentError>,
{
    type Output = Result<R, AugmentError>;

    fn level(self, stage: &Stage<'_, '_, '_, '_, W>, level: &Level<'_>) -> Self::Output {
        (self.0)(stage, level)
    }
}

/// The `CanonicalizationMethod` of the signature's `SignedInfo`.
fn signed_method<W: Work>(
    stage: &Stage<'_, '_, '_, '_, W>,
    id: &str,
) -> Result<NodeIdentity, AugmentError> {
    let view = stage.session.view();
    let work = stage.session.execution();
    let signature = stage.prepared.bound().containers().signature();
    let missing = || AugmentError::UnknownSignature(id.into());
    let signed_info =
        placement::child(view, signature, DS, "SignedInfo", work)?.ok_or_else(missing)?;
    placement::child(view, signed_info, DS, "CanonicalizationMethod", work)?.ok_or_else(missing)
}

/// Digest state fed by one pass over the timestamp input.
struct Imprint<'a, P: Digest<'a>> {
    provider: &'a P,
    state: P::State,
}

impl<'a, P: Digest<'a>> Sink for Imprint<'a, P> {
    type Error = P::Error;

    fn write<Q: Work>(&mut self, bytes: &[u8], execution: &Q) -> Result<(), P::Error> {
        self.provider.update(&mut self.state, bytes, execution)
    }
}

/// The message imprint of `input` (RFC 3161 §2.4.1).
fn imprint<S, W: Work>(
    cms: &CmsProvider<'_>,
    identity: DigestAlgorithm,
    input: &mut S,
    work: &W,
) -> Result<DigestOutput, AugmentError>
where
    S: structured_cms::stream::Source<Error = InputError<Error, NodeIdentity>>,
{
    let state = match cms.start(&identity, work).map_err(AugmentError::Imprint)? {
        Resolution::Supported(state) => state,
        Resolution::Unsupported | Resolution::Malformed => {
            return Err(AugmentError::UnsupportedDigest);
        }
    };
    let mut sink = Imprint {
        provider: cms,
        state,
    };
    stream::run(input, &mut sink, work, "messageImprint", 0).map_err(|error| match error {
        StreamError::Source(error) => AugmentError::Input(Box::new(error)),
        StreamError::Callback(error) => AugmentError::Imprint(error),
        StreamError::Processing(error) => AugmentError::Message(error),
    })?;
    cms.finish(sink.state, work).map_err(AugmentError::Imprint)
}

/// The DER `TimeStampReq` over `hashed`.
fn encode(
    parser: &Parser,
    request: &TimestampRequest<'_>,
    hashed: &[u8],
) -> Result<OwnedVec<u8>, AugmentError> {
    let oid = request.digest.identifier().as_bytes();
    // X.690 §8.1.3.4: every standard digest identifier is a few octets, so
    // both lengths of `SEQUENCE { OID }` take the short form.
    let length = u8::try_from(oid.len())
        .ok()
        .filter(|length| *length < 126)
        .expect("standard digest identifiers are short");
    let mut der = parser.memory().vector();
    der.try_reserve_exact(oid.len() + 4)?;
    der.try_extend_from_slice(&[0x30, length + 2, 0x06, length])?;
    der.try_extend_from_slice(oid)?;
    let mut reader = parser.read(&der, 0).map_err(AugmentError::Asn1)?;
    let element = reader
        .expect(Tag::constructed(universal::SEQUENCE))
        .map_err(AugmentError::Asn1)?;
    // RFC 5754 §2 and RFC 9688 §2: absent parameters identify each digest.
    let algorithm = structured_pkix::algorithm::read(&reader, &element, "hashAlgorithm")
        .map_err(AugmentError::Pkix)?;
    NewRequest {
        algorithm,
        hashed_message: hashed,
        policy: request.policy,
        nonce: request.nonce,
        cert_req: true,
        extensions: &[],
    }
    .encode_der(&reader)
    .map_err(|error| AugmentError::Encoding(Box::new(error)))
}

/// The timestamp property of a checked response, as markup.
fn timestamped<W: Work>(
    stage: &Stage<'_, '_, '_, '_, W>,
    level: &Level<'_>,
    pending: &PendingTimestamp,
    response: &[u8],
    completion: &Completion<'_, '_>,
    unsigned: Unsigned,
) -> Result<String, AugmentError> {
    let parser = stage.parser;
    let method = signed_method(stage, &pending.signature)?;
    let mut source = parser.read(response, 0).map_err(AugmentError::Asn1)?;
    let response = Response::read(&mut source).map_err(AugmentError::Message)?;
    let status = response.status().status();
    let Some(token) = response.token().filter(|_| status.granted()) else {
        return Err(AugmentError::Refused(status));
    };
    let carrier = response
        .token_reader_in(stage.operation)
        .map_err(AugmentError::Message)?
        .ok_or(AugmentError::Refused(status))?;
    let mut asked = parser
        .read(pending.request(), 0)
        .map_err(AugmentError::Asn1)?;
    let element = asked
        .expect(Tag::constructed(universal::SEQUENCE))
        .map_err(AugmentError::Asn1)?;
    let request = Request::read(&asked, &element).map_err(AugmentError::Message)?;
    let supplied = read_certificates(parser, completion.inputs.certificates)?;
    let anchors = read_certificates(parser, completion.inputs.anchors)?;
    let (certificate, certificate_parent) =
        authority(token, &carrier, [&supplied, &anchors], stage.operation)?
            .ok_or(AugmentError::MissingAuthority)?;
    let stated = accuracy::read(parser, completion.inputs.accuracies)?;
    let policy_accuracy = accuracy::select_outside(&stated, token, &carrier, stage.operation)?;
    let context = CheckContext {
        certificate,
        certificate_parent,
        key: WorkingKey::standing(certificate.tbs().public_key()),
        requested: Some(Requested {
            request: &request,
            parent: &asked,
        }),
        utc: completion.inputs.utc,
        // A token generated after the time the signature is validated at
        // cannot timestamp it at that time.
        reference: Some(stage.signer_time),
        window: completion.window,
        // RFC 3161 §2.4.2: the caller's policy accuracy answers only an
        // absent field, as in the level validation of the new generation.
        policy_accuracy,
    };
    let cms = stage.session.cms_provider();
    let augmentation = Augmentation::new(stage.document, stage.prepared);
    let checked = augmentation
        .check_response(
            level,
            pending.kind,
            method,
            &ResponseCheck {
                response: &response,
                provider: &cms,
                query: stage.operation,
                context: &context,
            },
            unrecognized(),
        )
        .map_err(|error| AugmentError::Check(Box::new(error)))?;
    let Some(timestamp) = checked.timestamp() else {
        let facts = checked
            .facts()
            .timestamp()
            .ok_or(AugmentError::Refused(status))?;
        return Err(AugmentError::Unproven(TokenFacts {
            imprint: facts.imprint,
            requested_imprint: facts.requested_imprint,
            requested_fields: facts.requested_fields,
            timeliness: facts.timeliness,
        }));
    };
    let mut staging = Staging {
        session: stage.session,
        base: stage.document.snapshot(),
        signature: stage.prepared.bound().containers().signature(),
        unsigned: unsigned.signature_properties(),
        draft: Draft::new(),
    };
    augmentation
        .write_timestamp(&timestamp, &mut staging, stage.session.execution())
        .map_err(construction)?;
    Ok(staging.draft.finish()?.0)
}

/// The certificate `token` names as its signer, carried or supplied.
fn authority<'p, 't>(
    token: &'p Token<'t>,
    carrier: &'p Reader<'t>,
    [supplied, anchors]: [&'p [Certificate<'t>]; 2],
    supplied_parent: &'p Reader<'t>,
) -> Result<Option<(&'p Certificate<'t>, &'p Reader<'t>)>, AugmentError> {
    let named = token.signer().sid();
    // RFC 5652 §5.1: a token may omit its signer's certificate.
    for (certificates, parent) in [
        (token.message().certificates(), carrier),
        (supplied, supplied_parent),
        (anchors, supplied_parent),
    ] {
        for certificate in certificates {
            if matches!(
                matches_certificate_in(named, certificate, parent).map_err(AugmentError::Signer)?,
                CertificateAgreement::Matches
            ) {
                return Ok(Some((certificate, parent)));
            }
        }
    }
    Ok(None)
}

/// A refusal of the shared construction step, with its original cause.
fn construction(error: produce::Error<StagingError>) -> AugmentError {
    match error {
        produce::Error::Writer(StagingError::Draft(error)) => AugmentError::Draft(error),
        produce::Error::Writer(StagingError::Method(error)) => AugmentError::Method(error),
        produce::Error::Resource(error) => AugmentError::Resource(error),
        produce::Error::Value(value) => AugmentError::Construction(produce::Error::Value(value)),
        produce::Error::Foreign => AugmentError::Construction(produce::Error::Foreign),
        produce::Error::Prerequisites => AugmentError::Construction(produce::Error::Prerequisites),
    }
}

/// Why the staged property could not be written.
#[derive(Debug)]
enum StagingError {
    Draft(DraftError),
    Method(DsigError),
}

/// The unpublished property of one augmentation, opened at the original
/// generation the token's input was computed over.
struct Staging<'s, 'v, 'sc, 'i, W: Work> {
    session: &'s VerifiedSession<'v, 'sc, 'i, W>,
    base: Snapshot,
    signature: NodeIdentity,
    unsigned: Option<NodeIdentity>,
    draft: Draft,
}

impl<W: Work> Writer for Staging<'_, '_, '_, '_, W> {
    type Error = StagingError;

    fn write<Q: Work>(&mut self, event: Event<'_>, work: &Q) -> Result<(), StagingError> {
        self.draft.write(event, work).map_err(StagingError::Draft)
    }
}

impl<W: Work> Transaction for Staging<'_, '_, '_, '_, W> {
    type Id = NodeIdentity;
    type Document = DocumentIdentity;
    type Generation = u64;

    fn base(&self) -> Snapshot {
        self.base
    }

    fn signature(&self) -> NodeIdentity {
        self.signature
    }

    fn unsigned_parent(&self) -> Option<NodeIdentity> {
        self.unsigned
    }

    fn method<Q: Work>(&mut self, method: NodeIdentity, work: &Q) -> Result<(), StagingError> {
        let draft = &mut self.draft;
        // The method element canonicalized by itself is a complete element
        // that declares every namespace it uses, PrefixList included.
        self.session
            .canonicalize_element(method, method, work, &mut |bytes: &[u8]| {
                draft.copied(bytes, work)
            })
            .map_err(|error| match error {
                ReplayError::Processing(error) => StagingError::Method(error),
                ReplayError::Receiver(error) => StagingError::Draft(error),
            })
    }
}
