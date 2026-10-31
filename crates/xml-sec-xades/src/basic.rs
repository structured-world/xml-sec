//! The `XAdES` B-B pipeline for one verified signature.

use crate::accuracy::{self, AuthorityAccuracy, Stated};
use crate::level::{RenewalFailure, TimestampFailure, signature_span};
use crate::path::{self, CounterPathError};
use crate::status::{StatusError, StatusFailure};
use crate::{Document, Error};
use alloc::{boxed::Box, string::String};
use core::convert::Infallible;
use structured_asn1::memory::Work;
use structured_asn1::{Parser, Reader};
use structured_cms::content_source::ContentError;
use structured_cms::timestamp::InfoError;
use structured_ltv::baseline::{ArchiveCensusError, TimeError};
use structured_ltv::material::IndexError;
use structured_ltv::pki::{ParticipantClosureError, ParticipantError, TimestampBindingError};
use structured_ltv::timestamp::{ObligationError, TemporalError};
use structured_pkix::temporal::{Instant, LeapTable};
use structured_xades::baseline::{self, Basic, BasicInput, LevelError};
use structured_xades::certificate::{self, CheckedPathCertificate, KeyAssociation};
use structured_xades::counter::{self, WalkError};
use structured_xades::credential;
use structured_xades::hashes::{self, HashError, ParticipantBinding, ParticipantProblem};
use structured_xades::material::PipelineError;
use structured_xades::pki::{self, CounterPaths, CounterSelectionError};
use structured_xades::prepare::{self, Prepared};
use structured_xades::renewed;
use structured_xades::timestamp::{
    self, CarriedError, CounterTimestampError, RequirementError, TokenPipelineError, TokenProfile,
};
use structured_xades::unsigned::Requirements;
use structured_xades::xml::{Access, Xml};
use xml_sec::document::{DocumentIdentity, NodeIdentity};
use xml_sec::xmldsig::VerifiedSession;
use xml_sec::xmldsig::cms::CmsProviderError;

pub use crate::path::PathFailure;

/// The assembled B-B facts handed to the caller's visitor. Inspect
/// [`Basic::all_root_requirements_met`] and the individual facts; the report
/// asserts no timestamp, revocation or application trust decision.
pub type Report<'a> = Basic<'a, 'a, 'a, 'a, NodeIdentity, DocumentIdentity, u64>;

/// A completed B-B validation, or the completed negative fact that stopped it.
#[derive(Debug)]
pub enum Outcome<R> {
    /// The B-B facts were assembled; this is the visitor's result.
    Assessed(R),
    /// A signer of the root or of an incorporated countersignature has no
    /// checked certificate path.
    Path {
        /// Original signature whose signer lacks the path.
        signature: NodeIdentity,
        /// Why no path is available.
        failure: PathFailure,
    },
    /// A countersignature's verification key is not its path target's key.
    CounterKey {
        /// Original countersignature.
        signature: NodeIdentity,
        /// The completed or unproven association.
        association: KeyAssociation,
    },
    /// An original actor used MD5 or an unsupported or unprocessed hash
    /// (EN 319 132-1 §6.2.1).
    Hashes(ParticipantProblem<NodeIdentity>),
    /// A timestamp token has no usable evidence for this request.
    Timestamp {
        /// Original timestamp property.
        property: NodeIdentity,
        /// Why the token proves nothing here.
        failure: TimestampFailure,
    },
    /// A signed credential has no selected format handler.
    Credential {
        /// Original credential payload.
        node: NodeIdentity,
    },
    /// A path member has no usable status input.
    Status(StatusFailure),
    /// A `RenewedDigestsV2` property does not confirm its detached object.
    Renewal {
        /// Original renewal property.
        property: NodeIdentity,
        /// Why it does not.
        failure: RenewalFailure,
    },
}

/// Countersignature traversal failure with the original selection cause.
pub type CounterError =
    WalkError<Error, CounterSelectionError<CounterPathError, Error, NodeIdentity>, NodeIdentity>;

/// Processing failure of one pipeline stage, with the stage's original cause.
///
/// Stage causes nest the adapter's error with original locations; they are
/// boxed so the successful result stays small. The box is allocated only on
/// the failure path.
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    /// Adapter, path selection or session failure.
    #[error("XAdES adapter failure: {0}")]
    Adapter(#[from] Error),
    /// Qualifying-property structure, binding or reading failed.
    #[error("XAdES preparation failed: {0:?}")]
    Prepare(Box<prepare::Error<Error, NodeIdentity>>),
    /// Signed property attributes, URIs or the claimed signing time failed.
    #[error("XAdES signed field check failed: {0:?}")]
    Fields(Box<prepare::FieldError<Error, NodeIdentity, DocumentIdentity, u64>>),
    /// Countersignature traversal or binding failed.
    #[error("countersignature traversal failed: {0:?}")]
    Counters(Box<CounterError>),
    /// Hash-use receipts could not be checked.
    #[error("hash-use check failed: {0:?}")]
    Hashes(Box<HashError<Error, NodeIdentity>>),
    /// Signing-certificate references could not be checked against the path.
    #[error("signing certificate check failed: {0:?}")]
    Certificate(Box<certificate::CheckError<Error, Error, NodeIdentity, DocumentIdentity, u64>>),
    /// The final B-B assembly failed.
    #[error("B-B assembly failed: {0:?}")]
    Basic(Box<baseline::BasicError<Error, NodeIdentity, DocumentIdentity, u64>>),
    /// The ASN.1 operation for binary values could not start.
    #[error("ASN.1 operation could not start: {0:?}")]
    Operation(structured_asn1::Error),
    /// The stage reports do not describe the requested level.
    #[error("baseline level assembly failed: {0:?}")]
    Level(LevelError),
    /// A countersignature's timestamp properties could not be read.
    #[error("countersignature timestamps failed: {0:?}")]
    Stamps(Box<CounterTimestampError<Error, NodeIdentity>>),
    /// Original timestamp tokens could not be decoded.
    #[error("timestamp tokens failed: {0:?}")]
    Tokens(Box<TokenPipelineError<Error, Infallible, NodeIdentity, DocumentIdentity, u64>>),
    /// Original validation material could not be decoded.
    #[error("validation material failed: {0:?}")]
    Material(Box<PipelineError<Error, Infallible, NodeIdentity, DocumentIdentity, u64>>),
    /// A signature timestamp's generation time could not be read.
    #[error("timestamp information failed: {0:?}")]
    TokenInfo(Box<ContentError<InfoError<Infallible>>>),
    /// A token's signer could not be compared with a certificate.
    #[error("timestamp signer comparison failed: {0:?}")]
    Token(structured_cms::directory::Error),
    /// A timestamp check could not complete.
    #[error("timestamp check failed: {0:?}")]
    Timestamp(Box<TimestampCheckError>),
    /// A token's generation interval could not be established.
    #[error("timestamp generation interval failed: {0:?}")]
    Time(TemporalError),
    /// A token could not be bound to its checked path.
    #[error("timestamp path binding failed: {0:?}")]
    TimestampBinding(TimestampBindingError),
    /// The document's timestamp obligations could not be derived.
    #[error("timestamp requirements failed: {0:?}")]
    Requirements(Box<RequirementError<Error, NodeIdentity>>),
    /// The timestamp obligations could not be associated with their paths.
    #[error("timestamp obligation failed: {0:?}")]
    Obligation(ObligationError<NodeIdentity>),
    /// The B-T association could not complete.
    #[error("timestamp association failed: {0:?}")]
    Timing(TimeError<NodeIdentity>),
    /// A signed credential could not be processed.
    #[error("credential processing failed: {0:?}")]
    Credentials(Box<credential::Error<Error, Infallible, NodeIdentity>>),
    /// The participant census could not be derived or linked.
    #[error("participant census failed: {0:?}")]
    Participants(ParticipantError<NodeIdentity>),
    /// Material carried in a timestamp token could not be decoded.
    #[error("carried token material failed: {0:?}")]
    Carried(Box<CarriedError<NodeIdentity, DocumentIdentity, u64>>),
    /// The artifact index could not be built.
    #[error("artifact index failed: {0:?}")]
    Index(IndexError<NodeIdentity>),
    /// A path's status inputs could not be processed.
    #[error("status processing failed: {0}")]
    Status(Box<StatusError>),
    /// The reachable status authorities could not be closed.
    #[error("authority closure failed: {0:?}")]
    Closure(ParticipantClosureError<NodeIdentity>),
    /// Material presence or placement could not be assessed. The cause borrows
    /// certificates of this scope, so its diagnostic is what remains of it.
    #[error("validation material assessment failed: {0}")]
    Placement(String),
    /// The archive census could not be completed.
    #[error("archive census failed: {0:?}")]
    Archives(ArchiveCensusError<NodeIdentity>),
    /// A `RenewedDigestsV2` property could not be processed.
    #[error("renewed digest processing failed: {0:?}")]
    Renewal(Box<renewed::CheckError<Error, Error, NodeIdentity, DocumentIdentity, u64>>),
}

/// A timestamp check that could not complete, with its original cause.
pub type TimestampCheckError =
    timestamp::CheckError<Error, NodeIdentity, DocumentIdentity, u64, CmsProviderError, Infallible>;

/// Validate the B-B level (ETSI EN 319 132-1 §6.3) of `signature`.
///
/// `signature` must be a Signature of `session`'s request. `certificates`
/// are the caller's DER certificates beyond the Signature's `KeyInfo`: the
/// trust anchors and intermediates the verification's key resolver used.
/// Each signer's path is the exact path verification validated, re-checked
/// by the shared processor; countersignatures need validated paths of their
/// own.
///
/// All limits come from the session's compiled policy: XML queries spend the
/// request's own execution, and certificate processing runs on a fresh
/// account bounded by the operation's X.509 resource and path policy, as the
/// verification's certificate processing does.
///
/// The visitor receives the assembled report; nothing borrowed from it can
/// escape. A completed negative fact returns as an [`Outcome`] variant.
///
/// # Errors
/// Returns the original cause of the stage that could not complete, and
/// [`Error::UnknownSignature`] for an identity outside the request.
pub fn validate_basic<W: Work, R>(
    session: &VerifiedSession<'_, '_, '_, W>,
    signature: NodeIdentity,
    certificates: &[&[u8]],
    visitor: impl for<'a> FnOnce(&Report<'a>) -> R,
) -> Result<Outcome<R>, ValidationError> {
    with_stage(
        session,
        signature,
        Requirements::Basic,
        [certificates, &[]],
        None,
        |_, report| Ok(Outcome::Assessed(visitor(report))),
    )
}

/// The inputs a higher level continues from, all of one verified signature.
pub(crate) struct Stage<'a, 'view, 'scope, 'inputs, W: Work> {
    pub(crate) session: &'a VerifiedSession<'view, 'scope, 'inputs, W>,
    pub(crate) document: &'a Document<'a, 'view, 'scope, 'inputs, W>,
    pub(crate) access: &'a Access<'a, Document<'a, 'view, 'scope, 'inputs, W>, W>,
    pub(crate) prepared: &'a Prepared<Document<'a, 'view, 'scope, 'inputs, W>>,
    pub(crate) counters: &'a CounterPaths<'a, 'a, NodeIdentity, DocumentIdentity, u64>,
    pub(crate) certificate: &'a CheckedPathCertificate<'a, 'a, NodeIdentity, DocumentIdentity, u64>,
    pub(crate) parser: &'a Parser,
    pub(crate) operation: &'a Reader<'a>,
    pub(crate) signer_time: Instant,
    pub(crate) stated: &'a [Stated<'a>],
    pub(crate) token_profile: TokenProfile,
}

/// What a level above B-B reads timestamp tokens with.
#[derive(Clone, Copy)]
pub(crate) struct Timing<'t> {
    pub(crate) utc: &'t LeapTable<'t>,
    pub(crate) accuracies: &'t [AuthorityAccuracy<'t>],
    pub(crate) profile: TokenProfile,
}

/// The completed negative fact of a countersignature binding, or its refusal.
fn counter_fact<R>(error: CounterError) -> Result<Outcome<R>, ValidationError> {
    match error {
        WalkError::Visitor(CounterSelectionError::Selection {
            signature,
            cause: CounterPathError::Missing(failure),
        }) => Ok(Outcome::Path { signature, failure }),
        WalkError::Visitor(CounterSelectionError::Differs { signature }) => {
            Ok(Outcome::CounterKey {
                signature,
                association: KeyAssociation::Differs,
            })
        }
        WalkError::Visitor(CounterSelectionError::Unproven { signature }) => {
            Ok(Outcome::CounterKey {
                signature,
                association: KeyAssociation::Unproven,
            })
        }
        error => Err(ValidationError::Counters(Box::new(error))),
    }
}

/// Run the B-B pipeline for the requested structural level, then `then` over
/// its assembled report. A completed negative fact stops before `then`.
pub(crate) fn with_stage<W: Work, R>(
    session: &VerifiedSession<'_, '_, '_, W>,
    signature: NodeIdentity,
    requirements: Requirements,
    certificates: [&[&[u8]]; 2],
    timing: Option<Timing<'_>>,
    then: impl for<'a> FnOnce(
        &Stage<'a, '_, '_, '_, W>,
        &Report<'a>,
    ) -> Result<Outcome<R>, ValidationError>,
) -> Result<Outcome<R>, ValidationError> {
    let work = session.execution();
    path::require_member(session, signature, work)?;

    let document = Document::new(session);
    let access = Access::new(&document, document.snapshot(), work);
    let prepared = prepare::prepare(&access, signature, requirements, None)
        .map_err(|error| ValidationError::Prepare(Box::new(error)))?;
    let fields = prepare::check_fields(&prepared, &access)
        .map_err(|error| ValidationError::Fields(Box::new(error)))?;
    let incorporated = counter::walk(&access, prepared.bound(), |binding, _| {
        Ok::<_, CounterSelectionError<CounterPathError, Error, NodeIdentity>>(
            binding.original().child(),
        )
    })
    .map_err(|error| ValidationError::Counters(Box::new(error)))?;

    let parser = session.certificate_parser();
    let x509 = parser.memory();
    let signers = path::signers(session, signature, &incorporated, x509)?;
    let decoded = path::key_info_certificates(session, &signers, x509)?;
    let candidates = path::candidates(&decoded, certificates, x509)?;
    let selection = path::select(&signers, &candidates, &parser, x509)?;
    let operation = parser.read(&[], 0).map_err(ValidationError::Operation)?;
    let verified_at = path::verification_time(&signers, signature);
    let stated = accuracy::read(&parser, timing.map_or(&[], |timing| timing.accuracies))?;
    let span = signature_span(
        &document,
        &prepared,
        &operation,
        &stated,
        timing,
        verified_at,
    )?;
    let paths = path::check(session, &selection, (signature, span), x509)?;
    let root = match paths.get(signature, x509) {
        Ok(root) => root,
        Err(CounterPathError::Missing(failure)) => {
            return Ok(Outcome::Path { signature, failure });
        }
        Err(CounterPathError::Resource(cause)) => return Err(Error::from(cause).into()),
    };

    let bound = pki::bind_counters(prepared.bound(), &access, |binding, work| {
        paths.get(binding.original().child(), work)
    });
    let counters = match bound {
        Ok(counters) => counters,
        Err(error) => return counter_fact(error),
    };
    let hashes = match hashes::check_participants(&prepared, &counters, &access)
        .map_err(|error| ValidationError::Hashes(Box::new(error)))?
    {
        ParticipantBinding::Bound(hashes) => hashes,
        ParticipantBinding::Unproven(problem) => return Ok(Outcome::Hashes(problem)),
    };
    let certificate = certificate::check_path(
        &document,
        prepared.bound(),
        prepared.certificates(),
        root,
        &document,
        work,
    )
    .map_err(|error| ValidationError::Certificate(Box::new(error)))?;
    let report = baseline::basic(
        BasicInput {
            fields: &fields,
            hashes: &hashes,
            certificate: &certificate,
            counters: &counters,
        },
        &document,
        &operation,
    )
    .map_err(|error| ValidationError::Basic(Box::new(error)))?;
    then(
        &Stage {
            session,
            document: &document,
            access: &access,
            prepared: &prepared,
            counters: &counters,
            certificate: &certificate,
            parser: &parser,
            operation: &operation,
            signer_time: verified_at.expect("a checked root path has its trust evidence"),
            stated: &stated,
            // B-B reads no token, so this choice is never consulted there.
            token_profile: timing.map_or(TokenProfile::Etsi, |timing| timing.profile),
        },
        &report,
    )
}
