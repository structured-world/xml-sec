//! Sealing a signature with an RFC 6283 evidence record (ETSI TS 119 132-3).
//!
//! [`request_evidence_record`] computes the initial archive timestamp's
//! input over the signature's protected objects (TS 119 132-3 §5.2.2) and
//! encodes the RFC 3161 request over its hash-tree root; `complete_timestamp`
//! checks the TSA response against that request, drafts the record, verifies
//! the staged record with the shared ERS kernel and publishes the generation
//! only when the document confirms the record is its one change.

use super::Judged;
use super::{
    AugmentError, Completion, Gate, PendingTimestamp, Staging, StagingError, Stamp,
    TimestampRequest, archival, construction, encode, gated, selected, unproven,
    with_response_check,
};
use crate::basic::{Outcome, ValidationError};
use crate::create::{Assessment, Carried};
use crate::draft::Draft;
use crate::evidence::{Kind, Sealing};
use crate::level::{Inputs, read_certificates, unrecognized};
use crate::path::{self, Authorities};
use crate::{Document, Error, Snapshot, accuracy};
use alloc::{boxed::Box, string::String, vec::Vec};
use core::convert::Infallible;
use structured_asn1::Reader;
use structured_asn1::memory::MemoryError;
use structured_asn1::memory::{Execution, Work};
use structured_cms::directory::{CertificateAgreement, matches_certificate_in};
use structured_cms::evidence::verify::{Decision, OrderCause, Selection};
use structured_cms::stream::{RangesError, Receiver, Source};
use structured_cms::timestamp::{CheckError, Token, interval_in};
use structured_pkix::Certificate;
use structured_pkix::algorithm::digest;
use structured_pkix::path::{Anchor, EffectiveKey, Interval};
use structured_xades::evidence::xmlers::{
    self, Archive, Authority, Check, HistoricalInput, Method, Methods, Stamp as ArchiveStamp,
};
use structured_xades::evidence::{
    self as records, Edit, EditError, EditPlan, Format, InitialError, InitialImprint, ObjectError,
    Placement, SealingWriter,
};
use structured_xades::material::{self, Value};
use structured_xades::produce::{Event, Transaction, Writer};
use structured_xades::timestamp;
use structured_xades::xml::{Access, Xml};
use xml_sec::document::{DocumentIdentity, NodeIdentity, XmlDocument};
use xml_sec::xmldsig::cms::{CmsProvider, CmsProviderError};
use xml_sec::xmldsig::{DigestAlgorithm, with_verified_request};

/// RFC 6283 §2.1 leaves the chain's canonicalization to the producer; this
/// one applies only to later renewals of the record.
const EXCLUSIVE_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

/// Which evidence record a seal adds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealKind {
    /// The signature's first `SealingEvidenceRecords` property.
    Initial,
    /// One more record in the last `SealingEvidenceRecords`, parallel to
    /// the records already there: the same protected input, from another
    /// TSA or under another digest (ETSI TS 119 132-3 §5.1.1).
    Parallel,
}

/// Why an evidence record could not be added.
#[derive(Debug)]
pub enum EvidenceError {
    /// The signature's sealing properties could not be read.
    Records(records::Error<Error, NodeIdentity>),
    /// The shared rules refused the seal at this place.
    Edit(EditError<Error, NodeIdentity>),
    /// An initial seal was asked of a sealed signature, or a parallel record
    /// of an unsealed one.
    Kind(SealKind),
    /// The protected objects could not be replayed.
    Objects(ObjectError<Error, NodeIdentity>),
    /// The hash-tree root could not be computed.
    Imprint(InitialError<Error, NodeIdentity, CmsProviderError>),
    /// The TSA response could not be checked.
    Response(CheckError<RangesError, CmsProviderError, Infallible>),
    /// The staged record could not be verified.
    Verification(Box<VerifyError>),
    /// The staged record verified with these failures.
    Unverified(Vec<RecordFailure>),
}

/// The shared ERS kernel's refusal of a staged record.
pub type VerifyError = xmlers::CheckError<
    Error,
    NodeIdentity,
    DocumentIdentity,
    u64,
    CmsProviderError,
    SignerError,
    Infallible,
    Error,
>;

/// A token of a staged record that verified negatively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordFailure {
    /// No positive mathematical evidence for the token.
    Token(NodeIdentity),
    /// The token is not in the order its renewal states.
    Order(NodeIdentity, OrderCause),
    /// The token's signer has no accepted path or algorithm.
    Historical(NodeIdentity, Decision),
}

impl From<&xmlers::Failure<NodeIdentity>> for RecordFailure {
    fn from(failure: &xmlers::Failure<NodeIdentity>) -> Self {
        match *failure {
            xmlers::Failure::Token(node) => Self::Token(node),
            xmlers::Failure::Order(node, cause) => Self::Order(node, cause),
            xmlers::Failure::Historical(node, decision) => Self::Historical(node, decision),
        }
    }
}

impl From<EvidenceError> for AugmentError {
    fn from(error: EvidenceError) -> Self {
        Self::Evidence(Box::new(error))
    }
}

type Plan = EditPlan<NodeIdentity, DocumentIdentity, u64>;

/// Compute the initial archive timestamp input of a new `kind` evidence
/// record for `request.signature` and encode the RFC 3161 request over it.
///
/// The signature must meet `inputs.requirements`, B-LT or B-LTA, under
/// `assessment`: ETSI TS 119 132-3 §5.1.2 requires every validation datum of
/// the signed components before the first seal, which B-LT holds, and the
/// E-ERS level of §6.3 a `SignatureTimeStamp`. The record protects the data
/// objects, `SignedInfo`, `SignatureValue`, `KeyInfo`, every unsigned property
/// and every other `Object` of the signature (§5.2.2.1). Pass the response
/// to `complete_timestamp`.
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
///     Assessment, Completion, Inputs, Requirements, SealKind, TimestampRequest,
///     complete_timestamp, request_evidence_record,
/// };
/// # fn seal(
/// #     document: &mut xml_sec::XmlDocument,
/// #     assessment: &Assessment<'_, '_>,
/// #     evidence: &Inputs<'_>,
/// #     tsa: impl Fn(&[u8]) -> Vec<u8>,
/// #     work: &structured_asn1::memory::Memory,
/// # ) -> Result<(), xml_sec_xades::AugmentError> {
/// let inputs = Inputs { requirements: Requirements::LongTerm, ..*evidence };
/// let pending = request_evidence_record(
///     document,
///     &TimestampRequest {
///         signature: "sig",
///         digest: Algorithm::Sha256,
///         policy: None,
///         nonce: Some(&[0x2a; 8]),
///         id_attributes: &[],
///     },
///     SealKind::Initial,
///     assessment,
///     &inputs,
///     work,
/// )?;
/// let response = tsa(pending.request());
/// complete_timestamp(
///     document,
///     &pending,
///     &response,
///     &Completion { assessment, inputs: &inputs, window: None, id_attributes: &[] },
///     work,
/// )
/// # }
/// ```
pub fn request_evidence_record<W: Work>(
    document: &XmlDocument,
    request: &TimestampRequest<'_>,
    kind: SealKind,
    assessment: &Assessment<'_, '_>,
    inputs: &Inputs<'_>,
    work: &W,
) -> Result<PendingTimestamp, AugmentError> {
    let certificates = archival(inputs, assessment, work)?;
    let inputs = Inputs {
        certificates: &certificates,
        ..*inputs
    };
    let gate = Gate::LongTerm(&inputs);
    let (identity, generation) = document.with_view(|view| (view.identity(), view.generation()));
    let encoded = with_verified_request(
        document,
        assessment.context,
        assessment.request,
        work,
        |session| {
            Ok(
                selected(document, &session, request.signature, request.id_attributes).and_then(
                    |node| {
                        gated(&session, node, &gate, |stage, level| {
                            met(level)?;
                            with_input(stage, kind, request.digest, |_, imprint| {
                                encode(stage.parser, request, imprint.root().as_bytes())
                            })
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
        kind: Stamp::Seal(kind),
        basis: gate.requirements(),
        request: encoded,
        renewal: None,
        repeat: Some(super::Repeat::of(request)),
    })
}

/// The record a checked response yields, drafted over the starting generation.
struct Drafted {
    base: Snapshot,
    signature: NodeIdentity,
    plan: Plan,
    markup: String,
    /// The certificates the token carries, which may hold its signer and the
    /// path to it.
    carried: Vec<Vec<u8>>,
}

/// Check `response`, draft its record, append it and publish the generation
/// once the staged record verifies and is the document's one change.
pub(super) fn complete<W: Work>(
    document: &mut XmlDocument,
    pending: &PendingTimestamp,
    kind: SealKind,
    response: &[u8],
    completion: &Completion<'_, '_>,
    [inputs, basis]: [&Inputs<'_>; 2],
    work: &W,
) -> Result<(), AugmentError> {
    let assessment = completion.assessment;
    let signature = pending.signature.as_str();
    let digest = pending
        .repeat
        .as_ref()
        .map(|repeat| repeat.digest)
        .ok_or(AugmentError::Changed)?;
    document.transaction(|document| {
        let drafted = with_verified_request(
            document,
            assessment.context,
            assessment.request,
            work,
            |session| {
                Ok(
                    selected(document, &session, signature, completion.id_attributes).and_then(
                        |node| {
                            gated(&session, node, &Gate::LongTerm(basis), |stage, level| {
                                met(level)?;
                                drafted(stage, kind, digest, pending, response, completion)
                            })
                        },
                    ),
                )
            },
        )??;
        let parent = match drafted.plan.placement() {
            Placement::Serial(Some(parent)) | Placement::Parallel(parent) => parent,
            // B-LT has unsigned signature properties, and this crate drafts
            // no renewal.
            Placement::Serial(None) | Placement::Renew(..) => {
                return Err(EvidenceError::Kind(kind).into());
            }
        };
        document.append_child(parent, &drafted.markup)?;
        let sealing = Sealing {
            base: drafted.base,
            kind: match kind {
                SealKind::Initial => Kind::Serial,
                SealKind::Parallel => Kind::Parallel,
            },
            signature: [drafted.signature, document.carry(drafted.signature)?],
            parent,
            appended: document.appended_child(parent)?,
        };
        let carried = Carried::new::<_, AugmentError>(document, assessment.request, work)?;
        with_verified_request(
            document,
            assessment.context,
            &carried.request(assessment.request),
            work,
            |session| {
                Ok(
                    selected(document, &session, signature, completion.id_attributes).and_then(
                        |node| {
                            gated(&session, node, &Gate::LongTerm(inputs), |stage, level| {
                                met(level)?;
                                committed(stage, sealing, &drafted, inputs)
                            })
                        },
                    ),
                )
            },
        )?
    })
}

/// Refuse a level whose requirements are not all met. A timestamp's input is
/// refused by the shared rules on that ground; a seal's is computed here.
fn met(level: Judged<'_, '_>) -> Result<(), AugmentError> {
    if level.all_requirements_met() {
        Ok(())
    } else {
        Err(AugmentError::Unmet(Outcome::Assessed(())))
    }
}

/// Run `then` over the plan and initial imprint of a new `kind` record.
fn with_input<W: Work, R>(
    stage: &crate::basic::Stage<'_, '_, '_, '_, W>,
    kind: SealKind,
    algorithm: digest::Algorithm,
    then: impl for<'p> FnOnce(Plan, &InitialImprint<'p, CmsProvider<'p>>) -> Result<R, AugmentError>,
) -> Result<R, AugmentError> {
    let execution = stage.session.execution();
    let census =
        records::read(stage.access, stage.prepared.bound()).map_err(EvidenceError::Records)?;
    let (edit, existing) = match (kind, census.groups().last()) {
        (SealKind::Initial, None) => (Edit::Serial(Format::Xml), None),
        (SealKind::Parallel, Some(group)) => {
            (Edit::Parallel(Format::Xml), Some(group.members().start))
        }
        _ => return Err(EvidenceError::Kind(kind).into()),
    };
    let plan = census
        .edit(stage.access, edit, None)
        .map_err(EvidenceError::Edit)?;
    let mut objects = match existing {
        None => census.serial_objects(stage.document, execution),
        Some(index) => census.objects(stage.document, index, execution),
    }
    .map_err(EvidenceError::Objects)?;
    let cms = stage.session.cms_provider();
    let imprint = objects
        .initial_imprint(&cms, algorithm, execution)
        .map_err(EvidenceError::Imprint)?;
    then(plan, &imprint)
}

/// The record of a checked `response` over the stage's generation, drafted.
fn drafted<W: Work>(
    stage: &crate::basic::Stage<'_, '_, '_, '_, W>,
    kind: SealKind,
    algorithm: digest::Algorithm,
    pending: &PendingTimestamp,
    response: &[u8],
    completion: &Completion<'_, '_>,
) -> Result<Drafted, AugmentError> {
    let method = DigestAlgorithm::from_pkix(algorithm).ok_or(AugmentError::UnsupportedDigest)?;
    with_input(stage, kind, algorithm, |plan, imprint| {
        with_response_check(stage, pending, response, completion, |check, status| {
            let hashes: Vec<&[u8]> = imprint.hashes().collect();
            let checked = check
                .response
                .check(
                    check.provider,
                    check.query,
                    check.context,
                    &mut Concatenated(&hashes),
                    unrecognized(),
                )
                .map_err(EvidenceError::Response)?;
            if checked
                .timestamp()
                .and_then(|token| token.evidence())
                .is_none()
            {
                return Err(unproven(&checked, status));
            }
            let token = check
                .response
                .token_element()
                .ok_or(AugmentError::Refused(status))?
                .as_bytes();
            let carried = check
                .response
                .token()
                .map(|token| {
                    token
                        .message()
                        .certificates()
                        .iter()
                        .map(|certificate| certificate.as_bytes().to_vec())
                        .collect()
                })
                .unwrap_or_default();
            let base = stage.document.snapshot();
            let signature = stage.prepared.bound().containers().signature();
            let parent = match plan.placement() {
                Placement::Serial(parent) => parent,
                Placement::Parallel(group) => Some(group),
                Placement::Renew(..) => None,
            };
            let mut sealer = Sealer {
                staging: Staging {
                    session: stage.session,
                    base,
                    signature,
                    unsigned: parent,
                    draft: Draft::new(),
                },
                placement: plan.placement(),
            };
            plan.write_xml(
                &mut sealer,
                Archive {
                    methods: Some(Methods {
                        digest: Method::Uri(method.uri()),
                        canonicalization: Method::Uri(EXCLUSIVE_C14N),
                    }),
                    // ETSI TS 119 132-3 §5.2.2.1: the first list holds the
                    // digest value of the whole group of data objects.
                    first_hashes: &[imprint.root().as_bytes()],
                    token,
                },
                stage.session.execution(),
            )
            .map_err(construction)?;
            Ok(Drafted {
                base,
                signature,
                plan,
                markup: sealer.staging.draft.finish()?.0,
                carried,
            })
        })
    })
}

/// Verify the staged record with the shared ERS kernel and authorize its
/// commit against the document's own record of the change.
fn committed<W: Work>(
    stage: &crate::basic::Stage<'_, '_, '_, '_, W>,
    sealing: Sealing,
    drafted: &Drafted,
    inputs: &Inputs<'_>,
) -> Result<(), AugmentError> {
    let owner = Document::sealed(stage.session, sealing);
    let execution = stage.session.execution();
    let access = Access::new(&owner, owner.snapshot(), execution);
    let census = records::read(&access, stage.prepared.bound()).map_err(EvidenceError::Records)?;
    let carried: Vec<&[u8]> = drafted.carried.iter().map(Vec::as_slice).collect();
    let held = document_certificates(stage)?;
    let held: Vec<&[u8]> = held.iter().map(Vec::as_slice).collect();
    let parser = stage.parser;
    let anchors = read_certificates(parser, inputs.anchors)?;
    let supplied = read_certificates(parser, inputs.certificates)?;
    let carried = read_certificates(parser, &carried)?;
    let held = read_certificates(parser, &held)?;
    let mut anchored = parser.memory().vector();
    let mut pool = parser.memory().vector();
    for anchor in &anchors {
        anchored.try_push(Anchor::from_certificate(anchor))?;
    }
    // Candidates only: a path still has to end at one of `anchors`.
    for certificate in supplied.iter().chain(&carried).chain(&held).chain(&anchors) {
        pool.try_push(certificate)?;
    }
    let authorities = Authorities {
        anchors: &anchors,
        anchored: &anchored,
        pool: &pool,
        responders: inputs.responders,
        memory: parser.memory(),
    };
    let parent = parser.read(&[], 0).map_err(AugmentError::Asn1)?;
    let stated = accuracy::read(parser, inputs.accuracies)?;
    let candidates = Candidates {
        certificates: &pool,
        parent: &parent,
        stated: &stated,
        operation: stage.operation,
    };
    let cms = stage.session.cms_provider();
    let report = Check {
        provider: &cms,
        operation: stage.operation,
        authorities: &candidates,
        utc: inputs.utc,
        reference: stage.signer_time,
    }
    .xml(
        &owner,
        &census,
        drafted.plan.member_index(),
        |_, _, _| Ok::<_, Infallible>(false),
        |input, work| decision(stage, &authorities, &pool, inputs, &input, work),
    )
    .map_err(|error| EvidenceError::Verification(Box::new(error)))?;
    let proof = report.verified().ok_or_else(|| {
        EvidenceError::Unverified(report.failures().iter().map(RecordFailure::from).collect())
    })?;
    drafted
        .plan
        .authorize_commit(&access, &census, &proof)
        .map_err(EvidenceError::Edit)?;
    Ok(())
}

/// The certificates the document already holds, in its values, their OCSP
/// responses and its timestamp tokens: the pool a level assessment builds
/// paths over, copied out of the readers that own them.
fn document_certificates<W: Work>(
    stage: &crate::basic::Stage<'_, '_, '_, '_, W>,
) -> Result<Vec<Vec<u8>>, AugmentError> {
    let stamps = timestamp::counter_timestamps(stage.access, stage.counters)
        .map_err(|error| ValidationError::Stamps(Box::new(error)))?;
    timestamp::with_counter_tokens(
        stage.document,
        stage.prepared,
        &stamps,
        stage.operation,
        stage.token_profile,
        |operation, tokens| {
            Ok::<_, Infallible>(
                material::with_counter_values(
                    stage.document,
                    stage.prepared,
                    stage.counters,
                    operation,
                    |_, view| {
                        let mut held = Vec::new();
                        for value in view.values() {
                            if let Value::Certificate(certificate) = &value.value {
                                held.push(certificate.as_bytes().to_vec());
                            }
                        }
                        for basic in view.basic_responses() {
                            for certificate in basic.response().certificates() {
                                held.push(certificate.as_bytes().to_vec());
                            }
                        }
                        for reading in tokens.readings() {
                            for certificate in reading.token().message().certificates() {
                                held.push(certificate.as_bytes().to_vec());
                            }
                        }
                        Ok::<_, Infallible>(held)
                    },
                )
                .map_err(|error| ValidationError::Material(Box::new(error))),
            )
        },
    )
    .map_err(|error| ValidationError::Tokens(Box::new(error)))?
    .map_err(AugmentError::from)
}

/// The historical decision on a staged record's token: its signer has a
/// checked path to a caller anchor over the token's generation interval.
///
/// The level of a timestamped signature binds each token to such a path and
/// keeps the path's statuses as facts for the caller; the same holds here.
/// Before a later timestamp the record's validation data is incorporated
/// (ETSI TS 119 132-3 §5.1.2), which is when its statuses are archived.
fn decision<'d, W: Work>(
    stage: &crate::basic::Stage<'_, '_, '_, '_, W>,
    authorities: &Authorities<'d>,
    pool: &[&'d Certificate<'d>],
    inputs: &Inputs<'_>,
    input: &HistoricalInput<'_, '_, NodeIdentity>,
    work: &Execution<'_>,
) -> Result<Decision, Error> {
    let Some(evidence) = input.evidence.current.evidence() else {
        return Ok(Decision::Unknown);
    };
    let facts = evidence.facts();
    let Ok(generation) = interval_in(
        facts.gen_time(),
        facts
            .effective_accuracy()
            .map(structured_cms::timestamp::EffectiveAccuracy::accuracy),
        inputs.utc,
        work,
    ) else {
        return Ok(Decision::Unknown);
    };
    // The selection borrows the kernel's scope; the same certificate of
    // this operation's pool is the one a path is built for.
    let signer = input.evidence.selection.certificate.as_bytes();
    let Some(target) = pool
        .iter()
        .find(|certificate| certificate.as_bytes() == signer)
    else {
        return Ok(Decision::Unknown);
    };
    let interval = Interval::between_instants(generation.earliest, generation.latest);
    Ok(
        match path::discover(stage.session, authorities, target, interval)? {
            Ok(_) => Decision::Valid,
            Err(_) => Decision::Unknown,
        },
    )
}

/// The certificates a staged token's signer is chosen from, all owned by
/// this operation.
struct Candidates<'c> {
    certificates: &'c [&'c Certificate<'c>],
    parent: &'c Reader<'c>,
    stated: &'c [accuracy::Stated<'c>],
    operation: &'c Reader<'c>,
}

/// Why no signer was selected for a staged token.
#[derive(Debug)]
pub enum SignerError {
    /// No certificate of the caller's or the token's is the named signer.
    Missing,
    /// A certificate could not be compared with the signer's identifier.
    Comparison(structured_cms::directory::Error),
    /// The current execution refused work.
    Resource(MemoryError),
    /// The token's accuracy could not be matched with the caller's stated
    /// accuracies.
    Accuracy(Box<ValidationError>),
}

impl Authority<NodeIdentity> for Candidates<'_> {
    type Error = SignerError;

    fn select<'a, W: Work>(
        &'a self,
        _stamp: &ArchiveStamp<NodeIdentity>,
        token: &Token<'_>,
        reader: &Reader<'_>,
        work: &W,
    ) -> Result<Selection<'a>, Self::Error> {
        let named = token.signer().sid();
        for &certificate in self.certificates {
            work.charge_work(1).map_err(SignerError::Resource)?;
            if matches!(
                matches_certificate_in(named, certificate, self.parent)
                    .map_err(SignerError::Comparison)?,
                CertificateAgreement::Matches
            ) {
                let policy_accuracy =
                    accuracy::select_outside(self.stated, token, reader, self.operation)
                        .map_err(|error| SignerError::Accuracy(Box::new(error)))?;
                return Ok(Selection {
                    certificate,
                    certificate_parent: self.parent,
                    key: EffectiveKey::standing(certificate.tbs().public_key()),
                    policy_accuracy,
                });
            }
        }
        Err(SignerError::Missing)
    }
}

/// The sorted object digests of an initial archive timestamp, concatenated:
/// the input whose digest is the hash-tree root (RFC 6283 §3.2).
struct Concatenated<'a>(&'a [&'a [u8]]);

impl Source for Concatenated<'_> {
    type Error = RangesError;

    fn stream<W: Work>(
        &mut self,
        receiver: &mut impl Receiver,
        work: &W,
    ) -> Result<(), RangesError> {
        for digest in self.0 {
            work.charge_work(1).map_err(RangesError::Resource)?;
            receiver.write(digest).map_err(RangesError::Receiver)?;
        }
        Ok(())
    }
}

/// The unpublished record of one seal, at the place its plan names.
struct Sealer<'s, 'v, 'sc, 'i, W: Work> {
    staging: Staging<'s, 'v, 'sc, 'i, W>,
    placement: Placement<NodeIdentity>,
}

impl<W: Work> Writer for Sealer<'_, '_, '_, '_, W> {
    type Error = StagingError;

    fn write<Q: Work>(&mut self, event: Event<'_>, work: &Q) -> Result<(), StagingError> {
        self.staging.write(event, work)
    }
}

impl<W: Work> Transaction for Sealer<'_, '_, '_, '_, W> {
    type Id = NodeIdentity;
    type Document = DocumentIdentity;
    type Generation = u64;

    fn base(&self) -> Snapshot {
        self.staging.base()
    }

    fn signature(&self) -> NodeIdentity {
        self.staging.signature()
    }

    fn unsigned_parent(&self) -> Option<NodeIdentity> {
        self.staging.unsigned_parent()
    }

    fn method<Q: Work>(&mut self, method: NodeIdentity, work: &Q) -> Result<(), StagingError> {
        self.staging.method(method, work)
    }
}

impl<W: Work> SealingWriter for Sealer<'_, '_, '_, '_, W> {
    fn sealing_placement(&self) -> Placement<NodeIdentity> {
        self.placement
    }
}
