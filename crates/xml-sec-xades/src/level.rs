//! One requested baseline level over its complete linked stage reports.

use alloc::{boxed::Box, format};
use core::convert::Infallible;

use crate::accuracy::{self, AuthorityAccuracy, Stated};
use crate::basic::{Stage, Timing, ValidationError, with_stage};
use crate::path::{self, Authorities, PathFailure};
use crate::status::{self, StatusError};
use crate::{Document, Error, Outcome, Report};
use structured_asn1::memory::{Execution, Memory, OwnedVec, Work};
use structured_asn1::{Parser, Reader};
use structured_cms::directory::{CertificateAgreement, matches_certificate_in};
use structured_cms::timestamp::{
    CheckContext, IntervalError, PolicyAccuracy, TokenExtension, interval_in,
};
use structured_ltv::baseline::{self as composed, LongTerm, Timed};
use structured_ltv::credential::Authentication;
use structured_ltv::material::Coverage;
use structured_ltv::pki::{
    AuthorityNode, CheckedPath, ParticipantAuthority, ParticipantRequirements, PathStatuses,
    TimestampBinding, TimestampBindingFailure, TimestampPath,
};
use structured_ltv::timestamp::{
    CheckedActor, TimestampPathBinding, TimestampPathFailure, TimestampPaths,
    TimestampRequirements, Verified,
};
use structured_pkix::Certificate;
use structured_pkix::crl::CertificateList;
use structured_pkix::ocsp::{BasicResponse, Response};
use structured_pkix::path::{Anchor, Interval, WorkingKey};
use structured_pkix::temporal::{Instant, LeapTable};
use structured_xades::Xades;
use structured_xades::baseline::{self, Assessment, Evidence};
use structured_xades::certificate::CheckedPathCertificate;
use structured_xades::credential::{self, ParticipantCredentials};
use structured_xades::material::credentials::Scope;
use structured_xades::material::{self, Index, Value, View};
use structured_xades::pki as xades_pki;
use structured_xades::prepare::Prepared;
use structured_xades::reference::VisitError;
use structured_xades::renewed::{self, PairCheck, PairOutcome};
use structured_xades::timestamp::{
    self, CarriedMaterial, Check, Input, RequirementError, Role, TimestampSelection, TokenProfile,
    TokenView,
};
use structured_xades::unsigned::Requirements;
use structured_xades::xml::{Access, Xml};
use xml_sec::document::{DocumentIdentity, NodeIdentity};
use xml_sec::xmldsig::cms::CmsProvider;
use xml_sec::xmldsig::{VerifiedSession, X509ChainError};

type N = NodeIdentity;
type D = DocumentIdentity;
type G = u64;

/// A signed credential's authentication receipt. No format is selected here,
/// so a document carrying one is refused rather than given an evidence value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoCredential {}

/// The stage reports of one requested level. Inspect their detailed findings:
/// [`Assessment::all_requirements_met`] states that the requested structure
/// holds, not that a status is usable, a chronology holds or a signer is trusted.
pub type Level<'a> = Assessment<'a, NoCredential, N, D, G>;

/// Caller evidence of one baseline validation. Nothing here is discovered or
/// fetched: this is the whole outside world the validation sees.
#[derive(Clone, Copy)]
pub struct Inputs<'a> {
    /// The structural level to establish.
    pub requirements: Requirements,
    /// How timestamp tokens are read. [`TokenProfile::Cms`] takes RFC 5652 BER,
    /// so a met level then asserts nothing about EN 319 132-1 §5.1.3;
    /// [`TokenProfile::Etsi`] holds each token to its declared encoding.
    pub token_profile: TokenProfile,
    /// DER certificates that end timestamp and revocation-authority paths.
    pub anchors: &'a [&'a [u8]],
    /// Further DER certificates a path may use, beyond the document's.
    pub certificates: &'a [&'a [u8]],
    /// Caller-authenticated UTC facts with explicit coverage.
    pub utc: &'a LeapTable<'a>,
    /// Policy accuracy of the authorities whose tokens omit the field. A token
    /// neither stating accuracy nor listed here has no generation interval.
    pub accuracies: &'a [AuthorityAccuracy<'a>],
    /// OCSP responders the caller trusts for one issuer's certificates.
    pub responders: &'a [ConfiguredResponder<'a>],
    /// DER CRLs the caller obtained itself. They answer status, but only what
    /// the document incorporates counts toward a level.
    pub crls: &'a [&'a [u8]],
    /// DER `OCSPResponse` values the caller obtained itself, read as `crls` are.
    pub responses: &'a [&'a [u8]],
}

/// Local configuration of an OCSP signing authority (RFC 6960 §4.2.2.2): this
/// responder answers for this issuer, without a delegation certificate.
#[derive(Clone, Copy)]
pub struct ConfiguredResponder<'a> {
    /// DER certificate of the responder.
    pub responder: &'a [u8],
    /// DER certificate of the issuer it answers for.
    pub issuer: &'a [u8],
}

/// A timestamp token with no usable evidence for this request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampFailure {
    /// No available certificate is the one the token names as its signer.
    MissingSigner,
    /// The token's imprint, signature or profile facts did not hold.
    Rejected,
    /// The signer has no accepted path over the token's generation interval.
    Path(PathFailure),
    /// The checked path does not belong to the token's actual signer.
    Binding(TimestampBindingFailure),
    /// The checked paths do not answer every token of the document.
    Census(TimestampPathFailure),
}

/// Why a `RenewedDigestsV2` property does not confirm its detached object
/// (EN 319 132-1 §5.5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalFailure {
    /// The object's digest under the new algorithm differs from the declared one.
    Differs,
    /// No single detached `Manifest` reference matches the declared digest.
    Unbound,
    /// The property's digest method or `Manifest` cannot support a renewal.
    Unusable,
}

/// What the first unconfirmed pair of `report` says.
fn renewal_failure<E>(pairs: &[PairCheck<N, E>]) -> RenewalFailure {
    let failed = pairs
        .iter()
        .find(|pair| !matches!(pair.outcome, PairOutcome::Matches));
    match failed.map(|pair| &pair.outcome) {
        Some(PairOutcome::Differs) => RenewalFailure::Differs,
        Some(
            PairOutcome::MissingReference
            | PairOutcome::AmbiguousReference
            | PairOutcome::NotDetached,
        ) => RenewalFailure::Unbound,
        _ => RenewalFailure::Unusable,
    }
}

/// The first `RenewedDigestsV2` property that does not confirm its object.
fn unconfirmed_renewal<W: Work>(
    stage: &Stage<'_, '_, '_, '_, W>,
) -> Result<Option<(N, RenewalFailure)>, ValidationError> {
    let renewals = renewed::check_prepared(
        stage.document,
        stage.prepared,
        stage.document,
        stage.session.execution(),
    )
    .map_err(|error| ValidationError::Renewal(Box::new(error)))?;
    let report = renewals.reports().iter().find(|report| !report.agrees());
    Ok(report.map(|report| (report.property(), renewal_failure(report.pairs()))))
}

/// Validate the requested baseline level (ETSI EN 319 132-1 §6.3) of `signature`.
///
/// The visitor receives the level's reports; nothing borrowed from them can
/// escape. All limits come from the session's compiled policy.
///
/// # Errors
/// Returns the original cause of the stage that could not complete.
pub fn validate<W: Work, R>(
    session: &VerifiedSession<'_, '_, '_, W>,
    signature: N,
    inputs: &Inputs<'_>,
    visitor: impl for<'a> FnOnce(&Level<'a>) -> R,
) -> Result<Outcome<R>, ValidationError> {
    let requirements = inputs.requirements;
    let timing = (requirements != Requirements::Basic).then_some(Timing {
        utc: inputs.utc,
        accuracies: inputs.accuracies,
        profile: inputs.token_profile,
    });
    with_stage(
        session,
        signature,
        requirements,
        // Verification's own path may end at any of them or pass through any of
        // them; only `anchors` end the paths this validation builds itself.
        [inputs.anchors, inputs.certificates],
        timing,
        |stage, basic| {
            if requirements == Requirements::Basic {
                let level =
                    baseline::assess(Evidence::Basic(basic)).map_err(ValidationError::Level)?;
                return Ok(Outcome::Assessed(visitor(&level)));
            }
            timed(stage, basic, inputs, visitor)
        },
    )
}

type TokenActor<'c, 'd> = CheckedActor<'c, 'd, N, D, G, Xades>;
type TsaPath<'v, 'c, 'd> = TimestampPath<'v, 'c, 'd, N, D, G, Xades>;
type Stamps = timestamp::CounterTimestamps<N, D, G>;
type Tokens<'s> = TokenView<'s, N, D, G>;
type Material<'s> = View<'s, N, D, G>;
type Required = TimestampRequirements<N, D, G, Xades>;
type Actors<'a> = ParticipantRequirements<'a, 'a, N, D, G, Xades>;
type Credentials<'a> = ParticipantCredentials<'a, 'a, NoCredential, N, D, G>;
type TimedReport<'a> =
    Timed<'a, 'a, 'a, Report<'a>, CheckedPathCertificate<'a, 'a, N, D, G>, N, D, G, Xades>;
type LongTermReport<'a> = LongTerm<
    'a,
    TimedReport<'a>,
    material::Checks<'a, 'a, 'a, 'a, 'a, N, D, G>,
    material::credentials::Report<'a, 'a, 'a, NoCredential, N, D, G>,
>;

/// The token and material pools, frozen for the rest of the validation.
struct Pools<'p, 't> {
    stamps: &'p Stamps,
    operation: &'p Reader<'t>,
    tokens: &'p Tokens<'t>,
    view: &'p Material<'t>,
}

fn timed<W: Work, R>(
    stage: &Stage<'_, '_, '_, '_, W>,
    basic: &Report<'_>,
    inputs: &Inputs<'_>,
    visitor: impl for<'a> FnOnce(&Level<'a>) -> R,
) -> Result<Outcome<R>, ValidationError> {
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
                    |operation, view| {
                        let pools = Pools {
                            stamps: &stamps,
                            operation,
                            tokens: &tokens,
                            view: &view,
                        };
                        Ok::<_, Infallible>(frozen(stage, basic, inputs, &pools, visitor))
                    },
                )
                .map_err(|error| ValidationError::Material(Box::new(error)))
                .and_then(core::convert::identity),
            )
        },
    )
    .map_err(|error| ValidationError::Tokens(Box::new(error)))?
}

/// Every certificate a path may use, whatever carried it. Being here proves
/// nothing: a path still has to end at a caller anchor.
fn certificate_pool<'p, 't>(
    pools: &'p Pools<'p, 't>,
    supplied: &'p [Certificate<'t>],
    memory: &Memory,
) -> Result<OwnedVec<&'p Certificate<'t>>, Error> {
    let mut pool = memory.vector();
    for value in pools.view.values() {
        if let Value::Certificate(certificate) = &value.value {
            pool.try_push(certificate)?;
        }
    }
    for basic in pools.view.basic_responses() {
        for certificate in basic.response().certificates() {
            pool.try_push(certificate)?;
        }
    }
    for reading in pools.tokens.readings() {
        for certificate in reading.token().message().certificates() {
            pool.try_push(certificate)?;
        }
    }
    for certificate in supplied {
        pool.try_push(certificate)?;
    }
    Ok(pool.into_owned())
}

/// A completed negative fact about one timestamp property.
type TokenFailure = (N, TimestampFailure);

/// The certificate token `ordinal` names as its signer, with its own reader.
fn token_signer<'p, 't>(
    pools: &'p Pools<'p, 't>,
    ordinal: usize,
    supplied: &'p [Certificate<'t>],
    supplied_parent: &'p Reader<'t>,
) -> Result<Option<(&'p Certificate<'t>, &'p Reader<'t>)>, ValidationError> {
    let reading = &pools.tokens.readings()[ordinal];
    let named = reading.token().signer().sid();
    let carried = reading.token().message().certificates();
    for (certificates, parent) in [(carried, reading.reader()), (supplied, supplied_parent)] {
        for certificate in certificates {
            if matches!(
                matches_certificate_in(named, certificate, parent)
                    .map_err(ValidationError::Token)?,
                CertificateAgreement::Matches
            ) {
                return Ok(Some((certificate, parent)));
            }
        }
    }
    Ok(None)
}

/// No token extension is recognized, so a critical one refuses its token.
fn unrecognized() -> impl FnMut(&TokenExtension<'_>, &Execution<'_>) -> Result<bool, Infallible> {
    |_, _| Ok(false)
}

/// Check every token of the document with its named signer's own key.
fn token_actors<'p, 't, W: Work>(
    stage: &'p Stage<'_, '_, '_, '_, W>,
    inputs: &'p Inputs<'t>,
    pools: &'p Pools<'p, 't>,
    supplied: &'p [Certificate<'t>],
    supplied_parent: &'p Reader<'t>,
    cms: &CmsProvider<'_>,
) -> Result<Result<OwnedVec<TokenActor<'p, 't>>, TokenFailure>, ValidationError> {
    let Pools {
        stamps,
        operation,
        tokens,
        ..
    } = *pools;
    let roots = stage.prepared.timestamps();
    let mut actors = stage.parser.memory().vector();
    actors
        .try_reserve_exact(tokens.sources().len())
        .map_err(Error::from)?;
    for ordinal in 0..tokens.sources().len() {
        let source = &tokens.sources()[ordinal];
        let Some((certificate, parent)) = token_signer(pools, ordinal, supplied, supplied_parent)?
        else {
            return Ok(Err((source.property(), TimestampFailure::MissingSigner)));
        };
        let reading = &tokens.readings()[ordinal];
        let policy_accuracy = accuracy::select_outside(
            stage.stated,
            reading.token(),
            reading.reader(),
            stage.operation,
        )?;
        let context = CheckContext {
            certificate,
            certificate_parent: parent,
            key: WorkingKey::standing(certificate.tbs().public_key()),
            // An incorporated token is archived evidence: this instant only
            // refuses one generated after the time being validated at.
            requested: None,
            utc: inputs.utc,
            reference: Some(stage.signer_time),
            window: None,
            policy_accuracy,
        };
        let check = Check {
            xml: stage.document,
            provider: cms,
            context: &context,
        };
        let actor = if let Some(stamp) = roots.get(source.stamp_index()) {
            check.retain_actor(
                stage.prepared.bound(),
                stamp,
                source.token_index(),
                operation,
                unrecognized(),
            )
        } else {
            let counter = &stamps.entries()[source.stamp_index() - roots.len()];
            let entry = tokens.entry(ordinal).expect("ordinal within the pool");
            check.retain_counter_from(counter, entry, operation, unrecognized())
        }
        .map_err(|error| ValidationError::Timestamp(Box::new(error)))?;
        let Some(actor) = actor else {
            return Ok(Err((source.property(), TimestampFailure::Rejected)));
        };
        actors.try_push(actor).map_err(Error::from)?;
    }
    Ok(Ok(actors.into_owned()))
}

/// Each actor's path over its token's whole stated generation interval.
fn actor_paths<'d, W: Work>(
    session: &VerifiedSession<'_, '_, '_, W>,
    authorities: &Authorities<'d>,
    actors: &'d [TokenActor<'d, 'd>],
    utc: &LeapTable<'_>,
) -> Result<Result<OwnedVec<CheckedPath<'d>>, TokenFailure>, ValidationError> {
    let memory = authorities.memory;
    let mut checked = memory.vector();
    checked
        .try_reserve_exact(actors.len())
        .map_err(Error::from)?;
    for actor in actors {
        let generation = actor
            .verified()
            .interval(utc, memory)
            .map_err(ValidationError::Time)?;
        let interval = Interval::between_instants(generation.earliest, generation.latest);
        match path::discover(session, authorities, actor.certificate(), interval)? {
            Ok(path) => checked.try_push(path).map_err(Error::from)?,
            Err(failure) => {
                let property = actor.verified().property();
                return Ok(Err((property, TimestampFailure::Path(failure))));
            }
        }
    }
    Ok(Ok(checked.into_owned()))
}

/// The checked paths bound to the very tokens they answer.
fn bound_paths<'v, 'd>(
    checked: &'v [CheckedPath<'d>],
    actors: &'v [TokenActor<'d, 'd>],
    utc: &LeapTable<'_>,
    memory: &Memory,
) -> Result<Result<OwnedVec<TsaPath<'v, 'd, 'd>>, TokenFailure>, ValidationError> {
    let mut bound = memory.vector();
    bound.try_reserve_exact(actors.len()).map_err(Error::from)?;
    for (path, actor) in checked.iter().zip(actors) {
        match path
            .bind_timestamp(actor, utc, memory)
            .map_err(ValidationError::TimestampBinding)?
        {
            TimestampBinding::Bound(value) => bound.try_push(value).map_err(Error::from)?,
            TimestampBinding::Rejected(cause) => {
                let property = actor.verified().property();
                return Ok(Err((property, TimestampFailure::Binding(cause))));
            }
        }
    }
    Ok(Ok(bound.into_owned()))
}

/// Early return of a completed negative token fact.
macro_rules! token_fact {
    ($value:expr) => {
        match $value? {
            Ok(value) => value,
            Err((property, failure)) => return Ok(Outcome::Timestamp { property, failure }),
        }
    };
}

fn frozen<W: Work, R>(
    stage: &Stage<'_, '_, '_, '_, W>,
    basic: &Report<'_>,
    inputs: &Inputs<'_>,
    pools: &Pools<'_, '_>,
    visitor: impl for<'a> FnOnce(&Level<'a>) -> R,
) -> Result<Outcome<R>, ValidationError> {
    let session = stage.session;
    let memory = stage.parser.memory();
    let access = stage.access;
    let anchors = read_certificates(stage.parser, inputs.anchors)?;
    let supplied = read_certificates(stage.parser, inputs.certificates)?;
    let supplied_parent = stage
        .parser
        .read(&[], 0)
        .map_err(ValidationError::Operation)?;
    let pool = certificate_pool(pools, &supplied, memory)?;
    let mut anchored = memory.vector();
    anchored
        .try_reserve_exact(anchors.len())
        .map_err(Error::from)?;
    for anchor in &anchors {
        anchored
            .try_push(Anchor::from_certificate(anchor))
            .map_err(Error::from)?;
    }
    let authorities = Authorities {
        anchors: &anchors,
        anchored: &anchored,
        pool: &pool,
        responders: inputs.responders,
        memory,
    };
    let external = External::read(stage.parser, inputs, &supplied_parent)?;
    let cms = session.cms_provider();
    let actors = token_fact!(token_actors(
        stage,
        inputs,
        pools,
        &supplied,
        &supplied_parent,
        &cms
    ));
    let checked = token_fact!(actor_paths(session, &authorities, &actors, inputs.utc));
    let bound = token_fact!(bound_paths(&checked, &actors, inputs.utc, memory));
    let mut references = memory.vector();
    references
        .try_reserve_exact(bound.len())
        .map_err(Error::from)?;
    for path in &bound {
        references.try_push(path).map_err(Error::from)?;
    }
    let whole = timestamp::requirements_with_counters(
        access,
        stage.prepared,
        pools.stamps,
        TimestampSelection::All,
    )
    .map_err(|error| ValidationError::Requirements(Box::new(error)))?;
    let paths = match whole
        .bind_paths(&references, access)
        .map_err(ValidationError::Obligation)?
    {
        TimestampPathBinding::Bound(paths) => paths,
        TimestampPathBinding::Unproven(cause) => {
            return Ok(Outcome::Timestamp {
                property: whole.signature(),
                failure: TimestampFailure::Census(cause),
            });
        }
    };
    let timed = composed::timestamped(basic, &paths, access).map_err(ValidationError::Timing)?;
    if inputs.requirements == Requirements::Timestamped {
        let level =
            baseline::assess(Evidence::Timestamped(&timed)).map_err(ValidationError::Level)?;
        return Ok(Outcome::Assessed(visitor(&level)));
    }
    long_term(
        &Chain {
            stage,
            inputs,
            pools,
            authorities: &authorities,
            external: &external,
            cms: &cms,
            bound: &bound,
            paths: &paths,
            timed: &timed,
        },
        visitor,
    )
}

/// Everything the long-term stages share.
struct Chain<'c, 'a, 'v, 's, 'i, 't, W: Work> {
    stage: &'c Stage<'a, 'v, 's, 'i, W>,
    inputs: &'c Inputs<'c>,
    pools: &'c Pools<'c, 't>,
    authorities: &'c Authorities<'c>,
    external: &'c External<'c>,
    cms: &'c CmsProvider<'c>,
    bound: &'c [TsaPath<'c, 'c, 'c>],
    paths: &'c TimestampPaths<'c, 'c, 'c, N, D, G, Xades>,
    timed: &'c TimedReport<'c>,
}

/// The status sources the caller supplied, parsed once.
struct External<'s> {
    crls: OwnedVec<CertificateList<'s>>,
    responses: OwnedVec<BasicResponse<'s>>,
}

impl<'s> External<'s> {
    fn read(
        parser: &'s Parser,
        inputs: &Inputs<'s>,
        query: &Reader<'s>,
    ) -> Result<Self, ValidationError> {
        let status = |cause: structured_pkix::Error| {
            ValidationError::Status(Box::new(StatusError::Pkix(cause)))
        };
        let (mut crls, mut responses) = (parser.memory().vector(), parser.memory().vector());
        crls.try_reserve_exact(inputs.crls.len())
            .map_err(Error::from)?;
        for bytes in inputs.crls {
            let list = CertificateList::read(parser, bytes, 0).map_err(status)?;
            crls.try_push(list).map_err(Error::from)?;
        }
        for bytes in inputs.responses {
            // A protocol failure carries no signed status, so it answers nothing.
            let Response::Successful(body) = Response::read(parser, bytes, 0).map_err(status)?
            else {
                continue;
            };
            if let Some(basic) = body.basic_in(query).map_err(status)? {
                responses.try_push(basic).map_err(Error::from)?;
            }
        }
        Ok(Self {
            crls: crls.into_owned(),
            responses: responses.into_owned(),
        })
    }
}

/// The CRLs and OCSP responses of one document, then the caller's.
fn status_sources<'p, 't: 'p>(
    view: &'p Material<'t>,
    carried: &'p CarriedMaterial<'t, N, D, G>,
    external: &'p External<'t>,
    memory: &Memory,
) -> Result<
    (
        OwnedVec<&'p CertificateList<'t>>,
        OwnedVec<&'p BasicResponse<'t>>,
    ),
    Error,
> {
    let mut lists = memory.vector();
    for value in view.values() {
        if let Value::Crl(list) = &value.value {
            lists.try_push(list)?;
        }
    }
    for list in carried.crls() {
        lists.try_push(&list.value)?;
    }
    for list in &*external.crls {
        lists.try_push(list)?;
    }
    let mut responses = memory.vector();
    for basic in view.basic_responses() {
        responses.try_push(basic.response())?;
    }
    for response in carried.basic_responses() {
        responses.try_push(&response.value)?;
    }
    for response in &*external.responses {
        responses.try_push(response)?;
    }
    Ok((lists.into_owned(), responses.into_owned()))
}

/// Every participant's status, its incorporation and, for B-LTA, each archive.
fn long_term<W: Work, R>(
    chain: &Chain<'_, '_, '_, '_, '_, '_, W>,
    visitor: impl for<'a> FnOnce(&Level<'a>) -> R,
) -> Result<Outcome<R>, ValidationError> {
    let stage = chain.stage;
    let access = stage.access;
    let memory = stage.parser.memory();
    let credentials =
        match credential::check_participants(stage.prepared, stage.counters, &NoFormats, access) {
            Ok(credentials) => credentials,
            Err(credential::Error::Unsupported { node }) => {
                return Ok(Outcome::Credential { node });
            }
            Err(error) => return Err(ValidationError::Credentials(Box::new(error))),
        };
    let participants = xades_pki::participants(
        stage.certificate,
        stage.counters,
        &credentials,
        chain.paths,
        access,
    )
    .map_err(ValidationError::Participants)?;
    let carried = chain
        .pools
        .tokens
        .material_in(chain.pools.operation)
        .map_err(|error| ValidationError::Carried(Box::new(error)))?;
    let index = material::index_with_tokens(chain.pools.view, &carried, access)
        .map_err(ValidationError::Index)?;
    let (lists, responses) = status_sources(chain.pools.view, &carried, chain.external, memory)?;
    // One census per live path; several actors may share one.
    let mut distinct: OwnedVec<&CheckedPath<'_>, _> = memory.vector();
    for path in participant_paths(&participants) {
        if !distinct.iter().any(|known| core::ptr::eq(*known, path)) {
            distinct.try_push(path).map_err(Error::from)?;
        }
    }
    let closed = status::with_statuses(
        stage.session,
        chain.cms,
        chain.authorities,
        &lists,
        &responses,
        &distinct,
        chain.inputs.utc,
        stage.signer_time,
        |statuses, nodes| {
            material_level(
                chain,
                &Assessed {
                    credentials: &credentials,
                    participants: &participants,
                    index: &index,
                    statuses,
                    nodes,
                },
                visitor,
            )
        },
    )
    .map_err(|error| ValidationError::Status(Box::new(error)))?;
    match closed {
        Ok(outcome) => outcome,
        Err(failure) => Ok(Outcome::Status(failure)),
    }
}

/// The whole-signature facts every long-term report is derived from.
struct Assessed<'a, W: Work> {
    credentials: &'a Credentials<'a>,
    participants: &'a Actors<'a>,
    index: &'a Index<'a, N, D, G, W>,
    statuses: &'a [&'a PathStatuses<'a, 'a, 'a>],
    nodes: &'a [AuthorityNode<'a, 'a, 'a>],
}

fn placement_error(error: impl core::fmt::Debug) -> ValidationError {
    ValidationError::Placement(format!("{error:?}"))
}

/// The B-LT reports, and the B-LTA census when the request asks for it.
fn material_level<W: Work, R>(
    chain: &Chain<'_, '_, '_, '_, '_, '_, W>,
    facts: &Assessed<'_, W>,
    visitor: impl for<'a> FnOnce(&Level<'a>) -> R,
) -> Result<Outcome<R>, ValidationError> {
    let stage = chain.stage;
    let access = stage.access;
    let roots = census(facts.participants, facts.statuses, stage.parser.memory())?;
    let closure = facts
        .participants
        .close_statuses(&roots, facts.nodes, access)
        .map_err(ValidationError::Closure)?;
    let x509 = material::check_participants(
        stage.prepared,
        &closure,
        stage.counters,
        facts.index,
        access,
    )
    .map_err(placement_error)?;
    let format = material::credentials::check(
        facts.credentials,
        stage.counters,
        chain.paths.required(),
        facts.index,
        &Scope::whole(),
        &NoFormats,
        access,
    )
    .map_err(placement_error)?;
    let long_term = composed::long_term(chain.timed, &x509, &format, access)
        .map_err(ValidationError::Participants)?;
    if chain.inputs.requirements == Requirements::LongTerm {
        let level =
            baseline::assess(Evidence::LongTerm(&long_term)).map_err(ValidationError::Level)?;
        return Ok(Outcome::Assessed(visitor(&level)));
    }
    archival(chain, facts, &long_term, visitor)
}

type EarlierScopes<'c> = (
    OwnedVec<Required>,
    OwnedVec<OwnedVec<&'c TsaPath<'c, 'c, 'c>>>,
);

/// Each archive's earlier token scope, and the checked paths of those tokens.
fn earlier_scopes<'c, W: Work>(
    chain: &Chain<'c, '_, '_, '_, '_, '_, W>,
    archives: &[usize],
) -> Result<Result<EarlierScopes<'c>, TokenFailure>, ValidationError> {
    let stage = chain.stage;
    let memory = stage.parser.memory();
    let (mut earlier, mut chosen) = (memory.vector(), memory.vector());
    for ordinal in archives {
        let required = timestamp::requirements_with_counters(
            stage.access,
            stage.prepared,
            chain.pools.stamps,
            TimestampSelection::BeforeArchive(*ordinal),
        )
        .map_err(|error| ValidationError::Requirements(Box::new(error)))?;
        let mut paths = memory.vector();
        for entry in required.entries() {
            let Some(path) = chain
                .bound
                .iter()
                .find(|path| path.actor().verified().token().node == entry.token)
            else {
                let failure = TimestampFailure::Census(TimestampPathFailure::Count);
                return Ok(Err((entry.property, failure)));
            };
            paths.try_push(path).map_err(Error::from)?;
        }
        chosen.try_push(paths.into_owned()).map_err(Error::from)?;
        earlier.try_push(required).map_err(Error::from)?;
    }
    Ok(Ok((earlier.into_owned(), chosen.into_owned())))
}

type ArchiveInput<'c> = (
    Coverage<N, D, G, Memory, Xades>,
    &'c Verified<N, D, G, Xades>,
);

/// Each archive's exact input coverage and its checked token.
fn archive_inputs<'c, W: Work>(
    chain: &Chain<'c, '_, '_, '_, '_, '_, W>,
    archives: &[usize],
) -> Result<OwnedVec<ArchiveInput<'c>>, ValidationError> {
    let stage = chain.stage;
    let memory = stage.parser.memory();
    let mut covered = memory.vector();
    for ordinal in archives {
        let stamp = &stage.prepared.timestamps()[*ordinal];
        let input = Input::prepare(stage.document, stage.prepared.bound(), stamp, memory)
            .map_err(|error| ValidationError::Requirements(Box::new(error.into())))?;
        let coverage = input.element_coverage(memory).map_err(|error| {
            ValidationError::Requirements(Box::new(RequirementError::Coverage(error)))
        })?;
        let evidence = chain
            .bound
            .iter()
            .map(|path| path.actor().verified())
            .find(|verified| verified.property() == stamp.node())
            .expect("every archive token has its checked path");
        covered
            .try_push((coverage, evidence))
            .map_err(Error::from)?;
    }
    Ok(covered.into_owned())
}

/// The census of every root archive, each over its own earlier scope.
fn archival<W: Work, R>(
    chain: &Chain<'_, '_, '_, '_, '_, '_, W>,
    facts: &Assessed<'_, W>,
    long_term: &LongTermReport<'_>,
    visitor: impl for<'a> FnOnce(&Level<'a>) -> R,
) -> Result<Outcome<R>, ValidationError> {
    let stage = chain.stage;
    let (access, memory) = (stage.access, stage.parser.memory());
    let mut archives = memory.vector();
    for (ordinal, stamp) in stage.prepared.timestamps().iter().enumerate() {
        if stamp.role() == Role::Archive {
            archives.try_push(ordinal).map_err(Error::from)?;
        }
    }
    let (earlier, chosen) = token_fact!(earlier_scopes(chain, &archives));
    let mut prior = memory.vector();
    for (required, paths) in earlier.iter().zip(chosen.iter()) {
        match required
            .bind_paths(paths, access)
            .map_err(ValidationError::Obligation)?
        {
            TimestampPathBinding::Bound(value) => prior.try_push(value).map_err(Error::from)?,
            TimestampPathBinding::Unproven(cause) => {
                return Ok(Outcome::Timestamp {
                    property: required.signature(),
                    failure: TimestampFailure::Census(cause),
                });
            }
        }
    }
    let (mut actors, mut censuses) = (memory.vector(), memory.vector());
    for paths in &prior {
        let scope = xades_pki::participants(
            stage.certificate,
            stage.counters,
            facts.credentials,
            paths,
            access,
        )
        .map_err(ValidationError::Participants)?;
        censuses
            .try_push(census(&scope, facts.statuses, memory)?)
            .map_err(Error::from)?;
        actors.try_push(scope).map_err(Error::from)?;
    }
    let mut closures = memory.vector();
    for (actors, roots) in actors.iter().zip(censuses.iter()) {
        let closure = actors
            .close_statuses(roots, facts.nodes, access)
            .map_err(ValidationError::Closure)?;
        closures.try_push(closure).map_err(Error::from)?;
    }
    let covered = archive_inputs(chain, &archives)?;
    let (mut x509, mut formats) = (memory.vector(), memory.vector());
    for ((closure, required), (coverage, evidence)) in
        closures.iter().zip(earlier.iter()).zip(covered.iter())
    {
        let material = structured_ltv::material::archived_participants(
            closure,
            facts.index,
            coverage,
            *evidence,
            access,
        )
        .map_err(placement_error)?;
        x509.try_push(material).map_err(Error::from)?;
        let format = material::credentials::check(
            facts.credentials,
            stage.counters,
            required,
            facts.index,
            &Scope::before_archive(coverage, evidence),
            &NoFormats,
            access,
        )
        .map_err(placement_error)?;
        formats.try_push(format).map_err(Error::from)?;
    }
    let mut pairs = memory.vector();
    for (material, format) in x509.iter().zip(formats.iter()) {
        let pair = composed::archive_material(material, format, access)
            .map_err(ValidationError::Participants)?;
        pairs.try_push(pair).map_err(Error::from)?;
    }
    let mut reports = memory.vector();
    for pair in &pairs {
        reports.try_push(pair).map_err(Error::from)?;
    }
    let archives =
        composed::archives(stage.prepared, &reports, access).map_err(ValidationError::Archives)?;
    if let Some((property, failure)) = unconfirmed_renewal(stage)? {
        return Ok(Outcome::Renewal { property, failure });
    }
    let level = baseline::assess(Evidence::Archival {
        long_term,
        archives: &archives,
    })
    .map_err(ValidationError::Level)?;
    Ok(Outcome::Assessed(visitor(&level)))
}

/// The checked path of every path actor of `participants`, in census order.
fn participant_paths<'p, 'd>(
    participants: &'p ParticipantRequirements<'p, 'd, N, D, G, Xades>,
) -> impl Iterator<Item = &'p CheckedPath<'d>> {
    participants
        .entries()
        .iter()
        .filter_map(|entry| match entry.authority() {
            ParticipantAuthority::Path(path) => Some(path),
            ParticipantAuthority::Anchor(_) | ParticipantAuthority::CertificateFree => None,
        })
}

/// One root census per path actor, in the order `close_statuses` requires.
fn census<'v, 'c, 'd>(
    participants: &ParticipantRequirements<'_, 'd, N, D, G, Xades>,
    statuses: &[&'v PathStatuses<'v, 'c, 'd>],
    memory: &Memory,
) -> Result<OwnedVec<&'v PathStatuses<'v, 'c, 'd>>, ValidationError> {
    let mut roots = memory.vector();
    for path in participant_paths(participants) {
        let status = statuses
            .iter()
            .find(|status| core::ptr::eq(status.path(), path))
            .expect("every distinct actor path has its census");
        roots.try_push(*status).map_err(Error::from)?;
    }
    Ok(roots.into_owned())
}

/// No credential format is selected, so every signed one stays unsupported.
struct NoFormats;

impl<'p, 'd, X: Xml> credential::Provider<'p, 'd, X> for NoFormats {
    type Evidence = NoCredential;
    type Error = Infallible;

    fn authenticate<Q: Work>(
        &self,
        _access: &Access<'_, X, Q>,
        _credential: credential::Credential<X::Id, X::Document, X::Generation>,
    ) -> Result<Authentication<'p, 'd, NoCredential>, Infallible> {
        Ok(Authentication::Unsupported)
    }
}

impl<X: Xml> material::credentials::Provider<X, NoCredential> for NoFormats {
    type Error = Infallible;

    fn visit<VE, Q: Work>(
        &self,
        credential: &credential::Checked<'_, '_, NoCredential, X::Id, X::Document, X::Generation>,
        _open: &[material::Opaque<X::Id, X::Document, X::Generation>],
        _access: &Access<'_, X, Q>,
        _visitor: impl for<'value, 'document> FnMut(
            material::credentials::Need<'value, 'document, X::Id, X::Document, X::Generation>,
        ) -> Result<(), VE>,
    ) -> Result<material::credentials::Completeness, VisitError<Infallible, VE>> {
        match *credential.evidence() {}
    }
}

/// The interval the signer's path must hold over: the verification instant and
/// every signature timestamp's whole stated generation interval (EN 319 132-1
/// V1.3.1 §6.3(o)). Read before any token is authenticated, which is safe in one
/// direction only: a false time widens what the path must satisfy, and the
/// association itself uses the authenticated token. A token whose accuracy
/// neither it nor the caller states adds nothing here and stays unproven there.
pub(crate) fn signature_span<'s, W: Work>(
    document: &Document<'_, '_, '_, '_, W>,
    prepared: &Prepared<Document<'_, '_, '_, '_, W>>,
    operation: &Reader<'s>,
    stated: &[Stated<'s>],
    timing: Option<Timing<'_>>,
    verified_at: Option<Instant>,
) -> Result<Option<Interval>, ValidationError> {
    let (Some(Timing { utc, profile, .. }), Some(at)) = (timing, verified_at) else {
        return Ok(None);
    };
    let parent = operation;
    let span = timestamp::with_tokens(
        document,
        prepared,
        operation,
        profile,
        |operation, tokens| {
            let execution = operation.execution();
            let (mut first, mut last) = (at, at);
            for (source, reading) in tokens.sources().iter().zip(tokens.readings()) {
                if source.role() != Role::Signature {
                    continue;
                }
                let generation = reading.token().with_info(reading.reader(), |info, _, _| {
                    // RFC 3161 §2.4.2: policy accuracy answers only an absent field.
                    let accuracy = match info.accuracy() {
                        Some(value) => value.deviation().ok(),
                        None => {
                            match accuracy::select(stated, reading.token(), info.policy(), parent) {
                                Ok(policy) => policy.map(PolicyAccuracy::accuracy),
                                Err(cause) => return Ok::<_, Infallible>(Err(cause)),
                            }
                        }
                    };
                    Ok(Ok(interval_in(info.gen_time(), accuracy, utc, &execution)))
                });
                match generation {
                    Ok(Ok(Ok(generation))) => {
                        first = first.min(generation.earliest);
                        last = last.max(generation.latest);
                    }
                    Ok(Ok(Err(IntervalError::Resource(cause)))) => {
                        return Ok(Err(ValidationError::Adapter(cause.into())));
                    }
                    Ok(Ok(Err(IntervalError::Uncertain(_)))) => {}
                    Ok(Err(cause)) => return Ok(Err(cause)),
                    Err(cause) => return Ok(Err(ValidationError::TokenInfo(Box::new(cause)))),
                }
            }
            Ok::<_, Infallible>(Ok(Interval::between_instants(first, last)))
        },
    )
    .map_err(|error| ValidationError::Tokens(Box::new(error)))??;
    Ok(Some(span))
}

/// Parse caller DER under the operation's certificate parser.
fn read_certificates<'s>(
    parser: &'s Parser,
    sources: &'s [&'s [u8]],
) -> Result<OwnedVec<Certificate<'s>>, Error> {
    let mut parsed = parser.memory().vector();
    parsed.try_reserve_exact(sources.len())?;
    for bytes in sources {
        parsed
            .try_push(Certificate::read(parser, bytes, 0).map_err(X509ChainError::Processing)?)?;
    }
    Ok(parsed.into_owned())
}
