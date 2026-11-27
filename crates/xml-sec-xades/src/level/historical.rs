//! The participant census of a signature in a historical vocabulary: ETSI
//! TS 101 903 V1.1.1 or V1.2.2, or the TS 103 171 profile of V1.3.2.
//!
//! The signer's path, the timestamps' TSA paths and every status those paths
//! need are established as for a baseline level, over the original
//! historical grammar; no EN 319 132-1 level applies. The census states which
//! of that validation data the document holds and which it lacks.

use super::{
    Error, External, Inputs, N, NoFormats, Outcome, TimestampFailure, Tokens, actor_paths,
    bound_paths, census, incorporated_certificates, participant_paths, read_certificates,
    status_sources, token_signer, unrecognized,
};
use crate::accuracy;
use crate::basic::{ValidationError, counter_fact};
use crate::path::{self, Authorities, CounterPathError};
use crate::status;
use crate::ts101903::Ts101903Error;
use crate::{Document, Snapshot};
use alloc::boxed::Box;
use core::convert::Infallible;
use structured_asn1::Reader;
use structured_asn1::memory::{Memory, OwnedVec, Work};
use structured_cms::timestamp::CheckContext;
use structured_ltv::pki::{CheckedPath, ParticipantClosure, SignerReceipt as _};
use structured_ltv::timestamp::TimestampPathBinding;
use structured_pkix::Certificate;
use structured_pkix::ocsp::{Response, ResponseBytes};
use structured_pkix::path::{Anchor, EffectiveKey};
use structured_xades::Xades;
use structured_xades::legacy::timestamp::HashDataUri;
use structured_xades::legacy::{self, Profile};
use structured_xades::material::{self, HistoricalIncorporation, Value, View};
use structured_xades::pki;
use structured_xades::timestamp::{self, CarriedMaterial, TimestampSelection, TokenProfile};
use structured_xades::xml::{Access, Xml};
use xml_sec::policy::TimestampTokenEncoding;
use xml_sec::xmldsig::VerifiedSession;

type D = xml_sec::document::DocumentIdentity;
type G = u64;

/// The census of one historical signature: its participants' validation
/// data and where the document holds each item.
pub(crate) struct HistoricalCensus<'r, 'c, 'v, 's, 'i, W: Work> {
    session: &'r VerifiedSession<'v, 's, 'i, W>,
    document: &'r Document<'c, 'v, 's, 'i, W>,
    access: &'r Access<'r, Document<'c, 'v, 's, 'i, W>, W>,
    prepared: &'r legacy::Prepared<Document<'c, 'v, 's, 'i, W>>,
    view: &'r View<'r, N, D, G>,
    carried: &'r CarriedMaterial<'r, N, D, G>,
    external: &'r External<'r>,
    closure: &'r ParticipantClosure<'r, 'r, 'r, 'r, N, D, G, Xades>,
    signer: Option<&'r CheckedPath<'r>>,
    incorporation: &'r HistoricalIncorporation<'r, 'r, Document<'c, 'v, 's, 'i, W>>,
}

impl<'r, 'c, 'v, 's, 'i, W: Work> HistoricalCensus<'r, 'c, 'v, 's, 'i, W> {
    /// The verified session the census was taken in.
    pub(crate) fn session(&self) -> &'r VerifiedSession<'v, 's, 'i, W> {
        self.session
    }

    /// The generation the census describes.
    pub(crate) fn snapshot(&self) -> Snapshot {
        self.document.snapshot()
    }

    /// The signature, prepared in its historical vocabulary.
    pub(crate) fn prepared(&self) -> &'r legacy::Prepared<Document<'c, 'v, 's, 'i, W>> {
        self.prepared
    }

    /// Reads of the generation the census describes.
    pub(crate) fn access(&self) -> &'r Access<'r, Document<'c, 'v, 's, 'i, W>, W> {
        self.access
    }

    /// Every participant's path and the statuses it uses.
    pub(crate) fn closure(&self) -> &'r ParticipantClosure<'r, 'r, 'r, 'r, N, D, G, Xades> {
        self.closure
    }

    /// The signer's checked path, when the historical signer binds it.
    pub(crate) fn signer(&self) -> Option<&'r CheckedPath<'r>> {
        self.signer
    }

    /// Where the document holds each item of validation data its
    /// participants need, and which it lacks.
    pub(crate) fn incorporation(
        &self,
    ) -> &'r HistoricalIncorporation<'r, 'r, Document<'c, 'v, 's, 'i, W>> {
        self.incorporation
    }

    /// The whole `OCSPResponse` that carries `basic`: the caller's, one the
    /// document holds, or one a token carries in its CMS.
    pub(crate) fn envelope(
        &self,
        basic: &structured_pkix::ocsp::BasicResponse<'_>,
    ) -> Option<&'r ResponseBytes<'r>> {
        let same = |response: &structured_pkix::ocsp::BasicResponse<'_>| {
            core::ptr::eq(response.as_bytes(), basic.as_bytes())
        };
        let external = self.external;
        if let Some(position) = external.responses.iter().position(same) {
            return external.envelopes.get(position);
        }
        if let Some(incorporated) = self
            .view
            .basic_responses()
            .iter()
            .find(|incorporated| same(incorporated.response()))
        {
            return match &self.view.values().get(incorporated.source_index())?.value {
                Value::Ocsp(Response::Successful(envelope)) => Some(envelope),
                _ => None,
            };
        }
        let origin = self
            .carried
            .basic_responses()
            .iter()
            .find(|carried| same(&carried.value))?
            .origin;
        self.carried
            .responses()
            .iter()
            .find(|carried| carried.origin == origin)
            .map(|carried| &carried.value)
    }
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

/// Take the census of `signature`, read in the vocabulary of `profile`, which
/// the caller chose, from `inputs` and the document, and run `visitor` over
/// it. A completed negative fact, such as a path or a status that cannot be
/// established, is its [`Outcome`].
///
/// # Errors
/// The original cause of the stage that could not complete.
pub(crate) fn with_historical_census<W: Work, R>(
    session: &VerifiedSession<'_, '_, '_, W>,
    signature: N,
    profile: Profile,
    inputs: &Inputs<'_>,
    visitor: impl for<'r, 'c> FnOnce(&HistoricalCensus<'r, 'c, '_, '_, '_, W>) -> R,
) -> Result<Outcome<R>, ValidationError> {
    let fail = |error| ValidationError::Ts101903(Box::new(error));
    crate::ts101903::require_admitted(session, profile)?;
    let work = session.execution();
    path::require_member(session, signature, work)?;
    let document = Document::new(session);
    let access = Access::new(&document, document.snapshot(), work);
    let layout = legacy::locate(&access, signature, profile)
        .map_err(|cause| fail(Ts101903Error::Container(cause)))?;
    let prepared = legacy::prepare(&access, &layout)
        .map_err(|cause| fail(Ts101903Error::Properties(cause)))?;
    let parser = session.certificate_parser();
    let x509 = parser.memory();
    let signers = path::signers(session, signature, &[], x509)?;
    let decoded = path::key_info_certificates(session, &signers, x509)?;
    let candidates = path::candidates(&decoded, [inputs.anchors, inputs.certificates], x509)?;
    let selection = path::select(&signers, &candidates, &parser, x509)?;
    let paths = path::check(session, &selection, (signature, None), x509)?;
    let root = match paths.get(signature, x509) {
        Ok(root) => root,
        Err(CounterPathError::Missing(failure)) => {
            return Ok(Outcome::Path { signature, failure });
        }
        Err(CounterPathError::Resource(cause)) => return Err(Error::from(cause).into()),
    };
    let Some(signer_time) = path::verification_time(&signers, signature) else {
        return Err(Error::UnknownSignature.into());
    };
    let signer = legacy::check_path(&document, &prepared, root, &document, work)
        .map_err(|cause| fail(Ts101903Error::Signer(cause)))?;
    let counters = match pki::bind_counters(prepared.binding(), &access, |binding, work| {
        paths.get(binding.original().child(), work)
    }) {
        Ok(counters) => counters,
        Err(error) => return counter_fact(error),
    };
    let inventory = legacy::inventory(&access, &prepared, HashDataUri::Standard)
        .map_err(|cause| fail(Ts101903Error::Inventory(cause)))?;
    let required = inventory
        .requirements(&access, TimestampSelection::All)
        .map_err(|error| ValidationError::Requirements(Box::new(error)))?;
    let credentials = match legacy::check_credentials(&prepared, &counters, &NoFormats, &access) {
        Ok(credentials) => credentials,
        Err(legacy::CredentialError::Check(structured_xades::credential::Error::Unsupported {
            node,
        })) => return Ok(Outcome::Credential { node }),
        Err(cause) => return Err(fail(Ts101903Error::Credentials(cause))),
    };
    let token_profile = match session.timestamp_token_encoding() {
        TimestampTokenEncoding::Declared => TokenProfile::Etsi,
        TimestampTokenEncoding::Ber => TokenProfile::Cms,
    };
    let operation = parser.read(&[], 0).map_err(ValidationError::Operation)?;
    let scope = Scope {
        session,
        document: &document,
        access: &access,
        prepared: &prepared,
        inventory: &inventory,
        signer: &signer,
        counters: &counters,
        credentials: &credentials,
        required: &required,
        inputs,
        parser: &parser,
        signer_time,
    };
    inventory
        .with_tokens(&document, &operation, token_profile, |operation, tokens| {
            Ok::<_, Infallible>(
                material::with_historical_values(
                    &document,
                    &prepared,
                    operation,
                    |operation, view| {
                        Ok::<_, Infallible>(scope.frozen(operation, &tokens, &view, visitor))
                    },
                )
                .map_err(|error| ValidationError::Material(Box::new(error)))
                .and_then(core::convert::identity),
            )
        })
        .map_err(|error| ValidationError::Tokens(Box::new(error)))?
}

/// Everything the census reads, all of one verified historical signature.
struct Scope<'a, 'c, 'v, 's, 'i, 'p, W: Work> {
    session: &'a VerifiedSession<'v, 's, 'i, W>,
    document: &'a Document<'c, 'v, 's, 'i, W>,
    access: &'a Access<'a, Document<'c, 'v, 's, 'i, W>, W>,
    prepared: &'a legacy::Prepared<Document<'c, 'v, 's, 'i, W>>,
    inventory: &'a legacy::Inventory<'a, Document<'c, 'v, 's, 'i, W>>,
    signer: &'a legacy::CheckedSigner<'p, 'p, N, D, G>,
    counters: &'a pki::CounterPaths<'p, 'p, N, D, G>,
    credentials: &'a structured_xades::credential::ParticipantCredentials<
        'p,
        'p,
        super::NoCredential,
        N,
        D,
        G,
    >,
    required: &'a structured_ltv::timestamp::TimestampRequirements<N, D, G, Xades>,
    inputs: &'a Inputs<'a>,
    parser: &'a structured_asn1::Parser,
    signer_time: structured_pkix::temporal::Instant,
}

impl<'v, 's, 'i, W: Work> Scope<'_, '_, 'v, 's, 'i, '_, W> {
    /// Check every token of the pool with its named signer's own key against
    /// its historical recipe; the first that gives no actor is the fact.
    fn actors<'p, 't>(
        &'p self,
        operation: &'p Reader<'t>,
        tokens: &'p Tokens<'t>,
        certificates: [&'p [Certificate<'t>]; 2],
        supplied_parent: &'p Reader<'t>,
        stated: &'p [accuracy::Stated<'p>],
    ) -> Result<Result<OwnedVec<super::TokenActor<'p, 'p>>, super::TokenFailure>, ValidationError>
    where
        't: 'p,
    {
        let cms = self.session.cms_provider();
        let mut actors = self.parser.memory().vector();
        for ordinal in 0..tokens.sources().len() {
            let property = tokens.sources()[ordinal].property();
            let Some((certificate, parent)) =
                token_signer(tokens, ordinal, certificates, supplied_parent)?
            else {
                return Ok(Err((property, TimestampFailure::MissingSigner)));
            };
            let reading = &tokens.readings()[ordinal];
            let policy_accuracy =
                accuracy::select_outside(stated, reading.token(), reading.reader(), operation)?;
            let context = CheckContext {
                certificate,
                certificate_parent: parent,
                key: EffectiveKey::standing(certificate.tbs().public_key()),
                requested: None,
                utc: self.inputs.utc,
                // A historical token is archived evidence: this instant only
                // refuses one generated after the time validated at.
                reference: Some(self.signer_time),
                window: None,
                policy_accuracy,
            };
            let checker = timestamp::Check {
                xml: self.document,
                provider: &cms,
                context: &context,
            };
            let entry = tokens.entry(ordinal).expect("ordinal within the pool");
            let ((), actor) = self
                .inventory
                .check_actor_from(&checker, entry, operation, unrecognized(), |_| ())
                .map_err(|error| ValidationError::Timestamp(Box::new(error)))?;
            let Some(actor) = actor else {
                return Ok(Err((property, TimestampFailure::Rejected)));
            };
            actors.try_push(actor).map_err(Error::from)?;
        }
        Ok(Ok(actors.into_owned()))
    }

    /// The census over the frozen token pool and the document's values.
    fn frozen<R>(
        &self,
        operation: &Reader<'_>,
        tokens: &Tokens<'_>,
        view: &View<'_, N, D, G>,
        visitor: impl for<'r, 'x> FnOnce(&HistoricalCensus<'r, 'x, 'v, 's, 'i, W>) -> R,
    ) -> Result<Outcome<R>, ValidationError> {
        let session = self.session;
        let parser = self.parser;
        let memory = parser.memory();
        let inputs = self.inputs;
        let [anchors, supplied, responders] = caller_certificates(parser, inputs)?;
        let supplied_parent = parser.read(&[], 0).map_err(ValidationError::Operation)?;
        let pool = certificate_pool(tokens, view, [&supplied, &responders], memory)?;
        let anchored = anchored(&anchors, memory)?;
        let authorities = Authorities {
            anchors: &anchors,
            anchored: &anchored,
            pool: &pool,
            responders: inputs.responders,
            memory,
        };
        let external = External::read(parser, inputs, &supplied_parent)?;
        let document_der = incorporated_certificates(view, memory)?;
        let incorporated = read_certificates(parser, &document_der)?;
        let stated = accuracy::read(parser, inputs.accuracies)?;
        let actors = token_fact!(self.actors(
            operation,
            tokens,
            [&supplied, &incorporated],
            &supplied_parent,
            &stated,
        ));
        let checked = token_fact!(actor_paths(session, &authorities, &actors, inputs.utc));
        let bound = token_fact!(bound_paths(&checked, &actors, inputs.utc, memory));
        let references = referenced(&bound, memory)?;
        let timestamps = match self
            .required
            .bind_paths(&references, self.access)
            .map_err(ValidationError::Obligation)?
        {
            TimestampPathBinding::Bound(paths) => paths,
            TimestampPathBinding::Unproven(cause) => {
                return Ok(Outcome::Timestamp {
                    property: self.required.signature(),
                    failure: TimestampFailure::Census(cause),
                });
            }
        };
        let participants = pki::historical_participants(
            self.signer,
            self.counters,
            self.credentials,
            &timestamps,
            self.access,
        )
        .map_err(ValidationError::Participants)?;
        let carried = tokens
            .material_in(operation)
            .map_err(|error| ValidationError::Carried(Box::new(error)))?;
        let index = material::index_with_tokens(view, &carried, self.access)
            .map_err(ValidationError::Index)?;
        let (lists, responses, supplied) =
            status_sources(view, &carried, &external, false, memory)?;
        let distinct = distinct_paths(&participants, memory)?;
        let closed = status::with_statuses(
            session,
            &session.cms_provider(),
            &authorities,
            &status::StatusSources {
                lists: &lists,
                responses: &responses,
                supplied,
            },
            &distinct,
            inputs.utc,
            self.signer_time,
            |statuses, nodes| {
                let roots = census(&participants, statuses, memory)?;
                let closure = participants
                    .close_statuses(&roots, nodes, self.access)
                    .map_err(ValidationError::Closure)?;
                let incorporation =
                    material::historical_incorporation(&closure, &index, self.access).map_err(
                        |cause| {
                            ValidationError::Ts101903(Box::new(Ts101903Error::Incorporation(cause)))
                        },
                    )?;
                Ok(Outcome::Assessed(visitor(&HistoricalCensus {
                    session,
                    document: self.document,
                    access: self.access,
                    prepared: self.prepared,
                    view,
                    carried: &carried,
                    external: &external,
                    closure: &closure,
                    signer: self.signer.path(),
                    incorporation: &incorporation,
                })))
            },
        )
        .map_err(|error| ValidationError::Status(Box::new(error)))?;
        match closed {
            Ok(outcome) => outcome,
            Err(failure) => Ok(Outcome::Status(failure)),
        }
    }
}

/// A reference to each of `items`, in order.
fn referenced<'a, T>(items: &'a [T], memory: &Memory) -> Result<OwnedVec<&'a T>, Error> {
    let mut references = memory.vector();
    for item in items {
        references.try_push(item)?;
    }
    Ok(references.into_owned())
}

/// Each live path of `participants` once: several actors may share one.
fn distinct_paths<'p, 'd>(
    participants: &'p structured_ltv::pki::ParticipantRequirements<'p, 'd, N, D, G, Xades>,
    memory: &Memory,
) -> Result<OwnedVec<&'p CheckedPath<'d>>, Error> {
    let mut distinct: OwnedVec<&CheckedPath<'_>, _> = memory.vector();
    for path in participant_paths(participants) {
        if !distinct.iter().any(|known| core::ptr::eq(*known, path)) {
            distinct.try_push(path)?;
        }
    }
    Ok(distinct.into_owned())
}

/// `anchors` in the form path building takes.
fn anchored<'p>(
    anchors: &'p [Certificate<'p>],
    memory: &Memory,
) -> Result<OwnedVec<Anchor<'p>>, Error> {
    let mut anchored = memory.vector();
    for anchor in anchors {
        anchored.try_push(Anchor::from_certificate(anchor))?;
    }
    Ok(anchored.into_owned())
}

/// The caller's anchors, further certificates and configured OCSP
/// responders, read.
fn caller_certificates<'p>(
    parser: &'p structured_asn1::Parser,
    inputs: &Inputs<'p>,
) -> Result<[OwnedVec<Certificate<'p>>; 3], ValidationError> {
    let mut responders = parser.memory().vector();
    for entry in inputs.responders {
        for certificate in read_certificates(parser, core::slice::from_ref(&entry.responder))? {
            responders.try_push(certificate).map_err(Error::from)?;
        }
    }
    Ok([
        read_certificates(parser, inputs.anchors)?,
        read_certificates(parser, inputs.certificates)?,
        responders.into_owned(),
    ])
}

/// Every certificate a path may use, whatever carried it. Being here proves
/// nothing: a path still has to end at a caller anchor.
fn certificate_pool<'p, 't>(
    tokens: &'p Tokens<'t>,
    view: &'p View<'t, N, D, G>,
    supplied: [&'p [Certificate<'t>]; 2],
    memory: &Memory,
) -> Result<OwnedVec<&'p Certificate<'t>>, Error> {
    let mut pool = memory.vector();
    for value in view.values() {
        if let Value::Certificate(certificate) = &value.value {
            pool.try_push(certificate)?;
        }
    }
    for basic in view.basic_responses() {
        for certificate in basic.response().certificates() {
            pool.try_push(certificate)?;
        }
    }
    for reading in tokens.readings() {
        for certificate in reading.token().message().certificates() {
            pool.try_push(certificate)?;
        }
    }
    for certificate in supplied.into_iter().flatten() {
        pool.try_push(certificate)?;
    }
    Ok(pool.into_owned())
}
