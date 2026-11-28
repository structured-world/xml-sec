//! Content timestamps of a new signature (EN 319 132-1 §5.2.8).
//!
//! A content timestamp covers the data objects before the signature exists,
//! so its input is the output of each data reference's dereference and
//! transforms: the bytes the signing operation feeds the reference digest.
//! [`crate::request_content_timestamps`] computes them in a dry run of the
//! same signing operation, stopped before any signature value, and encodes
//! one RFC 3161 request per timestamp; the caller sends each to its TSA.
//! [`crate::create`] computes them again, checks every response against its
//! exact request and input, writes the properties and signs, and refuses a
//! signature whose references digest other bytes than its timestamps cover.

use crate::accuracy::{self, AuthorityAccuracy};
use crate::augment::{TokenFacts, authority};
use crate::create::ManifestReference;
use crate::level::{read_certificates, unrecognized};
use crate::properties::{PropertyDraft, PropertyError};
use alloc::{boxed::Box, string::String, vec::Vec};
use core::convert::Infallible;
use structured_asn1::memory::{MemoryError, OwnedVec, Work};
use structured_asn1::{Oid, Parser, Tag, universal};
use structured_cms::stream::Receiver;
use structured_cms::timestamp::response::Status;
use structured_cms::timestamp::{CheckContext, Request, RequestWindow, Requested, Response};
use structured_pkix::algorithm::digest;
use structured_pkix::path::EffectiveKey;
use structured_pkix::temporal::LeapTable;
use structured_xades::produce::{
    CheckedContent, ContentInput, ContentInputError, ContentReference, ContentRequest,
    ContentRequestError, ContentResponseError, ContentScope as Selection, ContentSource,
    ContentWriter, Datatype, Event, PendingContent, ResponseCheck, Value, Writer,
};
use structured_xades::reference::ReplayOutcome;
use structured_xades::xml::Name;
use xml_sec::c14n::{C14nAlgorithm, C14nMode};
use xml_sec::policy::{GeneratedCanonicalization, SigningPolicy};
use xml_sec::xmldsig::SigningInputs;
use xml_sec::xmldsig::cms::{CmsProvider, CmsProviderError};

const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const EXCLUSIVE_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

/// The data objects one content timestamp covers.
#[derive(Debug, Clone, Copy)]
pub enum ContentScope<'a> {
    /// Every data object of `SignedInfo`: an `AllDataObjectsTimeStamp`.
    All,
    /// The data objects of these references, in this order, of `SignedInfo`
    /// or of a signed `Manifest`, named as [`crate::Request::id`] describes:
    /// an `IndividualDataObjectsTimeStamp`.
    Individual(&'a [&'a str]),
}

/// One content timestamp of a new signature.
#[derive(Debug, Clone, Copy)]
pub struct ContentTimestamp<'a> {
    /// The data objects it covers.
    pub scope: ContentScope<'a>,
    /// Hash of the message imprint; the verification policy must allow it.
    pub digest: digest::Algorithm,
    /// TSA policy to request, if any.
    pub policy: Option<Oid<'a>>,
    /// Unsigned nonce magnitude from the caller's entropy source. Without
    /// it, [`ContentEvidence::window`] has to establish freshness.
    pub nonce: Option<&'a [u8]>,
    /// The TSA's DER `TimeStampResp` to the request
    /// [`crate::request_content_timestamps`] returned for this timestamp;
    /// [`crate::create`] needs it, the request does not.
    pub response: Option<&'a [u8]>,
}

/// What content timestamp responses are checked with.
#[derive(Clone, Copy)]
pub struct ContentEvidence<'a> {
    /// DER certificates a token's signer may be among when the token omits it.
    pub certificates: &'a [&'a [u8]],
    /// Caller-authenticated UTC facts with explicit coverage.
    pub utc: &'a LeapTable<'a>,
    /// Policy accuracy of the authorities whose tokens omit the field.
    pub accuracies: &'a [AuthorityAccuracy<'a>],
    /// Caller-established window in which each request was uniquely
    /// outstanding (RFC 3161 §6); it proves freshness without a nonce.
    pub window: Option<RequestWindow>,
}

/// The DER `TimeStampReq` of each content timestamp, in order.
#[derive(Debug)]
pub struct ContentRequests {
    requests: Vec<OwnedVec<u8>>,
}

impl ContentRequests {
    /// The request of the `index`th content timestamp.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&[u8]> {
        self.requests.get(index).map(|request| &request[..])
    }

    /// How many requests there are, one per content timestamp.
    #[must_use]
    pub fn len(&self) -> usize {
        self.requests.len()
    }

    /// Whether there are none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    /// The requests in order.
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.requests.iter().map(|request| &request[..])
    }
}

/// A content timestamp that could not be requested or checked.
#[derive(Debug, thiserror::Error)]
pub enum ContentError {
    /// A scope names a URI that is no data reference of the new signature.
    #[error("{0:?} names no data reference of the signature")]
    UnknownReference(String),
    /// The dry run produced inputs that do not match the reference plan.
    #[error("the signing inputs do not match the reference plan")]
    Plan,
    /// The input could not be selected or replayed.
    #[error("content timestamp input failed: {0:?}")]
    Input(Box<ContentInputError<StagedError, usize>>),
    /// The request could not be built.
    #[error("content timestamp request failed: {0:?}")]
    Request(Box<ContentRequestError<StagedError, usize, CmsProviderError>>),
    /// A content timestamp has no response to complete it.
    #[error("content timestamp {0} has no response")]
    MissingResponse(usize),
    /// Responses are checked against evidence the request has not given.
    #[error("content timestamps need evidence to check their responses")]
    MissingEvidence,
    /// The TSA granted no token; the status is unauthenticated.
    #[error("the TSA granted no token: {0:?}")]
    Refused(Status),
    /// No supplied or carried certificate is the token's signer.
    #[error("no available certificate is the token's signer")]
    MissingAuthority,
    /// The response check could not complete.
    #[error("content timestamp response check failed: {0:?}")]
    Check(Box<ContentResponseError<StagedError, usize, CmsProviderError, Infallible>>),
    /// The token is not evidence for the request and its input.
    #[error("the token is not evidence for the request: {0:?}")]
    Unproven(TokenFacts),
    /// The signature digested other bytes than its content timestamps cover:
    /// a reference depends on the signature it is part of.
    #[error("a reference digested other bytes than the content timestamp covers")]
    Changed,
    /// ASN.1 processing could not start or failed.
    #[error("ASN.1 processing failed: {0:?}")]
    Asn1(structured_asn1::Error),
    /// The hash algorithm identifier could not be read.
    #[error("algorithm identifier failed: {0:?}")]
    Pkix(structured_pkix::Error),
    /// The request or response is not a conforming RFC 3161 message.
    #[error("timestamp message failed: {0:?}")]
    Message(structured_cms::Error),
    /// A supplied certificate could not be read.
    #[error(transparent)]
    Adapter(#[from] crate::Error),
    /// A policy accuracy could not be selected.
    #[error(transparent)]
    Accuracy(#[from] crate::ValidationError),
    /// The token signer could not be compared with a certificate.
    #[error("timestamp signer comparison failed: {0:?}")]
    Signer(structured_cms::directory::Error),
    /// The current execution refused work or storage.
    #[error("content timestamp resource refusal: {0}")]
    Resource(MemoryError),
}

impl From<MemoryError> for ContentError {
    fn from(error: MemoryError) -> Self {
        Self::Resource(error)
    }
}

/// A staged input refused during replay.
#[derive(Debug)]
pub enum StagedError {
    /// The canonicalization method is not the one the inputs were made with.
    Method,
    /// The reference is not one of the staged plan.
    Reference(usize),
}

/// The pre-sign reference plan of one new signature with the bytes each
/// reference digests, from a dry run of its signing operation.
///
/// Identities are positions: the `SignedInfo` references in order (the
/// data references, then `SignedProperties`), then the references of the
/// signed `Manifest`s, then the canonicalization method.
pub(crate) struct Replayed<'l> {
    signed_info: Vec<ContentReference<'l, usize>>,
    manifest: Vec<ContentReference<'l, usize>>,
    bytes: Vec<Vec<u8>>,
    method: usize,
    algorithm: C14nAlgorithm,
}

impl<'l> Replayed<'l> {
    /// The plan of `data` references, then `SignedProperties`, then the
    /// `manifest` references, over the signing inputs of the dry run.
    ///
    /// A chain ending in octets fed its digest those octets whatever the
    /// method; one ending in a node set fed the policy's conversion, written
    /// as an explicit Exclusive C14N transform unless the policy leaves it to
    /// Canonical XML 1.0 (`XMLDSig` 1.1 §4.4.3.2), which the method then is.
    pub(crate) fn new(
        inputs: SigningInputs,
        data: &'l [String],
        manifest: &'l [ManifestReference<'_>],
        signer: (&C14nAlgorithm, &SigningPolicy),
    ) -> Result<Self, ContentError> {
        let SigningInputs {
            signed_info_references,
            manifest_references,
            ..
        } = inputs;
        if signed_info_references.len() != data.len() + 1
            || manifest_references.len() != manifest.len()
        {
            return Err(ContentError::Plan);
        }
        let signed_info = data
            .iter()
            .map(|uri| Some(uri.as_str()))
            .chain([None])
            .enumerate()
            .map(|(node, include_uri)| ContentReference {
                node,
                include_uri,
                signed_properties: include_uri.is_none(),
            })
            .collect();
        let manifest = manifest
            .iter()
            .enumerate()
            // A supplied Manifest's reference without an Id has no URI an
            // individual timestamp could include.
            .map(|(index, entry)| ContentReference {
                node: data.len() + 1 + index,
                include_uri: entry.uri.as_deref(),
                signed_properties: false,
            })
            .collect();
        let (canonicalization, policy) = signer;
        let algorithm = match policy.transforms.generated_canonicalization {
            GeneratedCanonicalization::Implicit => {
                C14nAlgorithm::new(C14nMode::Inclusive1_0, false)
            }
            GeneratedCanonicalization::ExplicitExclusiveC14n => canonicalization.clone(),
        };
        let mut bytes = signed_info_references;
        bytes.extend(manifest_references);
        Ok(Self {
            signed_info,
            manifest,
            method: bytes.len(),
            bytes,
            algorithm,
        })
    }

    /// The identity of the reference `uri` names.
    fn node(&self, uri: &str) -> Option<usize> {
        self.signed_info
            .iter()
            .chain(&self.manifest)
            .find(|reference| reference.include_uri == Some(uri))
            .map(|reference| reference.node)
    }

    /// Whether `signed` digested the same bytes for every reference `stamps`
    /// cover as this dry run did.
    pub(crate) fn unchanged(
        &self,
        signed: &SigningInputs,
        stamps: &[ContentTimestamp<'_>],
    ) -> bool {
        let now: Vec<&Vec<u8>> = signed
            .signed_info_references
            .iter()
            .chain(&signed.manifest_references)
            .collect();
        if now.len() != self.bytes.len() {
            return false;
        }
        let same = |node: usize| {
            now.get(node)
                .is_some_and(|bytes| **bytes == self.bytes[node])
        };
        stamps.iter().all(|stamp| match stamp.scope {
            ContentScope::All => self
                .signed_info
                .iter()
                .filter(|reference| !reference.signed_properties)
                .all(|reference| same(reference.node)),
            ContentScope::Individual(uris) => {
                uris.iter().all(|uri| self.node(uri).is_some_and(same))
            }
        })
    }
}

impl ContentSource for Replayed<'_> {
    type Id = usize;
    type Error = StagedError;

    fn signed_info<W: Work>(
        &self,
        work: &W,
    ) -> Result<&[ContentReference<'_, usize>], StagedError> {
        // The references are already in memory; listing them is one step.
        work.charge_work(1).map_err(|_| StagedError::Method)?;
        Ok(&self.signed_info)
    }

    fn reference<W: Work>(
        &self,
        node: usize,
        work: &W,
    ) -> Result<Option<ContentReference<'_, usize>>, StagedError> {
        work.charge_work(1)
            .map_err(|_| StagedError::Reference(node))?;
        Ok(self
            .signed_info
            .iter()
            .chain(&self.manifest)
            .find(|reference| reference.node == node)
            .copied())
    }

    fn admit_method<W: Work>(&self, method: usize, _: &W) -> Result<(), StagedError> {
        if method == self.method {
            Ok(())
        } else {
            Err(StagedError::Method)
        }
    }

    fn replay<W: Work>(
        &self,
        reference: usize,
        method: usize,
        receiver: &mut impl Receiver,
        work: &W,
    ) -> Result<ReplayOutcome<StagedError>, StagedError> {
        self.admit_method(method, work)?;
        let bytes = self
            .bytes
            .get(reference)
            .ok_or(StagedError::Reference(reference))?;
        work.charge_work(bytes.len() as u64)
            .map_err(|_| StagedError::Reference(reference))?;
        // A refusal stops the stream; the driver observes it on the receiver.
        if receiver.write(bytes).is_err() {
            return Ok(ReplayOutcome::Complete);
        }
        Ok(ReplayOutcome::Complete)
    }
}

impl<'l> ContentWriter<Replayed<'l>> for PropertyDraft<'_> {
    fn matches_content<W: Work>(
        &self,
        source: &Replayed<'l>,
        work: &W,
    ) -> Result<bool, PropertyError> {
        work.charge_work(1)
            .map_err(crate::draft::DraftError::from)?;
        Ok(self.content.is_some_and(|staged| {
            core::ptr::eq(
                core::ptr::from_ref(staged).cast::<()>(),
                core::ptr::from_ref(source).cast::<()>(),
            )
        }))
    }

    fn content_method<W: Work>(&mut self, method: usize, work: &W) -> Result<(), PropertyError> {
        let Some(staged) = self.content else {
            return Err(PropertyError::ContentMethod);
        };
        if method != staged.method {
            return Err(PropertyError::ContentMethod);
        }
        let algorithm = staged.algorithm.clone();
        let event = |draft: &mut Self, event: Event<'_>| draft.write(event, work);
        event(
            self,
            Event::Begin(Name {
                namespace: DS,
                local: "CanonicalizationMethod",
            }),
        )?;
        event(
            self,
            Event::Attribute(
                Name {
                    namespace: "",
                    local: "Algorithm",
                },
                Value {
                    lexical: algorithm.uri(),
                    datatype: Datatype::AnyUri,
                },
            ),
        )?;
        let prefixes = algorithm.inclusive_prefixes();
        if algorithm.mode() == C14nMode::Exclusive1_0 && !prefixes.is_empty() {
            let list = prefixes
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(" ");
            event(
                self,
                Event::Begin(Name {
                    namespace: EXCLUSIVE_C14N,
                    local: "InclusiveNamespaces",
                }),
            )?;
            event(
                self,
                Event::Attribute(
                    Name {
                        namespace: "",
                        local: "PrefixList",
                    },
                    Value {
                        lexical: &list,
                        datatype: Datatype::String,
                    },
                ),
            )?;
            event(self, Event::End)?;
        }
        event(self, Event::End)
    }
}

/// The content inputs of `stamps` over `replayed`, in order.
fn inputs<'r, 'l, W: Work>(
    replayed: &'r Replayed<'l>,
    stamps: &[ContentTimestamp<'_>],
    work: &W,
) -> Result<Vec<ContentInput<'r, Replayed<'l>>>, ContentError> {
    stamps
        .iter()
        .map(|stamp| {
            let selected: Vec<usize>;
            let scope = match stamp.scope {
                ContentScope::All => Selection::All,
                ContentScope::Individual(uris) => {
                    selected = uris
                        .iter()
                        .map(|uri| {
                            replayed
                                .node(uri)
                                .ok_or_else(|| ContentError::UnknownReference((*uri).into()))
                        })
                        .collect::<Result<_, _>>()?;
                    Selection::Individual(&selected)
                }
            };
            ContentInput::prepare(replayed, replayed.method, scope, work)
                .map_err(|error| ContentError::Input(Box::new(error)))
        })
        .collect()
}

/// The DER `AlgorithmIdentifier` of `algorithm` with absent parameters
/// (RFC 5754 §2, RFC 9688 §2).
fn identifier(parser: &Parser, algorithm: digest::Algorithm) -> Result<OwnedVec<u8>, ContentError> {
    let oid = algorithm.identifier().as_bytes();
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
    Ok(der.into_owned())
}

/// The request of each content input, in order.
fn pending<'p, 'r, 'l>(
    inputs: &'p [ContentInput<'r, Replayed<'l>>],
    stamps: &[ContentTimestamp<'_>],
    cms: &'p CmsProvider<'_>,
    parser: &Parser,
) -> Result<Vec<PendingContent<'p, 'r, Replayed<'l>>>, ContentError> {
    inputs
        .iter()
        .zip(stamps)
        .map(|(input, stamp)| {
            let der = identifier(parser, stamp.digest)?;
            let mut reader = parser.read(&der, 0).map_err(ContentError::Asn1)?;
            let element = reader
                .expect(Tag::constructed(universal::SEQUENCE))
                .map_err(ContentError::Asn1)?;
            let algorithm = structured_pkix::algorithm::read(&reader, &element, "hashAlgorithm")
                .map_err(ContentError::Pkix)?;
            input
                .request(
                    cms,
                    &reader,
                    &ContentRequest {
                        algorithm,
                        policy: stamp.policy,
                        nonce: stamp.nonce,
                        cert_req: true,
                        extensions: &[],
                    },
                )
                .map_err(|error| ContentError::Request(Box::new(error)))
        })
        .collect()
}

/// Each content timestamp's request over `replayed`.
pub(crate) fn requests<W: Work>(
    replayed: &Replayed<'_>,
    stamps: &[ContentTimestamp<'_>],
    cms: &CmsProvider<'_>,
    work: &W,
) -> Result<ContentRequests, ContentError> {
    let parser = Parser::der(work.memory().clone());
    let inputs = inputs(replayed, stamps, work)?;
    let pending = pending(&inputs, stamps, cms, &parser)?;
    let mut requests = Vec::with_capacity(pending.len());
    for request in &pending {
        let mut copy = work.memory().vector();
        copy.try_extend_from_slice(request.request_bytes())?;
        requests.push(copy.into_owned());
    }
    Ok(ContentRequests { requests })
}

/// Check each content timestamp's response against its request and input,
/// then run `then` with each input and its checked token, in order.
pub(crate) fn with_checked<'l, W: Work, R, E: From<ContentError>>(
    replayed: &Replayed<'l>,
    stamps: &[ContentTimestamp<'_>],
    evidence: Option<&ContentEvidence<'_>>,
    cms: &CmsProvider<'_>,
    work: &W,
    then: impl FnOnce(
        &[(
            &ContentInput<'_, Replayed<'l>>,
            CheckedContent<'_, '_, '_, Replayed<'l>>,
        )],
    ) -> Result<R, E>,
) -> Result<R, E> {
    let evidence = evidence.ok_or(ContentError::MissingEvidence)?;
    let parser = Parser::der(work.memory().clone());
    let operation = parser.read(&[], 0).map_err(ContentError::Asn1)?;
    let inputs = inputs(replayed, stamps, work)?;
    let pending = pending(&inputs, stamps, cms, &parser)?;
    let mut responses = Vec::with_capacity(stamps.len());
    for (index, stamp) in stamps.iter().enumerate() {
        let bytes = stamp.response.ok_or(ContentError::MissingResponse(index))?;
        let mut source = parser.read(bytes, 0).map_err(ContentError::Asn1)?;
        responses.push(Response::read(&mut source).map_err(ContentError::Message)?);
    }
    let mut asked = Vec::with_capacity(pending.len());
    for request in &pending {
        asked.push(
            parser
                .read(request.request_bytes(), 0)
                .map_err(ContentError::Asn1)?,
        );
    }
    let mut requests = Vec::with_capacity(asked.len());
    for reader in &mut asked {
        let element = reader
            .expect(Tag::constructed(universal::SEQUENCE))
            .map_err(ContentError::Asn1)?;
        requests.push(Request::read(reader, &element).map_err(ContentError::Message)?);
    }
    let supplied = read_certificates(&parser, evidence.certificates).map_err(ContentError::from)?;
    let stated = accuracy::read(&parser, evidence.accuracies).map_err(ContentError::from)?;
    let mut carriers = Vec::with_capacity(responses.len());
    for response in &responses {
        let status = response.status().status();
        if !status.granted() || response.token().is_none() {
            return Err(ContentError::Refused(status).into());
        }
        carriers.push(
            response
                .token_reader_in(&operation)
                .map_err(ContentError::Message)?
                .ok_or(ContentError::Refused(status))?,
        );
    }
    let mut checked = Vec::with_capacity(responses.len());
    for (((response, carrier), (request, reader)), pending) in responses
        .iter()
        .zip(&carriers)
        .zip(requests.iter().zip(&asked))
        .zip(&pending)
    {
        let status = response.status().status();
        let token = response.token().ok_or(ContentError::Refused(status))?;
        let (certificate, certificate_parent) =
            authority(token, carrier, [&supplied, &[]], &operation)
                .map_err(|error| match error {
                    crate::AugmentError::Signer(error) => ContentError::Signer(error),
                    _ => ContentError::MissingAuthority,
                })?
                .ok_or(ContentError::MissingAuthority)?;
        let policy_accuracy = accuracy::select_outside(&stated, token, carrier, &operation)
            .map_err(ContentError::from)?;
        let context = CheckContext {
            certificate,
            certificate_parent,
            key: EffectiveKey::standing(certificate.tbs().public_key()),
            requested: Some(Requested {
                request,
                parent: reader,
            }),
            utc: evidence.utc,
            // The signature that would bound the token's time does not exist
            // yet; its B-B assessment orders the token against it.
            reference: None,
            window: evidence.window,
            policy_accuracy,
        };
        let result = pending
            .check_response(
                &ResponseCheck {
                    response,
                    provider: cms,
                    query: &operation,
                    context: &context,
                },
                unrecognized(),
            )
            .map_err(|error| ContentError::Check(Box::new(error)))?;
        let facts = result
            .facts()
            .timestamp()
            .ok_or(ContentError::Refused(status))?;
        if facts.evidence().is_none() {
            return Err(ContentError::Unproven(TokenFacts {
                imprint: facts.imprint,
                requested_imprint: facts.requested_imprint,
                requested_fields: facts.requested_fields,
                timeliness: facts.timeliness,
            })
            .into());
        }
        checked.push(result);
    }
    let pairs: Vec<_> = inputs.iter().zip(checked).collect();
    then(&pairs)
}
