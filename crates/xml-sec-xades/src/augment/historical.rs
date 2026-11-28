//! The signature timestamp of a signature in a historical vocabulary: ETSI
//! TS 101 903 V1.1.1 or V1.2.2, or the TS 103 171 profile of V1.3.2.

use super::extended::{CompleteReferences, ExtendedKind, reference_error, signer_artifacts};
use super::{
    AugmentError, Checking, Completion, DataAdded, PendingTimestamp, Repeat, Staging, StagingError,
    Stamp, TimestampRequest, ValidationData, checked_response, construction, pooled, selected,
    unproven, with_algorithm,
};
use crate::create::{Assessment, Carried};
use crate::draft::Draft;
use crate::level::historical::{HistoricalCensus, historical_tsa_paths, with_historical_census};
use crate::level::{Inputs, unrecognized};
use crate::path;
use crate::placement::{self, DS, PlacementError, Unsigned};
use crate::signature::hash_class;
use crate::ts101903::{Ts101903Report, validate_historical};
use crate::{Document, Outcome};
use alloc::{boxed::Box, string::String, vec::Vec};
use core::convert::Infallible;
use structured_asn1::digest::Resolution;
use structured_asn1::memory::{OwnedVec, Work};
use structured_ltv::material::ArtifactRef;
use structured_xades::legacy::{self, Profile};
use structured_xades::produce::References;
use structured_xades::produce::{
    ContentRequest, Event, ExtendedAugmentation, HistoricalTimestampWriter, Material,
    ReferenceRole, Writer, write_historical_values,
};
use structured_xades::unsigned::Requirements;
use structured_xades::xml::{Access, Name, Xml as _};
use xml_sec::document::{DocumentView, NodeIdentity, XmlDocument};
use xml_sec::xmldsig::DigestAlgorithm;
use xml_sec::xmldsig::VerificationRequest;
use xml_sec::xmldsig::{ReplayError, VerifiedSession, with_verified_request};

/// Compute the `SignatureTimeStamp` input of `request.signature`, a
/// signature in the vocabulary of `profile`, and encode the RFC 3161 request
/// for it.
///
/// The signature must meet the BES requirements of `profile` under
/// `assessment`. The input is its `SignatureValue` canonicalized with its own
/// `CanonicalizationMethod`; the completed property names it as that
/// profile's grammar does. Pass the response to [`super::complete_timestamp`].
///
/// # Errors
/// Returns the original cause; the document is never changed.
///
/// # Examples
///
/// ```no_run
/// use structured_pkix::algorithm::digest::Algorithm;
/// use xml_sec_xades::properties::Profile;
/// use xml_sec_xades::{Assessment, TimestampRequest, request_historical_timestamp};
/// # fn t(
/// #     document: &xml_sec::XmlDocument,
/// #     assessment: &Assessment<'_, '_>,
/// #     work: &structured_asn1::memory::Memory,
/// # ) -> Result<xml_sec_xades::PendingTimestamp, xml_sec_xades::AugmentError> {
/// request_historical_timestamp(
///     document,
///     &TimestampRequest {
///         signature: "sig",
///         digest: Algorithm::Sha256,
///         policy: None,
///         nonce: Some(&[0x2a; 8]),
///         id_attributes: &[],
///     },
///     Profile::PreEn,
///     assessment,
///     work,
/// )
/// # }
/// ```
pub fn request_historical_timestamp<W: Work>(
    document: &XmlDocument,
    request: &TimestampRequest<'_>,
    profile: Profile,
    assessment: &Assessment<'_, '_>,
    work: &W,
) -> Result<PendingTimestamp, AugmentError> {
    request_stamp(document, request, (profile, None), assessment, work)
}

/// Compute the input of a new `kind` timestamp of `request.signature`, a
/// signature in the TS 103 171 profile of V1.3.2, and encode the RFC 3161
/// request for it: the X timestamp of its XAdES-X over the references
/// [`add_historical_references`] added, or the archive timestamp of its
/// XAdES-A (ETSI TS 101 903 V1.4.2 §§7.5, 8.2).
///
/// The signature must meet the BES requirements of the profile under
/// `assessment`; the input is canonicalized with its own
/// `CanonicalizationMethod`. Pass the response to
/// [`super::complete_timestamp`].
///
/// # Errors
/// Returns the original cause, [`AugmentError::HistoricalLevel`] for the
/// V1.1.1 and V1.2.2 vocabularies; the document is never changed.
///
/// # Examples
///
/// ```no_run
/// use structured_pkix::algorithm::digest::Algorithm;
/// use xml_sec_xades::properties::Profile;
/// use xml_sec_xades::{
///     Assessment, ExtendedKind, ReferenceSyntax, TimestampRequest,
///     request_historical_extended_timestamp,
/// };
/// # fn x(
/// #     document: &xml_sec::XmlDocument,
/// #     assessment: &Assessment<'_, '_>,
/// #     work: &structured_asn1::memory::Memory,
/// # ) -> Result<xml_sec_xades::PendingTimestamp, xml_sec_xades::AugmentError> {
/// request_historical_extended_timestamp(
///     document,
///     &TimestampRequest {
///         signature: "sig",
///         digest: Algorithm::Sha256,
///         policy: None,
///         nonce: Some(&[0x2a; 8]),
///         id_attributes: &[],
///     },
///     ExtendedKind::SignatureAndReferences(ReferenceSyntax::Original),
///     Profile::PreEn,
///     assessment,
///     work,
/// )
/// # }
/// ```
pub fn request_historical_extended_timestamp<W: Work>(
    document: &XmlDocument,
    request: &TimestampRequest<'_>,
    kind: ExtendedKind,
    profile: Profile,
    assessment: &Assessment<'_, '_>,
    work: &W,
) -> Result<PendingTimestamp, AugmentError> {
    if profile != Profile::PreEn {
        return Err(AugmentError::HistoricalLevel(profile));
    }
    request_stamp(document, request, (profile, Some(kind)), assessment, work)
}

/// The request of a historical signature timestamp, or of a `kind` one.
fn request_stamp<W: Work>(
    document: &XmlDocument,
    request: &TimestampRequest<'_>,
    (profile, kind): (Profile, Option<ExtendedKind>),
    assessment: &Assessment<'_, '_>,
    work: &W,
) -> Result<PendingTimestamp, AugmentError> {
    let (identity, generation) = document.with_view(|view| {
        placement::locate_in(
            view,
            request.signature,
            request.id_attributes,
            profile.namespace(),
            work,
        )?;
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
                        with_historical(&session, node, profile, assessment, |prepared| {
                            prepared.request(request, kind)
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
        kind: Stamp::Historical(profile, kind),
        basis: Requirements::Basic,
        request: encoded,
        renewal: None,
        repeat: Some(Repeat::of(request)),
    })
}

/// Add to `data.signature`, a signature in the vocabulary of `profile`, the
/// certificates, CRLs and OCSP responses its participants' paths and
/// statuses need and the document lacks, as `CertificateValues` and
/// `RevocationValues` in that vocabulary: the values of ETSI TS 101 903
/// XAdES-X-L (V1.2.2 §7.6) and of the TS 103 171 profile of V1.3.2.
///
/// The census reads the signer's path, every timestamp's TSA path and their
/// statuses from `data.inputs` and the document, as for a baseline level; no
/// EN 319 132-1 level applies to these vocabularies. The new generation is
/// published only if the signature still meets the BES requirements of
/// `profile` and its census then finds nothing missing.
///
/// # Errors
/// Returns the original cause and leaves the document unchanged:
/// [`AugmentError::Unmet`] when a path or a status cannot be established or
/// the result still lacks a value.
///
/// # Examples
///
/// ```no_run
/// use xml_sec_xades::properties::Profile;
/// use xml_sec_xades::{Assessment, Inputs, ValidationData, add_historical_values};
/// # fn lt(
/// #     document: &mut xml_sec::XmlDocument,
/// #     assessment: &Assessment<'_, '_>,
/// #     inputs: &Inputs<'_>,
/// #     work: &structured_asn1::memory::Memory,
/// # ) -> Result<(), xml_sec_xades::AugmentError> {
/// add_historical_values(
///     document,
///     &ValidationData { signature: "sig", assessment, inputs, id_attributes: &[] },
///     Profile::V122,
///     work,
/// )?;
/// # Ok(())
/// # }
/// ```
pub fn add_historical_values<W: Work>(
    document: &mut XmlDocument,
    data: &ValidationData<'_, '_>,
    profile: Profile,
    work: &W,
) -> Result<DataAdded, AugmentError> {
    let assessment = data.assessment;
    let namespace = profile.namespace();
    let held = document.with_view(|view| {
        let located =
            placement::locate_in(view, data.signature, data.id_attributes, namespace, work)?;
        Held::of(view, located.unsigned, profile, work)
    })?;
    let certificates = pooled(data.inputs, assessment, work)?;
    let inputs = Inputs {
        certificates: &certificates,
        ..*data.inputs
    };
    let census = |document: &XmlDocument, request: &VerificationRequest<'_>| {
        with_verified_request(document, assessment.context, request, work, |session| {
            Ok(
                selected(document, &session, data.signature, data.id_attributes).and_then(|node| {
                    match with_historical_census(&session, node, profile, &inputs, |census| {
                        missing_values(census, held, profile)
                    })? {
                        Outcome::Assessed(values) => values,
                        outcome => Err(AugmentError::Unmet(outcome.map(|_| ()))),
                    }
                }),
            )
        })?
    };
    let values = census(document, assessment.request)?;
    if values.is_empty() {
        return Ok(DataAdded::AlreadyPresent);
    }
    document.transaction(|document| {
        insert_values(document, data, namespace, &values, work)?;
        let carried = Carried::new::<_, AugmentError>(document, assessment.request, work)?;
        let completion = Completion {
            assessment,
            inputs: &inputs,
            window: None,
            id_attributes: data.id_attributes,
        };
        require_bes(document, data.signature, profile, &completion, work)?;
        if census(document, &carried.request(assessment.request))?.is_empty() {
            Ok(DataAdded::Published)
        } else {
            Err(AugmentError::Unmet(Outcome::Assessed(())))
        }
    })
}

/// Add to `request.signature`, a signature in the TS 103 171 profile of
/// V1.3.2, the `CompleteCertificateRefs` and `CompleteRevocationRefs` of its
/// signer's path and statuses (ETSI TS 101 903 V1.4.2 §§7.4.1 and 7.4.2), in
/// the syntax `request.syntax` names, as one new generation: its XAdES-C.
///
/// The census reads the signer's path and statuses from `request.inputs` and
/// the document, as [`add_historical_values`] does; the values themselves are
/// not added. The new generation is published only if the signature still
/// meets the BES requirements of the profile.
///
/// # Errors
/// Returns the original cause and leaves the document unchanged:
/// [`AugmentError::HistoricalLevel`] for the V1.1.1 and V1.2.2 vocabularies,
/// and [`AugmentError::Unmet`] when a path or a status cannot be established.
///
/// # Examples
///
/// ```no_run
/// use xml_sec::xmldsig::DigestAlgorithm;
/// use xml_sec_xades::properties::Profile;
/// use xml_sec_xades::{
///     Assessment, CompleteReferences, Inputs, ReferenceSyntax, add_historical_references,
/// };
/// # fn c(
/// #     document: &mut xml_sec::XmlDocument,
/// #     assessment: &Assessment<'_, '_>,
/// #     inputs: &Inputs<'_>,
/// #     work: &structured_asn1::memory::Memory,
/// # ) -> Result<(), xml_sec_xades::AugmentError> {
/// add_historical_references(
///     document,
///     &CompleteReferences {
///         signature: "sig",
///         syntax: ReferenceSyntax::Original,
///         digest: DigestAlgorithm::Sha256,
///         assessment,
///         inputs,
///         id_attributes: &[],
///     },
///     Profile::PreEn,
///     work,
/// )
/// # }
/// ```
pub fn add_historical_references<W: Work>(
    document: &mut XmlDocument,
    request: &CompleteReferences<'_, '_>,
    profile: Profile,
    work: &W,
) -> Result<(), AugmentError> {
    if profile != Profile::PreEn {
        return Err(AugmentError::HistoricalLevel(profile));
    }
    let assessment = request.assessment;
    let namespace = profile.namespace();
    let unsigned = document.with_view(|view| {
        placement::locate_in(
            view,
            request.signature,
            request.id_attributes,
            namespace,
            work,
        )
        .map(|located| located.unsigned)
    })?;
    let certificates = pooled(request.inputs, assessment, work)?;
    let inputs = Inputs {
        certificates: &certificates,
        ..*request.inputs
    };
    let properties = with_verified_request(
        document,
        assessment.context,
        assessment.request,
        work,
        |session| {
            Ok(
                selected(document, &session, request.signature, request.id_attributes).and_then(
                    |node| match with_historical_census(
                        &session,
                        node,
                        profile,
                        &inputs,
                        |census| references(census, unsigned, request),
                    )? {
                        Outcome::Assessed(properties) => properties,
                        outcome => Err(AugmentError::Unmet(outcome.map(|_| ()))),
                    },
                ),
            )
        },
    )??;
    document.transaction(|document| {
        unsigned.insert_in(document, &properties.concat(), namespace)?;
        let completion = Completion {
            assessment,
            inputs: &inputs,
            window: None,
            id_attributes: request.id_attributes,
        };
        require_bes(document, request.signature, profile, &completion, work)
    })
}

/// The reference properties of the census's signer path and statuses.
fn references<W: Work>(
    census: &HistoricalCensus<'_, '_, '_, '_, '_, W>,
    unsigned: Unsigned,
    request: &CompleteReferences<'_, '_>,
) -> Result<Vec<String>, AugmentError> {
    let session = census.session();
    let work = session.execution();
    let signer = census.signer().ok_or(AugmentError::UnboundSigner)?;
    let artifacts = signer_artifacts(
        census.closure(),
        census.access(),
        signer.target().certificate().as_bytes(),
        |value| census.envelope(value),
        work,
    )?;
    let cms = session.cms_provider();
    let mut staging = Staging {
        session,
        base: census.snapshot(),
        signature: census.prepared().binding().containers().signature(),
        unsigned: unsigned.signature_properties(),
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

/// The values containers a signature already holds. TS 101 903 V1.1.1 §7.6
/// allows one `CertificateValues` and one `RevocationValues`, in that order,
/// each `RevocationValues` holding `CRLValues`, `OCSPValues` and
/// `OtherValues` in turn; new values of a V1.1.1 signature join those
/// containers. The later vocabularies repeat them, so nothing is held there.
#[derive(Clone, Copy, Default)]
struct Held {
    certificates: bool,
    revocation: Option<HeldRevocation>,
}

/// The containers a held `RevocationValues` holds.
#[derive(Clone, Copy)]
struct HeldRevocation {
    crls: bool,
    ocsps: bool,
}

impl Held {
    /// The containers of `profile` the `unsigned` properties hold.
    fn of<W: Work>(
        view: DocumentView<'_>,
        unsigned: Unsigned,
        profile: Profile,
        work: &W,
    ) -> Result<Self, PlacementError> {
        let Some(properties) = unsigned.signature_properties() else {
            return Ok(Self::default());
        };
        if profile != Profile::V111 {
            return Ok(Self::default());
        }
        let namespace = profile.namespace();
        let held = |parent, local| {
            Ok::<_, PlacementError>(
                placement::child(view, parent, namespace, local, work)?.is_some(),
            )
        };
        let revocation =
            match placement::child(view, properties, namespace, "RevocationValues", work)? {
                Some(revocation) => Some(HeldRevocation {
                    crls: held(revocation, "CRLValues")?,
                    ocsps: held(revocation, "OCSPValues")?,
                }),
                None => None,
            };
        Ok(Self {
            certificates: held(properties, "CertificateValues")?,
            revocation,
        })
    }
}

/// Where a drafted piece of values joins the signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Join {
    /// A new property after the unsigned signature properties.
    Property,
    /// A new `CertificateValues` before the held `RevocationValues`.
    BeforeRevocation,
    /// Into the held `CertificateValues`.
    Certificates,
    /// A new `CRLValues`, the first child of the held `RevocationValues`.
    FirstInRevocation,
    /// A new `OCSPValues`, before the held `OtherValues` or last.
    AfterCrls,
    /// Into the held `CRLValues`.
    Crls,
    /// Into the held `OCSPValues`.
    Ocsps,
}

/// One output of [`Split`]: the elements at least `skip` levels below the
/// values containers, as siblings.
struct Part {
    draft: Draft,
    skip: usize,
    join: Join,
    used: bool,
}

impl Part {
    fn new(skip: usize, join: Join) -> Self {
        Self {
            draft: Draft::siblings(),
            skip,
            join,
            used: false,
        }
    }

    fn finish(self) -> Result<Option<(String, Join)>, AugmentError> {
        if !self.used {
            return Ok(None);
        }
        Ok(Some((self.draft.finish_siblings()?.concat(), self.join)))
    }
}

/// The values written once, routed to the containers the signature holds:
/// a held container receives only the elements below it, a missing one is
/// written whole.
struct Split {
    path: Vec<&'static str>,
    certificates: Part,
    revocation: Revocation,
}

/// Where the revocation values go.
enum Revocation {
    /// A new `RevocationValues`.
    Whole(Part),
    /// Into the held one: its CRLs and its OCSP responses.
    Held { crls: Part, ocsps: Part },
}

impl Split {
    fn new(held: Held) -> Self {
        let certificates = match (held.certificates, held.revocation.is_some()) {
            (true, _) => Part::new(1, Join::Certificates),
            (false, true) => Part::new(0, Join::BeforeRevocation),
            (false, false) => Part::new(0, Join::Property),
        };
        let nested = |held, into, new| {
            if held {
                Part::new(2, into)
            } else {
                Part::new(1, new)
            }
        };
        let revocation = match held.revocation {
            None => Revocation::Whole(Part::new(0, Join::Property)),
            Some(revocation) => Revocation::Held {
                crls: nested(revocation.crls, Join::Crls, Join::FirstInRevocation),
                ocsps: nested(revocation.ocsps, Join::Ocsps, Join::AfterCrls),
            },
        };
        Self {
            path: Vec::new(),
            certificates,
            revocation,
        }
    }

    /// The part the current element belongs to, if it is written at all.
    fn part(&mut self) -> Option<&mut Part> {
        let part = match (self.path.first().copied(), self.path.get(1).copied()) {
            (Some("CertificateValues" | "AttrAuthoritiesCertValues"), _) => &mut self.certificates,
            (Some(_), second) => match (&mut self.revocation, second) {
                (Revocation::Whole(whole), _) => whole,
                (Revocation::Held { crls, .. }, Some("CRLValues")) => crls,
                (Revocation::Held { ocsps, .. }, Some("OCSPValues")) => ocsps,
                (Revocation::Held { .. }, _) => return None,
            },
            (None, _) => return None,
        };
        (self.path.len() > part.skip).then_some(part)
    }

    fn forward<Q: Work>(&mut self, event: Event<'_>, work: &Q) -> Result<(), StagingError> {
        if let Some(part) = self.part() {
            part.used = true;
            part.draft.write(event, work).map_err(StagingError::Draft)?;
        }
        Ok(())
    }

    /// The pieces in insertion order.
    fn finish(self) -> Result<Vec<(String, Join)>, AugmentError> {
        let mut pieces = Vec::new();
        pieces.extend(self.certificates.finish()?);
        match self.revocation {
            Revocation::Whole(whole) => pieces.extend(whole.finish()?),
            Revocation::Held { crls, ocsps } => {
                pieces.extend(crls.finish()?);
                pieces.extend(ocsps.finish()?);
            }
        }
        Ok(pieces)
    }
}

impl Writer for Split {
    type Error = StagingError;

    fn write<Q: Work>(&mut self, event: Event<'_>, work: &Q) -> Result<(), StagingError> {
        match event {
            Event::Begin(name) => {
                self.path.push(name.local);
                self.forward(event, work)
            }
            Event::End => {
                self.forward(event, work)?;
                self.path.pop();
                Ok(())
            }
            Event::Attribute(..) | Event::Text(_) | Event::Binary(_) => self.forward(event, work),
        }
    }
}

/// Insert `pieces` into `signature`, each where its [`Join`] says; the new
/// properties go in one insertion after the existing ones.
fn insert_values<W: Work>(
    document: &mut XmlDocument,
    data: &ValidationData<'_, '_>,
    namespace: &str,
    pieces: &[(String, Join)],
    work: &W,
) -> Result<(), AugmentError> {
    let mut properties = String::new();
    for (markup, join) in pieces {
        if *join == Join::Property {
            properties.push_str(markup);
            continue;
        }
        // One insertion per generation: each target is located afresh.
        let (node, before) = document.with_view(|view| {
            let located =
                placement::locate_in(view, data.signature, data.id_attributes, namespace, work)?;
            let held = || AugmentError::Construction(structured_xades::produce::Error::Foreign);
            let properties = located.unsigned.signature_properties().ok_or_else(held)?;
            let child = |parent, local| {
                placement::child(view, parent, namespace, local, work)?.ok_or_else(held)
            };
            Ok::<_, AugmentError>(match join {
                Join::Certificates => (child(properties, "CertificateValues")?, false),
                Join::BeforeRevocation => (child(properties, "RevocationValues")?, true),
                Join::Crls => (
                    child(child(properties, "RevocationValues")?, "CRLValues")?,
                    false,
                ),
                Join::Ocsps => (
                    child(child(properties, "RevocationValues")?, "OCSPValues")?,
                    false,
                ),
                Join::FirstInRevocation => {
                    let revocation = child(properties, "RevocationValues")?;
                    let mut first = None;
                    for node in placement::children(view, revocation, work)? {
                        if placement::is_element_node(view, node, work)? {
                            first = Some(node);
                            break;
                        }
                    }
                    first.map_or((revocation, false), |first| (first, true))
                }
                Join::AfterCrls => {
                    let revocation = child(properties, "RevocationValues")?;
                    placement::child(view, revocation, namespace, "OtherValues", work)?
                        .map_or((revocation, false), |other| (other, true))
                }
                Join::Property => unreachable!("new properties are inserted together"),
            })
        })?;
        if before {
            document.insert_before(node, markup)?;
        } else {
            document.append_child(node, markup)?;
        }
    }
    if !properties.is_empty() {
        let unsigned = document.with_view(|view| {
            placement::locate_in(view, data.signature, data.id_attributes, namespace, work)
                .map(|located| located.unsigned)
        })?;
        unsigned.insert_in(document, &properties, namespace)?;
    }
    Ok(())
}

/// The values of every item of validation data the census finds missing,
/// drafted for the containers `held`, none when the document holds them all.
fn missing_values<W: Work>(
    census: &HistoricalCensus<'_, '_, '_, '_, '_, W>,
    held: Held,
    profile: Profile,
) -> Result<Vec<(String, Join)>, AugmentError> {
    let session = census.session();
    let work = session.execution();
    let mut seen = work.map();
    let mut entries = work.vector();
    for entry in census.incorporation().entries() {
        work.charge_work(1)?;
        if entry.occurrence().is_some() {
            continue;
        }
        let artifact = entry.artifact();
        if seen.try_insert(artifact.identity(), ())?.is_some() {
            continue;
        }
        let material = match artifact {
            ArtifactRef::Certificate(value) => Material::certificate(value),
            ArtifactRef::Crl(value) => Material::crl(value),
            ArtifactRef::Ocsp(value) => {
                let envelope = census
                    .envelope(value)
                    .ok_or(AugmentError::MissingEnvelope)?;
                Material::ocsp::<Infallible, _>(envelope, value, work)
                    .map_err(AugmentError::Construction)?
            }
        };
        entries.try_push(material)?;
    }
    if entries.is_empty() {
        return Ok(Vec::new());
    }
    let mut split = Split::new(held);
    write_historical_values(
        &entries,
        profile,
        ReferenceRole::Signature,
        &mut split,
        work,
    )
    .map_err(construction)?;
    split.finish()
}

/// Check `response` against `pending` and publish its token as the
/// `SignatureTimeStamp` of the historical signature, or as its `kind`
/// timestamp, after the new generation still meets the BES requirements of
/// `profile`. `pooled` are the completion's inputs with the assessment's
/// certificates added, which every path check reads.
pub(super) fn complete<W: Work>(
    document: &mut XmlDocument,
    pending: &PendingTimestamp,
    response: &[u8],
    completion: &Completion<'_, '_>,
    pooled: &Inputs<'_>,
    work: &W,
) -> Result<(), AugmentError> {
    let Stamp::Historical(profile, kind) = pending.kind else {
        return Err(AugmentError::Construction(
            structured_xades::produce::Error::Prerequisites,
        ));
    };
    let completion = &Completion {
        inputs: pooled,
        ..*completion
    };
    let assessment = completion.assessment;
    let signature = pending.signature.as_str();
    let namespace = profile.namespace();
    let repeat = pending.repeated()?;
    let request = repeat.request(signature);
    document.transaction(|document| {
        let unsigned = document.with_view(|view| {
            placement::locate_in(view, signature, completion.id_attributes, namespace, work)
                .map(|located| located.unsigned)
        })?;
        let property = with_verified_request(
            document,
            assessment.context,
            assessment.request,
            work,
            |session| {
                Ok(
                    selected(document, &session, signature, completion.id_attributes).and_then(
                        |node| {
                            with_historical(&session, node, profile, assessment, |prepared| {
                                prepared.timestamp(
                                    (&request, kind),
                                    pending,
                                    response,
                                    completion,
                                    unsigned.signature_properties(),
                                )
                            })
                        },
                    ),
                )
            },
        )??;
        unsigned.insert_in(document, &property, namespace)?;
        require_bes(document, signature, profile, completion, work)?;
        require_tsa_paths(document, signature, profile, completion, work)
    })
}

/// Keep the new generation only if every timestamp of signature `id`,
/// the new one included, has a TSA path to the completion's anchors, as a
/// baseline B-T requires; revocation material is not part of a completion.
fn require_tsa_paths<W: Work>(
    document: &XmlDocument,
    id: &str,
    profile: Profile,
    completion: &Completion<'_, '_>,
    work: &W,
) -> Result<(), AugmentError> {
    let assessment = completion.assessment;
    let carried = Carried::new::<_, AugmentError>(document, assessment.request, work)?;
    let outcome = with_verified_request(
        document,
        assessment.context,
        &carried.request(assessment.request),
        work,
        |session| {
            Ok(
                selected(document, &session, id, completion.id_attributes).and_then(|node| {
                    Ok(historical_tsa_paths(
                        &session,
                        node,
                        profile,
                        completion.inputs,
                    )?)
                }),
            )
        },
    )??;
    match outcome {
        Outcome::Assessed(()) => Ok(()),
        outcome => Err(AugmentError::Unmet(outcome)),
    }
}

/// Keep the new generation only if signature `id` still meets the BES
/// requirements of `profile` under the completion's assessment.
fn require_bes<W: Work>(
    document: &XmlDocument,
    id: &str,
    profile: Profile,
    completion: &Completion<'_, '_>,
    work: &W,
) -> Result<(), AugmentError> {
    let assessment = completion.assessment;
    let carried = Carried::new::<_, AugmentError>(document, assessment.request, work)?;
    let outcome = with_verified_request(
        document,
        assessment.context,
        &carried.request(assessment.request),
        work,
        |session| {
            Ok(
                selected(document, &session, id, completion.id_attributes).and_then(|node| {
                    Ok(validate_historical(
                        &session,
                        node,
                        profile,
                        assessment.certificates,
                        bes_met,
                    )?)
                }),
            )
        },
    )??;
    match outcome {
        Outcome::Assessed(true) => Ok(()),
        outcome => Err(AugmentError::Unmet(outcome.map(|_| ()))),
    }
}

/// Whether the report's BES requirements hold; a function item is general
/// over the report's lifetime where a method path is not.
fn bes_met(report: &Ts101903Report<'_>) -> bool {
    report.bes_met()
}

/// The historical signature `node` of a session, prepared for its signature
/// timestamp.
struct Historical<'p, 'c, 'v, 's, 'i, W: Work> {
    checking: &'p Checking<'p, 'v, 's, 'i, W>,
    document: &'p Document<'c, 'v, 's, 'i, W>,
    prepared: &'p legacy::Prepared<Document<'c, 'v, 's, 'i, W>>,
    method: NodeIdentity,
}

/// The prepared input of a new historical timestamp and its DER request.
type Requested<'p, 'c, 'v, 's, 'i, W> = (
    ExtendedAugmentation<'p, Document<'c, 'v, 's, 'i, W>>,
    OwnedVec<u8>,
);

impl<'p, 'c, 'v, 's, 'i, W: Work> Historical<'p, 'c, 'v, 's, 'i, W> {
    /// The input of the new signature timestamp, or of a `kind` one over the
    /// signature's binding, with its DER request for `request`.
    fn augmentation(
        &self,
        request: &TimestampRequest<'_>,
        kind: Option<ExtendedKind>,
    ) -> Result<Requested<'p, 'c, 'v, 's, 'i, W>, AugmentError> {
        let session = self.checking.session;
        let work = session.execution();
        let prepared = match kind {
            None => ExtendedAugmentation::prepare_historical_signature(
                self.document,
                self.prepared,
                self.method,
                work,
            ),
            Some(kind) => ExtendedAugmentation::prepare(
                self.document,
                self.prepared.binding(),
                kind,
                self.method,
                work,
            ),
        };
        let mut augmentation = prepared.map_err(|error| AugmentError::Input(Box::new(error)))?;
        let cms = session.cms_provider();
        let encoded = with_algorithm(self.checking.parser, request.digest, |reader, algorithm| {
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
            let mut owned = work.memory().vector();
            owned.try_extend_from_slice(encoded)?;
            Ok(owned.into_owned())
        })?;
        Ok((augmentation, encoded))
    }

    /// The DER request for `request`.
    fn request(
        &self,
        request: &TimestampRequest<'_>,
        kind: Option<ExtendedKind>,
    ) -> Result<OwnedVec<u8>, AugmentError> {
        Ok(self.augmentation(request, kind)?.1)
    }

    /// The timestamp property of `response`, checked against the request made
    /// again over this generation, which must be `pending`'s.
    fn timestamp(
        &self,
        (request, kind): (&TimestampRequest<'_>, Option<ExtendedKind>),
        pending: &PendingTimestamp,
        response: &[u8],
        completion: &Completion<'_, '_>,
        unsigned: Option<NodeIdentity>,
    ) -> Result<String, AugmentError> {
        let (mut augmentation, encoded) = self.augmentation(request, kind)?;
        if *encoded != *pending.request() {
            return Err(AugmentError::Changed);
        }
        let session = self.checking.session;
        checked_response(
            self.checking,
            pending,
            response,
            completion,
            |check, status| {
                let checked = augmentation
                    .check_response(check, unrecognized())
                    .map_err(|error| AugmentError::Check(Box::new(error)))?;
                if checked.timestamp().is_none() {
                    return Err(unproven(checked.facts(), status));
                }
                let mut staging = Staging {
                    session,
                    base: self.document.snapshot(),
                    signature: self.prepared.binding().containers().signature(),
                    unsigned,
                    draft: Draft::new(),
                };
                // V1.1.1 and V1.2.2 name the stamped SignatureValue in the
                // property (HashDataInfo, Include); the TS 103 171 profile of
                // V1.3.2 writes the property as EN 319 132-1 does, and so do
                // its X and archive timestamps.
                let written = if kind.is_some() || self.prepared.profile() == Profile::PreEn {
                    augmentation.write_timestamp(&checked, &mut staging, session.execution())
                } else {
                    augmentation.write_historical_timestamp(
                        &checked,
                        &mut staging,
                        session.execution(),
                    )
                };
                written.map_err(construction)?;
                Ok(staging.draft.finish()?.0)
            },
        )
    }
}

/// Run `then` over historical signature `node` read in the vocabulary of
/// `profile`, after it meets that profile's BES requirements.
fn with_historical<W: Work, R>(
    session: &VerifiedSession<'_, '_, '_, W>,
    node: NodeIdentity,
    profile: Profile,
    assessment: &Assessment<'_, '_>,
    then: impl FnOnce(&Historical<'_, '_, '_, '_, '_, W>) -> Result<R, AugmentError>,
) -> Result<R, AugmentError> {
    match validate_historical(session, node, profile, assessment.certificates, bes_met)? {
        Outcome::Assessed(true) => {}
        outcome => return Err(AugmentError::Unmet(outcome.map(|_| ()))),
    }
    let work = session.execution();
    let document = Document::new(session);
    let access = Access::new(&document, document.snapshot(), work);
    let layout = legacy::locate(&access, node, profile)
        .map_err(|error| AugmentError::Historical(alloc::format!("{error:?}")))?;
    let prepared = legacy::prepare(&access, &layout)
        .map_err(|error| AugmentError::Historical(alloc::format!("{error:?}")))?;
    let view = session.view();
    let missing = || AugmentError::NotXades(String::new());
    let signed_info = placement::child(view, node, DS, "SignedInfo", work)?.ok_or_else(missing)?;
    let method = placement::child(view, signed_info, DS, "CanonicalizationMethod", work)?
        .ok_or_else(missing)?;
    let parser = session.certificate_parser();
    let x509 = parser.memory();
    let operation = parser.read(&[], 0).map_err(AugmentError::Asn1)?;
    let signers = path::signers(session, node, &[], x509)?;
    let signer_time = path::verification_time(&signers, node).ok_or_else(missing)?;
    let checking = Checking {
        session,
        parser: &parser,
        operation: &operation,
        signer_time,
    };
    then(&Historical {
        checking: &checking,
        document: &document,
        prepared: &prepared,
        method,
    })
}

impl<W: Work> HistoricalTimestampWriter for Staging<'_, '_, '_, '_, W> {
    fn signature_value_uri<Q: Work>(
        &mut self,
        value: NodeIdentity,
        attribute: Name<'static>,
        work: &Q,
    ) -> Result<(), StagingError> {
        let id = placement::attribute(self.session.view(), value, "Id", work)?
            .ok_or(StagingError::Unidentified)?;
        let uri = alloc::format!("#{}", id.trim());
        self.draft
            .write(
                Event::Attribute(
                    attribute,
                    structured_xades::produce::Value {
                        lexical: &uri,
                        datatype: structured_xades::produce::Datatype::AnyUri,
                    },
                ),
                work,
            )
            .map_err(StagingError::Draft)
    }

    fn canonicalization_transform<Q: Work>(
        &mut self,
        method: NodeIdentity,
        work: &Q,
    ) -> Result<(), StagingError> {
        let view = self.session.view();
        let algorithm = placement::attribute(view, method, "Algorithm", work)?
            .ok_or(StagingError::Unidentified)?;
        self.draft
            .write(
                Event::Begin(Name {
                    namespace: DS,
                    local: "Transform",
                }),
                work,
            )
            .map_err(StagingError::Draft)?;
        self.draft
            .write(
                Event::Attribute(
                    Name {
                        namespace: "",
                        local: "Algorithm",
                    },
                    structured_xades::produce::Value {
                        lexical: algorithm.trim(),
                        datatype: structured_xades::produce::Datatype::AnyUri,
                    },
                ),
                work,
            )
            .map_err(StagingError::Draft)?;
        // The method's parameters, such as an InclusiveNamespaces PrefixList,
        // each canonicalized by itself as a complete element.
        for child in placement::children(view, method, work)? {
            if !placement::is_element_node(view, child, work)? {
                continue;
            }
            let draft = &mut self.draft;
            self.session
                .canonicalize_element(child, child, work, &mut |bytes: &[u8]| {
                    draft.copied(bytes, work)
                })
                .map_err(|error| match error {
                    ReplayError::Processing(error) => StagingError::Method(error),
                    ReplayError::Receiver(error) => StagingError::Draft(error),
                })?;
        }
        self.draft
            .write(Event::End, work)
            .map_err(StagingError::Draft)
    }
}

impl From<PlacementError> for StagingError {
    fn from(error: PlacementError) -> Self {
        Self::Placement(alloc::format!("{error:?}"))
    }
}
