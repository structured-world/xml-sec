//! B-LT augmentation: the validation data a B-T signature lacks.

use super::values::{Held, Join, Split, insert_values};
use super::{AugmentError, Publication, Staging, construction, pooled, publish_with, selected};
use crate::basic::{Outcome, Stage, Vocabulary};
use crate::create::Assessment;
use crate::draft::Draft;
use crate::level::{Census, ExtendedLevel, Inputs, Level, Visit, validate_with};
use crate::placement::{self, Unsigned, XADES};
use alloc::{string::String, vec::Vec};
use core::convert::Infallible;
use structured_asn1::memory::{OwnedVec, Work};
use structured_ltv::material::ArtifactRef;
use structured_xades::produce::{Material, ReferenceRole, write_extended_values, write_material};
use structured_xades::unsigned::Requirements;
use structured_xades::xml::Xml;
use xml_sec::IdAttributeRegistration;
use xml_sec::document::XmlDocument;
use xml_sec::xmldsig::with_verified_request;

/// The validation data to add to one signature, and what the result must meet.
pub struct ValidationData<'a, 'inputs> {
    /// ID of the `Signature` to extend.
    pub signature: &'a str,
    /// The verification that assesses the document before and after the data
    /// is added.
    pub assessment: &'a Assessment<'a, 'inputs>,
    /// The caller's anchors, certificates, CRLs and OCSP responses, and the
    /// level the new generation must meet: B-LT or above.
    pub inputs: &'a Inputs<'a>,
    /// ID attributes beyond the standard spellings.
    pub id_attributes: &'a [IdAttributeRegistration],
}

/// What [`add_validation_data`] did to a document that meets the level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataAdded {
    /// The missing values were published as one new generation.
    Published,
    /// The document already incorporated every value; it is unchanged.
    AlreadyPresent,
}

/// Add to `data.signature` every certificate, CRL and OCSP response its B-LT
/// level (EN 319 132-1 §6.3) needs and the document does not carry where that
/// level accepts it.
///
/// The level validation of the signature decides what is missing, from the
/// paths of its signer, its timestamps and their revocation authorities and
/// the statuses `data.inputs` supplies. That includes a timestamp's own
/// material held only outside the containers §6.3(x) accepts for it, such as a
/// CA certificate shared with the signer and carried only in `KeyInfo`. The
/// values are appended as one new `xades141:AnyValidationData` property:
/// certificates and CRLs as their DER, OCSP responses as the whole
/// `OCSPResponse` the caller supplied or the document holds. The new
/// generation is published only if it meets `data.inputs.requirements`, which
/// also requires every B-T condition.
///
/// # Errors
/// Returns the original cause and leaves the document unchanged:
/// [`AugmentError::BelowLongTerm`] for a request below B-LT,
/// [`AugmentError::Validation`] when the signature lacks the structure the
/// level needs, such as its timestamp, and [`AugmentError::Unmet`] when a path
/// or a status cannot be established from the inputs or the result misses
/// the level.
///
/// # Examples
///
/// ```no_run
/// use xml_sec_xades::{
///     Assessment, DataAdded, Inputs, Requirements, ValidationData, add_validation_data,
/// };
/// # fn extend(
/// #     document: &mut xml_sec::XmlDocument,
/// #     assessment: &Assessment<'_, '_>,
/// #     utc: &structured_pkix::temporal::LeapTable<'_>,
/// #     work: &structured_asn1::memory::Memory,
/// #     root: &[u8],
/// #     crl: &[u8],
/// #     ocsp: &[u8],
/// # ) -> Result<(), xml_sec_xades::AugmentError> {
/// let inputs = Inputs {
///     requirements: Requirements::LongTerm,
///     anchors: &[root],
///     certificates: &[],
///     utc,
///     accuracies: &[],
///     responders: &[],
///     crls: &[crl],
///     responses: &[ocsp],
/// };
/// let added = add_validation_data(
///     document,
///     &ValidationData {
///         signature: "sig",
///         assessment,
///         inputs: &inputs,
///         id_attributes: &[],
///     },
///     work,
/// )?;
/// assert!(matches!(added, DataAdded::Published | DataAdded::AlreadyPresent));
/// # Ok(())
/// # }
/// ```
pub fn add_validation_data<W: Work>(
    document: &mut XmlDocument,
    data: &ValidationData<'_, '_>,
    work: &W,
) -> Result<DataAdded, AugmentError> {
    added(document, data, Form::Any, work)
}

/// Add to `data.signature` the values of `XAdES-XL` (ETSI TS 101 903 V1.4.2
/// §§7.6.1 and 7.6.2): every certificate, CRL and OCSP response the B-LT
/// census of the signature finds missing, as direct `CertificateValues` and
/// `RevocationValues` properties rather than one `AnyValidationData`.
///
/// The references of `XAdES-C` keep a signature from B-LT (EN 319 132-1
/// §6.3), so the new generation is assessed at `data.inputs.requirements`,
/// B-T or above.
///
/// # Errors
/// As for [`add_validation_data`], with [`AugmentError::BelowTimestamped`]
/// for a request below B-T.
///
/// # Examples
///
/// ```no_run
/// use xml_sec_xades::{
///     Assessment, DataAdded, Inputs, Requirements, ValidationData, add_extended_values,
/// };
/// # fn xl(
/// #     document: &mut xml_sec::XmlDocument,
/// #     assessment: &Assessment<'_, '_>,
/// #     inputs: &Inputs<'_>,
/// #     work: &structured_asn1::memory::Memory,
/// # ) -> Result<(), xml_sec_xades::AugmentError> {
/// let inputs = Inputs { requirements: Requirements::Timestamped, ..*inputs };
/// let added = add_extended_values(
///     document,
///     &ValidationData { signature: "sig", assessment, inputs: &inputs, id_attributes: &[] },
///     work,
/// )?;
/// assert!(matches!(added, DataAdded::Published | DataAdded::AlreadyPresent));
/// # Ok(())
/// # }
/// ```
pub fn add_extended_values<W: Work>(
    document: &mut XmlDocument,
    data: &ValidationData<'_, '_>,
    work: &W,
) -> Result<DataAdded, AugmentError> {
    added(document, data, Form::Direct, work)
}

/// Where the census's values go, and whose statuses come first.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Form {
    /// One `AnyValidationData`, the document's statuses first.
    Any,
    /// One `AnyValidationData`, the caller's statuses first.
    Refresh,
    /// Direct `CertificateValues` and `RevocationValues`.
    Direct,
}

impl Form {
    /// The vocabulary the signature is read in: the values of `XAdES-XL`
    /// follow the references of `XAdES-C`.
    fn vocabulary(self) -> Vocabulary {
        match self {
            Self::Any | Self::Refresh => Vocabulary::Baseline,
            Self::Direct => Vocabulary::ExtendedV2,
        }
    }
}

/// Add to `data.signature` the caller's statuses for its paths that the
/// document does not yet carry, even where the document's own statuses
/// already meet B-LT: before a new archive, fresher CRLs and OCSP responses
/// join the validation data an archive timestamp will protect
/// (EN 319 132-1 §5.5.2 lets an augmentation add validation data).
///
/// Each path member takes its status from `data.inputs` first and from the
/// document only when the caller supplies none for it; the values the
/// document already holds byte for byte are not added again. The result is
/// published as one `AnyValidationData`, under the same assessment as
/// [`add_validation_data`].
///
/// # Errors
/// As for [`add_validation_data`].
///
/// # Examples
///
/// ```no_run
/// use xml_sec_xades::{
///     Assessment, DataAdded, Inputs, Requirements, ValidationData, refresh_validation_data,
/// };
/// # fn refresh(
/// #     document: &mut xml_sec::XmlDocument,
/// #     assessment: &Assessment<'_, '_>,
/// #     inputs: &Inputs<'_>,
/// #     work: &structured_asn1::memory::Memory,
/// # ) -> Result<(), xml_sec_xades::AugmentError> {
/// let added = refresh_validation_data(
///     document,
///     &ValidationData { signature: "sig", assessment, inputs, id_attributes: &[] },
///     work,
/// )?;
/// assert!(matches!(added, DataAdded::Published | DataAdded::AlreadyPresent));
/// # Ok(())
/// # }
/// ```
pub fn refresh_validation_data<W: Work>(
    document: &mut XmlDocument,
    data: &ValidationData<'_, '_>,
    work: &W,
) -> Result<DataAdded, AugmentError> {
    added(document, data, Form::Refresh, work)
}

/// The census of `data`, its missing values published in `form`.
fn added<W: Work>(
    document: &mut XmlDocument,
    data: &ValidationData<'_, '_>,
    form: Form,
    work: &W,
) -> Result<DataAdded, AugmentError> {
    let requirements = data.inputs.requirements;
    match (form, requirements) {
        (Form::Direct, Requirements::Basic) => {
            return Err(AugmentError::BelowTimestamped(requirements));
        }
        (Form::Any | Form::Refresh, Requirements::Basic | Requirements::Timestamped) => {
            return Err(AugmentError::BelowLongTerm(requirements));
        }
        _ => {}
    }
    let assessment = data.assessment;
    let (unsigned, held) = document.with_view(|view| {
        let unsigned = placement::locate(view, data.signature, data.id_attributes, work)?.unsigned;
        // Direct values join the containers the signature holds; the
        // general AnyValidationData repeats.
        let held = match form {
            Form::Direct => Held::of(view, unsigned, XADES, work)?,
            Form::Any | Form::Refresh => Held::default(),
        };
        Ok::<_, AugmentError>((unsigned, held))
    })?;
    let certificates = pooled(data.inputs, assessment, work)?;
    let inputs = Inputs {
        certificates: &certificates,
        ..*data.inputs
    };
    // The census of B-LT decides what is missing; a higher level adds no
    // validation data of its own.
    let census = Inputs {
        requirements: Requirements::LongTerm,
        ..inputs
    };
    let property = with_verified_request(
        document,
        assessment.context,
        assessment.request,
        work,
        |session| {
            Ok(
                selected(document, &session, data.signature, data.id_attributes).and_then(|node| {
                    let visitor = Missing {
                        unsigned,
                        held,
                        form,
                    };
                    match validate_with(&session, node, &census, form.vocabulary(), visitor)? {
                        Outcome::Assessed(property) => property,
                        outcome => Err(AugmentError::Unmet(outcome.map(|_| ()))),
                    }
                }),
            )
        },
    )??;
    let added = if property.is_empty() {
        DataAdded::AlreadyPresent
    } else {
        DataAdded::Published
    };
    publish_with(
        document,
        &Publication {
            assessment,
            inputs: &inputs,
            vocabulary: form.vocabulary(),
            signature: data.signature,
            id_attributes: data.id_attributes,
            unsigned,
        },
        |document| insert_values(document, data, XADES, &property, work),
        work,
    )?;
    Ok(added)
}

/// The census visitor: the missing values as properties, if any.
struct Missing {
    unsigned: Unsigned,
    held: Held,
    form: Form,
}

impl<W: Work> Visit<W> for Missing {
    type Output = Result<Vec<(String, Join)>, AugmentError>;

    fn supplied_first(&self) -> bool {
        self.form == Form::Refresh
    }

    // Only a validation that ended before its B-LT census reaches these.
    fn level(self, _stage: &Stage<'_, '_, '_, '_, W>, level: &Level<'_>) -> Self::Output {
        Err(AugmentError::BelowLongTerm(level.requested()))
    }

    fn extended(self, _stage: &Stage<'_, '_, '_, '_, W>, level: ExtendedLevel) -> Self::Output {
        Err(AugmentError::BelowLongTerm(level.requested()))
    }

    fn census(self, census: &Census<'_, '_, '_, '_, '_, '_, '_, W>) -> Result<Self::Output, Self> {
        Ok(missing(census, self.unsigned, self.held, self.form))
    }
}

/// The properties of every value B-LT still needs, none when nothing is
/// missing. Whether the signature also meets B-T is left to the assessment
/// of the result, since B-LT includes it (EN 319 132-1 §6.3).
fn missing<W: Work>(
    census: &Census<'_, '_, '_, '_, '_, '_, '_, W>,
    unsigned: Unsigned,
    held: Held,
    form: Form,
) -> Result<Vec<(String, Join)>, AugmentError> {
    let stage = census.stage();
    let work = stage.session.execution();
    let entries = plan(census, work)?;
    if entries.is_empty() {
        return Ok(Vec::new());
    }
    if form == Form::Direct {
        let mut split = Split::new(held);
        write_extended_values(&entries, ReferenceRole::Signature, &mut split, work)
            .map_err(construction)?;
        return split.finish();
    }
    let mut staging = Staging {
        session: stage.session,
        base: stage.document.snapshot(),
        signature: stage.prepared.bound().containers().signature(),
        unsigned: unsigned.signature_properties(),
        draft: Draft::siblings(),
    };
    write_material(&entries, &mut staging, work).map_err(construction)?;
    Ok(staging
        .draft
        .finish_siblings()?
        .into_iter()
        .map(|property| (property, Join::Property))
        .collect())
}

/// Every value B-LT needs that has no eligible copy, each once: first those
/// the document lacks entirely, then a timestamp's own material whose copies
/// all sit outside the containers EN 319 132-1 §6.3(x) accepts for it, such
/// as a CA certificate shared with the signer and carried only in `KeyInfo`.
/// A general `AnyValidationData` is eligible for both.
fn plan<'r, W: Work, Q: Work>(
    census: &Census<'r, '_, '_, '_, '_, '_, '_, W>,
    work: &Q,
) -> Result<OwnedVec<Material<'r, 'r>>, AugmentError> {
    let checks = census.checks();
    let mut seen = work.map();
    let mut entries = work.vector();
    let mut add = |artifact: ArtifactRef<'r, 'r>| -> Result<(), AugmentError> {
        if seen.try_insert(artifact.identity(), ())?.is_some() {
            return Ok(());
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
        Ok(())
    };
    for entry in checks.presence().entries() {
        work.charge_work(1)?;
        if entry.occurrence().is_none() {
            add(entry.artifact())?;
        }
    }
    for finding in checks.timestamps().findings() {
        work.charge_work(1)?;
        add(finding.artifact)?;
    }
    Ok(entries.into_owned())
}
