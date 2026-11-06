//! B-LT augmentation: the validation data a B-T signature lacks.

use super::{AugmentError, Publication, Staging, construction, pooled, publish, selected};
use crate::basic::Outcome;
use crate::create::Assessment;
use crate::draft::Draft;
use crate::level::{Census, Inputs, Level, Visit, validate_with};
use crate::placement::{self, Unsigned};
use alloc::string::String;
use core::convert::Infallible;
use structured_asn1::memory::{OwnedVec, Work};
use structured_ltv::material::ArtifactRef;
use structured_xades::produce::{Material, write_material};
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
    let requirements = data.inputs.requirements;
    if matches!(
        requirements,
        Requirements::Basic | Requirements::Timestamped
    ) {
        return Err(AugmentError::BelowLongTerm(requirements));
    }
    let assessment = data.assessment;
    let unsigned = document.with_view(|view| {
        placement::locate(view, data.signature, data.id_attributes, work)
            .map(|located| located.unsigned)
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
                    match validate_with(&session, node, &census, Missing { unsigned })? {
                        Outcome::Assessed(property) => property,
                        outcome => Err(AugmentError::Unmet(outcome.map(|_| ()))),
                    }
                }),
            )
        },
    )??;
    let added = if property.is_some() {
        DataAdded::Published
    } else {
        DataAdded::AlreadyPresent
    };
    publish(
        document,
        &Publication {
            assessment,
            inputs: &inputs,
            signature: data.signature,
            id_attributes: data.id_attributes,
            unsigned,
        },
        property.as_deref(),
        work,
    )?;
    Ok(added)
}

/// The census visitor: the missing values as one property, if any.
struct Missing {
    unsigned: Unsigned,
}

impl Visit for Missing {
    type Output = Result<Option<String>, AugmentError>;

    // Only a validation that ended before its B-LT census reaches this.
    fn level(self, level: &Level<'_>) -> Self::Output {
        Err(AugmentError::BelowLongTerm(level.requested()))
    }

    fn census<W: Work>(
        self,
        census: &Census<'_, '_, '_, '_, '_, '_, '_, W>,
    ) -> Result<Self::Output, Self> {
        Ok(missing(census, self.unsigned))
    }
}

/// The `AnyValidationData` of every value B-LT still needs, if any. Whether
/// the signature also meets B-T is left to the assessment of the result,
/// since B-LT includes it (EN 319 132-1 §6.3).
fn missing<W: Work>(
    census: &Census<'_, '_, '_, '_, '_, '_, '_, W>,
    unsigned: Unsigned,
) -> Result<Option<String>, AugmentError> {
    let stage = census.stage();
    let work = stage.session.execution();
    let entries = plan(census, work)?;
    if entries.is_empty() {
        return Ok(None);
    }
    let mut staging = Staging {
        session: stage.session,
        base: stage.document.snapshot(),
        signature: stage.prepared.bound().containers().signature(),
        unsigned: unsigned.signature_properties(),
        draft: Draft::new(),
    };
    write_material(&entries, &mut staging, work).map_err(construction)?;
    Ok(Some(staging.draft.finish()?.0))
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
