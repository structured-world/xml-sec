//! `XAdES` B-B creation and countersigning over the `XMLDSig` signer.
//!
//! The signed properties come from the shared `structured_xades::produce`
//! rules through a [`Draft`]; the signature itself is built, signed and
//! committed by xml-sec with the caller's key and selected provider. Each
//! operation verifies the signed generation and runs the B-B assessment of
//! [`validate_basic`] before it publishes anything: a signature that does not
//! meet every B-B requirement is never left in the document.

use crate::basic::{Outcome, ValidationError, validate_basic};
use crate::draft::{Draft, DraftError};
use alloc::{collections::BTreeMap, format, string::String, vec::Vec};
use structured_asn1::Parser;
use structured_asn1::memory::{MemoryError, OwnedVec, Work};
use structured_pkix::Certificate;
use structured_xades::produce::{self, ReferenceKind};
use xml_sec::IdAttributeRegistration;
use xml_sec::c14n::C14nAlgorithm;
use xml_sec::document::{DocumentView, NodeIdentity, XmlDocument, XmlDocumentError};
use xml_sec::policy::SigningPolicy;
use xml_sec::provider::{CryptoProvider, ProviderError};
use xml_sec::xmldsig::extension::{self, InspectionError, NodeView, ScalarError, TreeError};
use xml_sec::xmldsig::parse::{KeyInfoParsingSession, ParseError};
use xml_sec::xmldsig::{
    CallerTrustedSignatureKey, DigestAlgorithm, DsigError, KeyInfoWriteError, ObjectBuilder,
    ObjectContent, ObjectElement, ReferenceBuilder, SignContext, SignatureAlgorithm,
    SignatureBuilder, SignatureBuilderError, SignatureTemplateSelection, SigningError, SigningKey,
    Transform, VerificationRequest, VerifyContext, X509CertificateKeyInfoWriter,
    compute_digest_with_provider, with_verified_request,
};

const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";

/// The signing key, its certificates and the algorithms of one signer.
pub struct Signer<'a> {
    /// Private key of the signing certificate.
    pub key: &'a dyn SigningKey,
    /// Provider for every digest and the signature value.
    pub provider: &'a dyn CryptoProvider,
    /// Immutable policy snapshot of the signing operation.
    pub policy: &'a SigningPolicy,
    /// The signing certificate first, then any issuers to carry in `KeyInfo`.
    pub chain: &'a [&'a [u8]],
    /// `SignatureMethod` of the new signature.
    pub method: SignatureAlgorithm,
    /// Digest of every reference and of the signing certificate.
    pub digest: DigestAlgorithm,
    /// `CanonicalizationMethod` and the canonicalization of XML references.
    pub canonicalization: C14nAlgorithm,
}

/// How a document-wide reference leaves signatures out of what it signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Envelope {
    /// The enveloped-signature transform removes only the new signature.
    /// A later signature over the same document changes what this one signs.
    Enveloped,
    /// An `XPath` filter removes every signature, so parallel signatures over
    /// the document, added before or after this one, leave it intact.
    ExcludingSignatures,
}

/// One data object the new signature signs, with its MIME type
/// (EN 319 132-1 §5.2.4 `DataObjectFormat`).
#[derive(Debug, Clone)]
pub enum DataObject<'a> {
    /// The whole document holding the signature (enveloped).
    Document {
        /// MIME type of the document.
        mime_type: &'a str,
        /// How other signatures are left out.
        envelope: Envelope,
    },
    /// One element of the same document, selected by its ID; with the
    /// signature outside it, this is an internally detached signature.
    Element {
        /// ID of the element.
        id: &'a str,
        /// MIME type of the element.
        mime_type: &'a str,
    },
    /// Bytes outside the document, supplied with [`Request::resources`].
    Detached {
        /// URI identifying the bytes.
        uri: &'a str,
        /// MIME type of the bytes.
        mime_type: &'a str,
    },
    /// Content carried in a new `Object` of the signature (enveloping).
    Enveloping {
        /// The object content.
        content: ObjectContent,
        /// MIME type of the content.
        mime_type: &'a str,
    },
}

/// What one new signature signs and where it goes.
pub struct Request<'a> {
    /// ID of the new `Signature`. The IDs of its parts derive from it, as
    /// `{id}-signed-properties`, `{id}-value`, `{id}-reference-{n}` and
    /// `{id}-object-{n}`; none of them may already be declared.
    pub id: &'a str,
    /// Claimed signing time, an XML Schema dateTime with an explicit timezone.
    /// This is the signer's claim, not a clock reading or temporal evidence.
    pub signing_time: &'a str,
    /// The data objects, in reference order. Enveloping content moves into
    /// the signature.
    pub objects: Vec<DataObject<'a>>,
    /// ID of the element the signature is appended to; the document element
    /// when absent.
    pub parent: Option<&'a str>,
    /// Detached data, keyed as the signing operation resolves its URIs.
    pub resources: Option<&'a BTreeMap<String, Vec<u8>>>,
    /// ID attributes beyond the standard spellings.
    pub id_attributes: &'a [IdAttributeRegistration],
}

/// A countersignature of one existing `XAdES` signature
/// (EN 319 132-1 §5.2.7.2).
pub struct Countersignature<'a> {
    /// ID of the countersigned `Signature`.
    pub parent: &'a str,
    /// ID of the new countersignature; its parts derive from it as in [`Request::id`].
    pub id: &'a str,
    /// Claimed signing time, as in [`Request::signing_time`].
    pub signing_time: &'a str,
    /// ID attributes beyond the standard spellings.
    pub id_attributes: &'a [IdAttributeRegistration],
}

/// The verification that assesses the signed generation before it is published.
pub struct Assessment<'a, 'inputs> {
    /// Verification context: policy and the key resolver with the caller's
    /// trust anchors for the signer's certificate path.
    pub context: &'a VerifyContext<'inputs>,
    /// Request data of that verification, such as detached data.
    pub request: &'a VerificationRequest<'inputs>,
    /// Certificates beyond `KeyInfo` that [`validate_basic`] may use.
    pub certificates: &'a [&'a [u8]],
}

/// A creation that published nothing, with its original cause.
#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    /// The signer carries no certificate.
    #[error("the signing certificate chain is empty")]
    EmptyChain,
    /// The signing certificate could not be read, with the original cause,
    /// including a work or storage refusal.
    #[error("the signing certificate could not be read: {0}")]
    Certificate(structured_pkix::Error),
    /// Bytes follow the signing certificate's DER encoding.
    #[error("the signing certificate is followed by other bytes")]
    TrailingBytes,
    /// A signature signs at least one data object (EN 319 132-1 §6.3).
    #[error("a XAdES signature signs at least one data object")]
    NoDataObject,
    /// One of the new IDs is already declared in the document.
    #[error("ID {0:?} is already declared in the document")]
    IdInUse(String),
    /// No `Signature` element has the parent ID.
    #[error("no Signature has the ID {0:?}")]
    UnknownSignature(String),
    /// The parent has no `QualifyingProperties` targeting it.
    #[error("signature {0:?} has no XAdES qualifying properties")]
    NotXades(String),
    /// The parent's `SignatureValue` has no ID a countersignature can
    /// reference. Adding one would change bytes its timestamps may cover.
    #[error("signature {0:?} has no SignatureValue ID to countersign")]
    Uncountersignable(String),
    /// The shared property rules refused a value.
    #[error("property construction refused: {0:?}")]
    Properties(produce::Error<DraftError>),
    /// The property draft could not be completed.
    #[error(transparent)]
    Draft(#[from] DraftError),
    /// The signature template was refused.
    #[error(transparent)]
    Template(#[from] SignatureBuilderError),
    /// The certificates could not be prepared for `KeyInfo`.
    #[error(transparent)]
    KeyInfo(#[from] KeyInfoWriteError),
    /// The operation's certificate account could not be opened.
    #[error(transparent)]
    KeyInfoAccount(#[from] ParseError),
    /// The provider could not digest the signing certificate.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// Signing failed.
    #[error(transparent)]
    Signing(#[from] SigningError),
    /// The document refused a mutation.
    #[error(transparent)]
    Document(#[from] XmlDocumentError),
    /// The document could not be read.
    #[error(transparent)]
    Tree(#[from] TreeError),
    /// An attribute of the document could not be read.
    #[error(transparent)]
    Scalar(#[from] ScalarError),
    /// The signed generation did not verify.
    #[error(transparent)]
    Verification(#[from] DsigError),
    /// The signed generation does not satisfy the assessment's verification
    /// request, for example because another signature no longer verifies.
    #[error("the signed generation does not satisfy the verification request")]
    NotAccepted,
    /// The B-B assessment could not complete.
    #[error(transparent)]
    Validation(#[from] ValidationError),
    /// The signed generation does not meet B-B; the outcome names why.
    /// `Assessed` means the report was assembled with an unmet requirement.
    #[error("the signed generation does not meet B-B: {0:?}")]
    Unmet(Outcome<()>),
    /// The current execution refused work or storage.
    #[error("creation resource refusal: {0}")]
    Resource(MemoryError),
}

impl From<MemoryError> for CreateError {
    fn from(error: MemoryError) -> Self {
        Self::Resource(error)
    }
}

/// The IDs of one new signature's parts.
struct Ids {
    signature: String,
    properties: String,
    value: String,
}

impl Ids {
    fn new(signature: &str) -> Self {
        Self {
            signature: signature.into(),
            properties: format!("{signature}-signed-properties"),
            value: format!("{signature}-value"),
        }
    }
}

/// Create a B-B signature over `request.objects` and publish it as one new
/// generation of `document`, after it verifies and meets every B-B
/// requirement of [`validate_basic`] under `assessment`.
///
/// The signing certificate is included in `KeyInfo` and identified by
/// `SigningCertificateV2`; signing refuses a certificate that does not hold
/// the key's public key.
///
/// # Errors
/// Returns the original cause; the document is unchanged.
pub fn create<W: Work>(
    document: &mut XmlDocument,
    signer: &Signer<'_>,
    request: Request<'_>,
    assessment: &Assessment<'_, '_>,
    work: &W,
) -> Result<(), CreateError> {
    if request.objects.is_empty() {
        return Err(CreateError::NoDataObject);
    }
    let ids = Ids::new(request.id);
    // Same-document URIs; the IDs are the text after '#'.
    let references: Vec<String> = (0..request.objects.len())
        .map(|index| format!("#{}-reference-{index}", ids.signature))
        .collect();
    let objects: Vec<String> = (0..request.objects.len())
        .map(|index| format!("#{}-object-{index}", ids.signature))
        .collect();
    let enveloping = request
        .objects
        .iter()
        .zip(&objects)
        .filter(|(object, _)| matches!(object, DataObject::Enveloping { .. }))
        .map(|(_, uri)| &uri[1..]);
    let new_ids: Vec<&str> = [ids.signature.as_str(), &ids.properties, &ids.value]
        .into_iter()
        .chain(references.iter().map(|uri| &uri[1..]))
        .chain(enveloping)
        .collect();
    require_free(document, &new_ids, request.id_attributes)?;

    let described: Vec<produce::DataObject<'_>> = request
        .objects
        .iter()
        .zip(&references)
        .map(|(object, reference)| produce::DataObject {
            reference,
            mime_type: mime_type(object),
        })
        .collect();
    let target = format!("#{}", ids.signature);
    let properties = signed_properties(
        signer,
        &ids,
        &target,
        request.signing_time,
        &described,
        None,
        work,
    )?;

    let Request {
        objects: data,
        parent,
        resources,
        id_attributes,
        ..
    } = request;
    let template = data_template(
        signer,
        data,
        &references,
        &objects,
        signature_template(signer, &ids),
    )
    .add_reference(properties_reference(signer, &ids))
    .add_object(ObjectBuilder::new(ObjectContent::Element(properties)));

    let key_info = key_info(signer)?;
    let mut context = context(signer, &key_info, id_attributes);
    if let Some(resources) = resources {
        context = context.external_resources(resources);
    }
    if let Some(parent) = parent {
        context = context.start_node_id(parent);
    }
    document.transaction(|document| {
        context.sign_document_with_builder(document, &template)?;
        assess(document, &ids.signature, id_attributes, assessment, work)
    })
}

/// Add one reference per data object, in order, and an `Object` holding each
/// enveloping object's content, which moves into the template uncopied.
fn data_template(
    signer: &Signer<'_>,
    data: Vec<DataObject<'_>>,
    references: &[String],
    objects: &[String],
    mut template: SignatureBuilder,
) -> SignatureBuilder {
    let mut enveloping = Vec::new();
    for ((object, reference), object_uri) in data.into_iter().zip(references).zip(objects) {
        let c14n = || Transform::C14n(signer.canonicalization.clone());
        let (uri, transforms) = match object {
            DataObject::Document { envelope, .. } => (
                String::new(),
                Vec::from([
                    match envelope {
                        Envelope::Enveloped => Transform::Enveloped,
                        Envelope::ExcludingSignatures => Transform::XpathExcludeAllSignatures,
                    },
                    c14n(),
                ]),
            ),
            DataObject::Element { id, .. } => (format!("#{id}"), Vec::from([c14n()])),
            // Detached bytes are signed as they are, with no transform.
            DataObject::Detached { uri, .. } => (String::from(uri), Vec::new()),
            DataObject::Enveloping { content, .. } => {
                enveloping.push(ObjectBuilder::new(content).id(&object_uri[1..]));
                (object_uri.clone(), Vec::from([c14n()]))
            }
        };
        let mut built = ReferenceBuilder::new(signer.digest)
            .uri(uri)
            .id(&reference[1..]);
        for transform in transforms {
            built = built.transform(transform);
        }
        template = template.add_reference(built);
    }
    for object in enveloping {
        template = template.add_object(object);
    }
    template
}

/// Countersign one existing `XAdES` signature and publish the result as one
/// new generation of `document`, after the countersignature meets every B-B
/// requirement and the parent still does with it incorporated.
///
/// The countersignature is itself a B-B signature over the parent's
/// `SignatureValue`. It is appended to the parent's unsigned signature
/// properties, which are created when the parent has none; nothing the
/// parent already holds changes.
///
/// # Errors
/// Returns the original cause; the document is unchanged.
pub fn countersign<W: Work>(
    document: &mut XmlDocument,
    signer: &Signer<'_>,
    countersignature: &Countersignature<'_>,
    assessment: &Assessment<'_, '_>,
    work: &W,
) -> Result<(), CreateError> {
    let ids = Ids::new(countersignature.id);
    let countersigned = format!("{}-reference-0", ids.signature);
    require_free(
        document,
        &[&ids.signature, &ids.properties, &ids.value, &countersigned],
        countersignature.id_attributes,
    )?;
    let parent = document.with_view(|view| {
        locate_parent(
            view,
            countersignature.parent,
            countersignature.id_attributes,
            work,
        )
    })?;
    let value_uri = format!("#{}", parent.value);

    let target = format!("#{}", ids.signature);
    let properties = signed_properties(
        signer,
        &ids,
        &target,
        countersignature.signing_time,
        &[],
        Some(&value_uri),
        work,
    )?;
    let template = signature_template(signer, &ids)
        .add_reference(
            ReferenceBuilder::new(signer.digest)
                .uri(value_uri.as_str())
                .id(countersigned.as_str())
                .ref_type(ReferenceKind::CounterSignature.type_uri())
                .transform(Transform::C14n(signer.canonicalization.clone())),
        )
        .add_reference(properties_reference(signer, &ids))
        .add_object(ObjectBuilder::new(ObjectContent::Element(properties)))
        .build_template_with_policy(signer.policy)?;
    let key_info = key_info(signer)?;
    let context = context(signer, &key_info, countersignature.id_attributes)
        .start_node_id(&ids.signature)
        .signature_template_selection(SignatureTemplateSelection::FirstDescendant);

    // EN 319 132-1 §4.3: UnsignedSignatureProperties precedes
    // UnsignedDataObjectProperties inside UnsignedProperties, which follows
    // SignedProperties; a new property is appended after the existing ones.
    let counter = format!(
        "<xades:CounterSignature xmlns:xades=\"{XADES}\">{template}</xades:CounterSignature>"
    );
    document.transaction(|document| {
        match parent.unsigned {
            Unsigned::Signature(properties) => document.append_child(properties, &counter)?,
            Unsigned::Data(data) => document.insert_before(
                data,
                &format!(
                    "<xades:UnsignedSignatureProperties xmlns:xades=\"{XADES}\">{counter}</xades:UnsignedSignatureProperties>"
                ),
            )?,
            Unsigned::Empty(properties) => document.append_child(
                properties,
                &format!(
                    "<xades:UnsignedSignatureProperties xmlns:xades=\"{XADES}\">{counter}</xades:UnsignedSignatureProperties>"
                ),
            )?,
            Unsigned::Absent(qualifying) => document.append_child(
                qualifying,
                &format!(
                    "<xades:UnsignedProperties xmlns:xades=\"{XADES}\"><xades:UnsignedSignatureProperties>{counter}</xades:UnsignedSignatureProperties></xades:UnsignedProperties>"
                ),
            )?,
        }
        context.sign_document(document)?;
        // The parent's assessment binds every incorporated countersignature
        // (path, key, hash use) but not its own signing-certificate
        // requirements, so the countersignature is assessed as well; its
        // countersigned value is exempt from format coverage (EN 319 132-1
        // §6.3(k)) through the binding that assessment derives.
        assess(
            document,
            &ids.signature,
            countersignature.id_attributes,
            assessment,
            work,
        )?;
        assess(
            document,
            countersignature.parent,
            countersignature.id_attributes,
            assessment,
            work,
        )
    })
}

fn mime_type<'a>(object: &DataObject<'a>) -> &'a str {
    match object {
        DataObject::Document { mime_type, .. }
        | DataObject::Element { mime_type, .. }
        | DataObject::Detached { mime_type, .. }
        | DataObject::Enveloping { mime_type, .. } => mime_type,
    }
}

/// Refuse any new ID the document already declares, in one document walk.
fn require_free(
    document: &XmlDocument,
    ids: &[&str],
    registrations: &[IdAttributeRegistration],
) -> Result<(), CreateError> {
    document.with_view(|view| match view.declared_id(ids, registrations) {
        Some(id) => Err(CreateError::IdInUse(id.into())),
        None => Ok(()),
    })
}

/// The `QualifyingProperties` of a new signature, drafted from the shared
/// B-B rules and checked as `Object` content under the signing policy.
fn signed_properties<W: Work>(
    signer: &Signer<'_>,
    ids: &Ids,
    target: &str,
    signing_time: &str,
    objects: &[produce::DataObject<'_>],
    counter_signature: Option<&str>,
    work: &W,
) -> Result<ObjectElement, CreateError> {
    let (&leaf, _) = signer.chain.split_first().ok_or(CreateError::EmptyChain)?;
    let parser = Parser::der(work.memory().clone());
    let certificate = Certificate::read(&parser, leaf, 0).map_err(CreateError::Certificate)?;
    if certificate.as_bytes().len() != leaf.len() {
        return Err(CreateError::TrailingBytes);
    }
    // EN 319 132-1 §5.2.2: CertDigest is the digest of the complete
    // certificate encoding, computed here by the operation's provider.
    let digest = compute_digest_with_provider(signer.provider, signer.digest, leaf, work.memory())?;
    let basic = produce::Basic {
        target,
        signed_properties_id: &ids.properties,
        signing_time,
        certificate: &certificate,
        certificate_digest_method: signer.digest.uri(),
        certificate_digest: &digest,
        objects,
        counter_signature,
    };
    let mut draft = Draft::new();
    basic
        .write(&mut draft, work)
        .map_err(CreateError::Properties)?;
    let (markup, _) = draft.finish()?;
    Ok(ObjectElement::parse(markup, signer.policy)?)
}

/// The signature skeleton every new signature shares.
fn signature_template(signer: &Signer<'_>, ids: &Ids) -> SignatureBuilder {
    SignatureBuilder::new(signer.canonicalization.clone(), signer.method)
        .ns_prefix("ds")
        .signature_id(ids.signature.as_str())
        .signature_value_id(ids.value.as_str())
        .key_info(true)
}

/// EN 319 132-1 §4.4.2: a typed reference covers the complete `SignedProperties`.
fn properties_reference(signer: &Signer<'_>, ids: &Ids) -> ReferenceBuilder {
    ReferenceBuilder::new(signer.digest)
        .uri(format!("#{}", ids.properties))
        .ref_type(ReferenceKind::SignedProperties.type_uri())
        .transform(Transform::C14n(signer.canonicalization.clone()))
}

/// `KeyInfo` with the signer's certificates, parsed in the signing policy's
/// certificate account.
fn key_info(signer: &Signer<'_>) -> Result<X509CertificateKeyInfoWriter, CreateError> {
    if signer.chain.is_empty() {
        return Err(CreateError::EmptyChain);
    }
    let mut session = KeyInfoParsingSession::new(&signer.policy.resources)?;
    Ok(X509CertificateKeyInfoWriter::from_der_chain_in_session(
        signer.chain.iter().copied(),
        &mut session,
    )?)
}

fn context<'a>(
    signer: &'a Signer<'a>,
    key_info: &'a X509CertificateKeyInfoWriter,
    id_attributes: &'a [IdAttributeRegistration],
) -> SignContext<'a> {
    SignContext::new(signer.key)
        .provider(signer.provider)
        .policy(signer.policy.clone())
        .key_info_writer(key_info)
        .id_attributes(id_attributes)
}

/// Verify the signed generation under the caller's request and require B-B
/// of `signature`.
///
/// The request's signature requirement (every signature, by default) must
/// hold, so a new signature cannot leave an earlier one, or a countersignature,
/// failing in the published generation. Its expected targets and trusted
/// keys hold for the same elements, carried into that generation.
fn assess<W: Work>(
    document: &XmlDocument,
    signature: &str,
    registrations: &[IdAttributeRegistration],
    assessment: &Assessment<'_, '_>,
    work: &W,
) -> Result<(), CreateError> {
    let carried = Carried::new::<_, CreateError>(document, assessment.request, work)?;
    let outcome = with_verified_request(
        document,
        assessment.context,
        &carried.request(assessment.request),
        work,
        |session| {
            if !session.evidence().accepted(document)? {
                return Ok(Err(CreateError::NotAccepted));
            }
            let Some(node) = session.view().node_for_id(signature, registrations) else {
                return Ok(Err(CreateError::UnknownSignature(signature.into())));
            };
            Ok(
                validate_basic(&session, node, assessment.certificates, |report| {
                    report.all_root_requirements_met()
                })
                .map_err(CreateError::from),
            )
        },
    )??;
    match outcome {
        Outcome::Assessed(true) => Ok(()),
        outcome => Err(CreateError::Unmet(outcome.map(|_| ()))),
    }
}

/// The node requirements of a verification request, carried into the current
/// generation of a document inside the transaction that changed it.
pub(crate) struct Carried<'k> {
    /// The carried targets, then the carried signatures of the keys.
    identities: OwnedVec<NodeIdentity>,
    targets: usize,
    keys: OwnedVec<CallerTrustedSignatureKey<'k>>,
}

impl<'k> Carried<'k> {
    /// Carry every expected target and trusted key's signature of `request`
    /// in one pass, paid for by `work` before it starts.
    ///
    /// The request's own cardinality limits are the verification's to
    /// enforce; the carrying in front of it is linear in the document and the
    /// number of entries, and charged here, so an oversized request spends
    /// the caller's budget rather than unaccounted work.
    ///
    /// # Errors
    /// The document's refusal when an element no longer has a counterpart, as
    /// when the transaction replaced it, or the account's refusal of the work
    /// or storage.
    pub(crate) fn new<W: Work, E>(
        document: &XmlDocument,
        request: &VerificationRequest<'k>,
        work: &W,
    ) -> Result<Self, E>
    where
        E: From<XmlDocumentError> + From<MemoryError>,
    {
        let (targets, keys) = (request.expected_targets, request.trusted_keys);
        let entries = targets.len() + keys.len();
        let mut identities = work.memory().vector();
        if entries > 0 {
            // The comparison reads the starting and current texts once and
            // the walk visits the current tree once, each about the size of
            // the document, then every entry is placed once.
            let bytes = (document.as_xml().len() as u64)
                .checked_mul(2)
                .and_then(|bytes| bytes.checked_add(entries as u64))
                .ok_or(MemoryError::WorkExceeded)?;
            work.charge_work(bytes)?;
            identities.try_reserve_exact(entries)?;
            for identity in targets
                .iter()
                .chain(keys.iter().map(|entry| &entry.signature))
            {
                identities.try_push(*identity)?;
            }
        }
        let mut identities = identities.into_owned();
        document.carry_all(&mut identities)?;
        let mut carried = work.memory().vector();
        carried.try_reserve_exact(keys.len())?;
        for (entry, signature) in keys.iter().zip(&identities[targets.len()..]) {
            carried.try_push(CallerTrustedSignatureKey {
                signature: *signature,
                key: entry.key,
            })?;
        }
        Ok(Self {
            identities,
            targets: targets.len(),
            keys: carried.into_owned(),
        })
    }

    /// `request` with the carried targets and keys.
    pub(crate) fn request<'a>(
        &'a self,
        request: &VerificationRequest<'a>,
    ) -> VerificationRequest<'a> {
        VerificationRequest {
            expected_targets: &self.identities[..self.targets],
            trusted_keys: &self.keys,
            external_resources: request.external_resources,
            signatures: request.signatures,
            correlation: request.correlation,
        }
    }
}

/// Where a countersignature goes in the parent's qualifying properties.
enum Unsigned {
    /// The existing `UnsignedSignatureProperties`.
    Signature(NodeIdentity),
    /// `UnsignedProperties` holding only `UnsignedDataObjectProperties`,
    /// which the new signature properties must precede.
    Data(NodeIdentity),
    /// `UnsignedProperties` without children.
    Empty(NodeIdentity),
    /// `QualifyingProperties` without `UnsignedProperties`.
    Absent(NodeIdentity),
}

struct Parent {
    value: String,
    unsigned: Unsigned,
}

fn locate_parent<W: Work>(
    view: DocumentView<'_>,
    id: &str,
    registrations: &[IdAttributeRegistration],
    work: &W,
) -> Result<Parent, CreateError> {
    let unknown = || CreateError::UnknownSignature(id.into());
    let signature = view.node_for_id(id, registrations).ok_or_else(unknown)?;
    if !is_element(view, signature, DS, "Signature", work)? {
        return Err(unknown());
    }
    let value = child(view, signature, DS, "SignatureValue", work)?.ok_or_else(unknown)?;
    let value = attribute(view, value, "Id", work)?
        .ok_or_else(|| CreateError::Uncountersignable(id.into()))?;
    let target = format!("#{id}");
    let mut qualifying = None;
    for object in children(view, signature, work)? {
        if !is_element(view, object, DS, "Object", work)? {
            continue;
        }
        for candidate in children(view, object, work)? {
            if is_element(view, candidate, XADES, "QualifyingProperties", work)?
                && attribute(view, candidate, "Target", work)?
                    .is_some_and(|value| value.trim() == target)
            {
                qualifying = Some(candidate);
            }
        }
    }
    let qualifying = qualifying.ok_or_else(|| CreateError::NotXades(id.into()))?;
    let unsigned = match child(view, qualifying, XADES, "UnsignedProperties", work)? {
        None => Unsigned::Absent(qualifying),
        Some(properties) => {
            match child(view, properties, XADES, "UnsignedSignatureProperties", work)? {
                Some(signature_properties) => Unsigned::Signature(signature_properties),
                None => match child(
                    view,
                    properties,
                    XADES,
                    "UnsignedDataObjectProperties",
                    work,
                )? {
                    Some(data) => Unsigned::Data(data),
                    None => Unsigned::Empty(properties),
                },
            }
        }
    };
    Ok(Parent { value, unsigned })
}

fn children<W: Work>(
    view: DocumentView<'_>,
    parent: NodeIdentity,
    work: &W,
) -> Result<Vec<NodeIdentity>, CreateError> {
    let mut nodes = Vec::new();
    let mut next = extension::first_child(view, parent, work)?;
    while let Some(node) = next {
        work.charge_work(1)?;
        nodes.push(node);
        next = extension::next_sibling(view, parent, node, work)?;
    }
    Ok(nodes)
}

fn child<W: Work>(
    view: DocumentView<'_>,
    parent: NodeIdentity,
    namespace: &str,
    local: &str,
    work: &W,
) -> Result<Option<NodeIdentity>, CreateError> {
    for node in children(view, parent, work)? {
        if is_element(view, node, namespace, local, work)? {
            return Ok(Some(node));
        }
    }
    Ok(None)
}

fn is_element<W: Work>(
    view: DocumentView<'_>,
    node: NodeIdentity,
    namespace: &str,
    local: &str,
    work: &W,
) -> Result<bool, CreateError> {
    Ok(extension::inspect_node(
        view,
        node,
        work,
        |node| matches!(node, NodeView::Element { namespace: Some(actual), local_name } if actual == namespace && local_name == local),
    )?)
}

/// An unqualified attribute's value.
fn attribute<W: Work>(
    view: DocumentView<'_>,
    node: NodeIdentity,
    local: &str,
    work: &W,
) -> Result<Option<String>, CreateError> {
    let mut found = None;
    let visited = extension::visit_direct_attributes(view, node, work, |attribute| {
        if attribute.namespace.is_none() && attribute.local_name == local {
            found = Some(String::from(attribute.value));
            // Attribute names are unique on an element.
            return Err(());
        }
        Ok(())
    });
    match visited {
        Ok(()) | Err(InspectionError::Visitor(())) => Ok(found),
        Err(InspectionError::Processing(error)) => Err(error.into()),
    }
}
