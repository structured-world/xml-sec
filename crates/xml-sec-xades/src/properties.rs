//! Optional qualifying properties of a new signature: its signature policy
//! and policy store, production place, signer role, commitments and the
//! details of each `DataObjectFormat` (EN 319 132-1 §5.2.3 to §5.2.10).
//!
//! The properties are built by the shared `structured_xades::produce` rules;
//! xml-sec supplies the XML they carry ([`Fragment`]), resolves the
//! references they name in the signature's reference plan and computes the
//! signature policy digest with the signer's provider.

use crate::content::{ContentEvidence, ContentTimestamp, Replayed};
use crate::draft::{Draft, DraftError};
use alloc::{string::String, vec::Vec};
use structured_asn1::memory::Work;
pub use structured_xades::identifier::Qualifier;
use structured_xades::produce::{
    self, Event, FragmentSlot, ObjectMetadata, PolicyWriter, PropertyWriter, Writer,
};
pub use structured_xades::produce::{
    CertifiedRole, Commitment, CommitmentScope, ExplicitPolicy, Identifier, NoticeReference,
    PolicyDocument, PolicyQualifier, PolicyStore, PolicyTransform, ProductionPlace,
    RoleCertificate, SignaturePolicy, SignerRole, UserNotice,
};
use xml_sec::policy::{PolicyViolation, SigningPolicy};
use xml_sec::provider::{CryptoProvider, ProviderError};
use xml_sec::xmldsig::extension::{
    InspectionError, ScalarError, ScalarFact, ScalarType, with_lexical_scalar,
};
use xml_sec::xmldsig::{
    DigestAlgorithm, DigestOutput, ObjectElement, SignatureBuilderError, Transform, TransformData,
    TransformError, compute_digest_with_provider, execute_transforms_with_policy, parse_transforms,
};
use xml_sec::{XmlDomDocument, XmlDomNode};

const DS: &str = "http://www.w3.org/2000/09/xmldsig#";

/// XML a new property carries in a slot its schema leaves open.
#[derive(Debug, Clone)]
pub enum Fragment {
    /// Character data of an `AnyType` slot, such as a claimed role's name.
    Text(String),
    /// One self-contained element of an `AnyType` slot, checked as `Object`
    /// content under the signing policy.
    Element(ObjectElement),
    /// The `ds:Transforms` of a signature policy digest.
    Transforms(PolicyTransforms),
}

/// A `ds:Transforms` element and the transforms it encodes: the same plan
/// is written into `SignaturePolicyId` and applied to the policy document
/// before its digest (EN 319 132-1 §5.2.9.2).
#[derive(Debug, Clone)]
pub struct PolicyTransforms {
    element: ObjectElement,
    transforms: Vec<Transform>,
}

/// A `ds:Transforms` element that cannot carry a policy digest plan.
#[derive(Debug, thiserror::Error)]
pub enum TransformsError {
    /// The markup is not one element admitted by the signing policy.
    #[error(transparent)]
    Markup(#[from] SignatureBuilderError),
    /// The element is not `ds:Transforms`.
    #[error("the element is not ds:Transforms")]
    NotTransforms,
    /// A transform is malformed or unsupported.
    #[error(transparent)]
    Transform(#[from] TransformError),
}

impl PolicyTransforms {
    /// Check `markup` as one `ds:Transforms` element under `policy` and read
    /// the transforms it encodes, in order.
    ///
    /// # Errors
    /// Returns the policy, parse or transform refusal.
    pub fn parse(
        markup: impl Into<String>,
        policy: &SigningPolicy,
    ) -> Result<Self, TransformsError> {
        let element = ObjectElement::parse(markup, policy)?;
        let transforms = with_transforms(&element, |node| Ok(parse_transforms(node)?))?;
        Ok(Self {
            element,
            transforms,
        })
    }

    /// The transforms, in order.
    #[must_use]
    pub fn transforms(&self) -> &[Transform] {
        &self.transforms
    }
}

/// Run `body` over the parsed `ds:Transforms` root of `element`.
fn with_transforms<T>(
    element: &ObjectElement,
    body: impl FnOnce(XmlDomNode<'_, '_>) -> Result<T, TransformsError>,
) -> Result<T, TransformsError> {
    // ObjectElement::parse admitted this markup under the signing policy.
    let document = XmlDomDocument::parse(element.as_ref()).map_err(|_| {
        TransformsError::Markup(SignatureBuilderError::InvalidObjectContent(
            "ds:Transforms must be well-formed",
        ))
    })?;
    let root = document.root_element();
    if root.tag_name().namespace() != Some(DS) || root.tag_name().name() != "Transforms" {
        return Err(TransformsError::NotTransforms);
    }
    body(root)
}

/// The `DataObjectFormat` content beyond the MIME type of one signed data
/// object (EN 319 132-1 §5.2.4).
#[derive(Debug, Clone, Copy)]
pub struct FormatDetails<'a> {
    /// URI of the object's reference, as [`crate::Request::id`] names it:
    /// `#{id}-reference-{n}`, or a reference of a signed `Manifest`.
    pub reference: &'a str,
    /// Human-readable description of the object.
    pub description: Option<&'a str>,
    /// Identifier of the object's type.
    pub identifier: Option<Identifier<'a>>,
    /// URI of the object's encoding; it must equal the `Encoding` of a
    /// `ds:Object` the reference targets.
    pub encoding: Option<&'a str>,
}

/// The optional properties of one new signature. The default has none.
#[derive(Default)]
pub struct Properties<'a> {
    /// `SignaturePolicyIdentifier` (§5.2.9).
    pub policy: Option<SignaturePolicy<'a, Fragment>>,
    /// `SignaturePolicyStore` of the explicit policy, an unsigned property
    /// (§5.2.10).
    pub policy_store: Option<PolicyStore<'a>>,
    /// `SignatureProductionPlaceV2` (§5.2.5).
    pub production_place: Option<ProductionPlace<'a>>,
    /// `SignerRoleV2` (§5.2.6).
    pub signer_role: Option<SignerRole<'a, Fragment>>,
    /// `CommitmentTypeIndication`s, in order (§5.2.3).
    pub commitments: &'a [Commitment<'a, Fragment>],
    /// `DataObjectFormat` details, at most one per signed data object.
    pub formats: &'a [FormatDetails<'a>],
    /// `AllDataObjectsTimeStamp`s and `IndividualDataObjectsTimeStamp`s, in
    /// order (§5.2.8); see [`crate::request_content_timestamps`].
    pub content_timestamps: &'a [ContentTimestamp<'a>],
    /// What the content timestamp responses are checked with.
    pub content_evidence: Option<ContentEvidence<'a>>,
}

impl Properties<'_> {
    /// Whether any property qualifies the signed data objects, which a pure
    /// countersignature does not have.
    pub(crate) fn qualifies_objects(&self) -> bool {
        !self.commitments.is_empty()
            || !self.formats.is_empty()
            || !self.content_timestamps.is_empty()
    }
}

/// A property the shared rules or xml-sec refused while drafting it.
#[derive(Debug, thiserror::Error)]
pub enum PropertyError {
    /// The draft refused an event.
    #[error(transparent)]
    Draft(#[from] DraftError),
    /// A fragment does not fit its slot: text or an element where a
    /// `ds:Transforms` is due, or the other way round.
    #[error("the fragment does not fit its {0:?} slot")]
    Slot(FragmentSlot),
    /// A lexical value is not an XML Schema integer.
    #[error("{0:?} is not an xsd:integer")]
    Integer(String),
    /// The policy digest method is not a known `XMLDSig` digest.
    #[error("unknown policy digest method {0:?}")]
    DigestMethod(String),
    /// The signing policy does not admit the policy digest method.
    #[error(transparent)]
    Policy(#[from] PolicyViolation),
    /// The digest as specified by a technical specification is not
    /// implemented; the policy needs another digest plan.
    #[error("policy digest as in specification {0:?} is not supported")]
    Specification(String),
    /// The policy transforms could not be applied.
    #[error(transparent)]
    Transforms(#[from] TransformsError),
    /// The provider could not digest the policy document.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// A content timestamp names a canonicalization method other than the
    /// one its input was produced with.
    #[error("the content timestamp method is not the method of its input")]
    ContentMethod,
}

impl From<TransformError> for PropertyError {
    fn from(error: TransformError) -> Self {
        Self::Transforms(TransformsError::Transform(error))
    }
}

/// One reference of the new signature's plan and the `Object` attributes of
/// its target, which a `DataObjectFormat` must repeat.
pub(crate) struct Planned {
    /// Same-document URI of the reference, `#` and its ID.
    pub(crate) uri: String,
    /// `MimeType` of the targeted `ds:Object`, if one is written.
    pub(crate) mime_type: Option<String>,
    /// `Encoding` of the targeted `ds:Object`, if one is written.
    pub(crate) encoding: Option<String>,
}

/// The explicit policy a `SignaturePolicyStore` may store: the one drafted
/// into a new signature, or the one an existing signature signed.
pub(crate) enum Bound<'a> {
    /// No explicit policy; no store can be written.
    None,
    /// The explicit policy this draft's `SignaturePolicyIdentifier` was
    /// written from.
    Staged(&'a ExplicitPolicy<'a, Fragment>),
    /// The `SignaturePolicyId` an existing signature signed.
    Signed(SignedPolicy),
}

/// The values of a signed `SignaturePolicyId` a stored policy must repeat.
pub(crate) struct SignedPolicy {
    /// `SigPolicyId/Identifier`, collapsed as an anyURI is.
    pub(crate) identifier: String,
    /// `SigPolicyHash/DigestMethod/@Algorithm`.
    pub(crate) method: String,
    /// The decoded `SigPolicyHash/DigestValue`.
    pub(crate) digest: Vec<u8>,
}

/// The draft of one new signature's `QualifyingProperties`, or of a policy
/// store, with what the optional properties need: the reference plan, the
/// provider and policy for a policy digest, and the explicit policy a store
/// must match.
pub(crate) struct PropertyDraft<'a> {
    pub(crate) draft: Draft,
    pub(crate) plan: &'a [Planned],
    pub(crate) provider: &'a dyn CryptoProvider,
    pub(crate) policy: &'a SigningPolicy,
    pub(crate) bound: Bound<'a>,
    /// The reference plan the content timestamps were checked over.
    pub(crate) content: Option<&'a Replayed<'a>>,
}

impl Writer for PropertyDraft<'_> {
    type Error = PropertyError;

    fn write<W: Work>(&mut self, event: Event<'_>, work: &W) -> Result<(), PropertyError> {
        Ok(self.draft.write(event, work)?)
    }
}

impl PropertyWriter for PropertyDraft<'_> {
    type Fragment = Fragment;

    fn data_reference<W: Work>(
        &self,
        uri: &str,
        work: &W,
    ) -> Result<Option<ObjectMetadata<'_>>, PropertyError> {
        work.charge_work(self.plan.len() as u64)
            .map_err(DraftError::from)?;
        Ok(self
            .plan
            .iter()
            .find(|planned| planned.uri == uri)
            .map(|planned| ObjectMetadata {
                mime_type: planned.mime_type.as_deref(),
                encoding: planned.encoding.as_deref(),
            }))
    }

    fn fragment<W: Work>(
        &mut self,
        slot: FragmentSlot,
        fragment: &Fragment,
        work: &W,
    ) -> Result<(), PropertyError> {
        match (slot, fragment) {
            (FragmentSlot::AnyContent, Fragment::Text(text)) => {
                self.draft.write(
                    Event::Text(produce::Value {
                        lexical: text,
                        datatype: produce::Datatype::String,
                    }),
                    work,
                )?;
            }
            (FragmentSlot::AnyContent, Fragment::Element(element)) => {
                self.draft.copied(element.as_ref().as_bytes(), work)?;
            }
            (FragmentSlot::PolicyTransforms, Fragment::Transforms(transforms)) => {
                self.draft
                    .copied(transforms.element.as_ref().as_bytes(), work)?;
            }
            (slot, _) => return Err(PropertyError::Slot(slot)),
        }
        Ok(())
    }

    fn integer<W: Work>(&mut self, lexical: &str, work: &W) -> Result<(), PropertyError> {
        let valid = with_lexical_scalar(lexical, ScalarType::Integer, work, |fact| {
            // The value is written as given, so it must need no collapsing.
            Ok::<_, core::convert::Infallible>(
                matches!(fact, ScalarFact::Value(_)) && lexical.trim() == lexical,
            )
        })
        .map_err(|error| match error {
            InspectionError::Processing(ScalarError::Resource(error)) => {
                PropertyError::Draft(DraftError::Resource(error))
            }
            InspectionError::Processing(_) => PropertyError::Integer(lexical.into()),
            InspectionError::Visitor(never) => match never {},
        })?;
        if !valid {
            return Err(PropertyError::Integer(lexical.into()));
        }
        Ok(self.draft.write(
            Event::Text(produce::Value {
                lexical,
                datatype: produce::Datatype::String,
            }),
            work,
        )?)
    }
}

impl PolicyWriter for PropertyDraft<'_> {
    type Digest = DigestOutput;

    fn policy_digest<W: Work>(
        &self,
        document: &[u8],
        method: &str,
        transform: &PolicyTransform<'_, Fragment>,
        work: &W,
    ) -> Result<DigestOutput, PropertyError> {
        let algorithm = DigestAlgorithm::from_uri(method)
            .ok_or_else(|| PropertyError::DigestMethod(method.into()))?;
        self.policy.check_digest_algorithm(algorithm)?;
        work.charge_work(document.len() as u64)
            .map_err(DraftError::from)?;
        let memory = work.memory();
        match transform {
            // EN 319 132-1 §5.2.9.2: without transforms the digest covers the
            // policy document's bytes as they are.
            PolicyTransform::None => Ok(compute_digest_with_provider(
                self.provider,
                algorithm,
                document,
                memory,
            )?),
            PolicyTransform::Xml(Fragment::Transforms(transforms)) => {
                let transformed = with_transforms(&transforms.element, |node| {
                    // The policy document is the input; `here()` in an XPath
                    // transform is the transform's own node.
                    Ok(execute_transforms_with_policy(
                        node,
                        TransformData::BorrowedBinary(document),
                        &transforms.transforms,
                        self.policy,
                    )?)
                })?;
                work.charge_work(transformed.len() as u64)
                    .map_err(DraftError::from)?;
                Ok(compute_digest_with_provider(
                    self.provider,
                    algorithm,
                    &transformed,
                    memory,
                )?)
            }
            PolicyTransform::Xml(_) => Err(PropertyError::Slot(FragmentSlot::PolicyTransforms)),
            PolicyTransform::InSpecification(specification) => {
                Err(PropertyError::Specification(specification.uri.into()))
            }
        }
    }

    fn matches_policy<W: Work>(
        &self,
        policy: &ExplicitPolicy<'_, Fragment>,
        work: &W,
    ) -> Result<bool, PropertyError> {
        work.charge_work(1).map_err(DraftError::from)?;
        match &self.bound {
            Bound::None => Ok(false),
            // A new signature stores only the explicit policy its own
            // SignaturePolicyIdentifier was drafted from.
            Bound::Staged(staged) => Ok(core::ptr::eq(
                core::ptr::from_ref(*staged).cast::<()>(),
                core::ptr::from_ref(policy).cast::<()>(),
            )),
            // EN 319 132-1 §5.2.10: the stored document is the one the signed
            // hash covers: the same version and method, and the digest of
            // the document under the supplied plan equals the signed one.
            Bound::Signed(signed) => {
                work.charge_work((policy.identifier.uri.len() + policy.digest_method.len()) as u64)
                    .map_err(DraftError::from)?;
                if policy.identifier.uri != signed.identifier
                    || policy.digest_method != signed.method
                {
                    return Ok(false);
                }
                let digest = self.policy_digest(
                    policy.document,
                    policy.digest_method,
                    &policy.transform,
                    work,
                )?;
                Ok(digest.as_ref() == signed.digest.as_slice())
            }
        }
    }
}
