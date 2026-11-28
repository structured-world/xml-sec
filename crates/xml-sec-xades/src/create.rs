//! `XAdES` B-B creation and countersigning over the `XMLDSig` signer.
//!
//! The signed properties come from the shared `structured_xades::produce`
//! rules through a [`Draft`]; the signature itself is built, signed and
//! committed by xml-sec with the caller's key and selected provider. Each
//! operation verifies the signed generation and runs the B-B assessment of
//! [`validate_basic`] before it publishes anything: a signature that does not
//! meet every B-B requirement is never left in the document.

use crate::basic::{Outcome, ValidationError, validate_basic};
use crate::content::{self, ContentError, ContentRequests, Replayed};
use crate::draft::{Draft, DraftError};
use crate::placement::{self, DS, PlacementError, XADES};
use crate::properties::{
    Bound, Planned, Policy, Profile, Properties, PropertyDraft, PropertyError, SignaturePolicy,
    policy_digest_method,
};
use alloc::{collections::BTreeMap, format, string::String, vec::Vec};
use structured_asn1::Parser;
use structured_asn1::memory::{MemoryError, OwnedVec, Work};
use structured_pkix::Certificate;
use structured_xades::produce::{self, ReferenceKind};
use structured_xades::produce::{CheckedContent, ContentInput};
use structured_xades::produce::{Event, Writer as _};
use structured_xades::xml::Name;
use xml_sec::IdAttributeRegistration;
use xml_sec::c14n::C14nAlgorithm;
use xml_sec::document::{DocumentView, NodeIdentity, XmlDocument, XmlDocumentError};
use xml_sec::policy::{ManifestProcessing, SigningPolicy};
use xml_sec::provider::{CryptoProvider, ProviderError};
use xml_sec::xmldsig::extension::{ScalarError, TreeError, first_child, next_sibling, parent};
use xml_sec::xmldsig::parse::{KeyInfoParsingSession, ParseError};
use xml_sec::xmldsig::{
    CallerTrustedSignatureKey, DigestAlgorithm, DsigError, KeyInfoWriteError, ManifestBuilder,
    ObjectBuilder, ObjectContent, ObjectElement, ReferenceBuilder, SignContext, SignatureAlgorithm,
    SignatureBuilder, SignatureBuilderError, SignatureTemplateSelection, SigningError, SigningKey,
    Transform, VerificationRequest, VerifyContext, X509CertificateKeyInfoWriter,
    compute_digest_with_provider, with_verified_request,
};
use xml_sec::xmldsig::{KeptInputs, SigningInputs};

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
    /// Namespace prefixes the new signatures are written with.
    pub prefixes: Prefixes<'a>,
}

/// The prefixes of the `XMLDSig` and `XAdES` namespaces in a new signature:
/// `ds` and `xades` by default. An empty prefix writes the namespace as the
/// default one. Prefixes change no canonical form a digest covers beyond the
/// prefix itself; they are a serialization choice, not policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefixes<'a> {
    /// Prefix of `http://www.w3.org/2000/09/xmldsig#`.
    pub ds: &'a str,
    /// Prefix of `http://uri.etsi.org/01903/v1.3.2#`.
    pub xades: &'a str,
}

impl Default for Prefixes<'_> {
    fn default() -> Self {
        Self {
            ds: "ds",
            xades: "xades",
        }
    }
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
    /// Content in a new `Object` of the signature with the caller's `Id`,
    /// signed through a reference to it with the caller's transforms
    /// (`XMLDSig` 1.1 §4.5, §6.6.2): base64 content with its `Encoding`,
    /// decoded by [`Transform::Base64Decode`], say.
    Object {
        /// ID of the new `Object`.
        id: &'a str,
        /// The object content.
        content: ObjectContent,
        /// `Encoding` attribute of the object, if any.
        encoding: Option<&'a str>,
        /// The transforms of the reference, in order.
        transforms: Vec<Transform>,
        /// MIME type of the content, also the object's `MimeType`.
        mime_type: &'a str,
    },
    /// A `Manifest` in a new `Object` with the caller's `Id`, listing the
    /// data its references name; the signature signs the `Manifest`, whose
    /// reference digests the signing operation computes first (`XMLDSig` 1.1
    /// §5.1, the signing policy processing Manifests).
    Manifest {
        /// ID of the `Manifest`; its references take `{id}-reference-{n}`.
        id: &'a str,
        /// The data the `Manifest` lists, each digested after its own
        /// transforms, detached data from [`Request::resources`] included.
        entries: Vec<ManifestEntry<'a>>,
        /// The transforms of the signature's reference to the `Manifest`;
        /// none canonicalizes it as [`Signer::canonicalization`] says.
        transforms: Vec<Transform>,
        /// MIME type of the `Manifest`.
        mime_type: &'a str,
    },
    /// A `Manifest` the caller built, carried in a new `Object` and signed
    /// through a reference to the `Id` of its root element (`XMLDSig` 1.1
    /// §5.1). As for any `Manifest`, the signature meets B-B only when the
    /// signing and verification policies process Manifests; signing then
    /// digests its references.
    SuppliedManifest {
        /// The `ds:Manifest` element, with an `Id`, read again under the
        /// signer's XML and resource limits.
        manifest: ObjectElement,
        /// The MIME type of each reference of the `Manifest` the signature
        /// describes, named by its `Id`: each processed reference is a signed
        /// data object that needs one (EN 319 132-1 §6.3(k)).
        entries: Vec<SuppliedEntry<'a>>,
        /// The transforms of the signature's reference to the `Manifest`;
        /// none canonicalizes it as [`Signer::canonicalization`] says.
        transforms: Vec<Transform>,
        /// MIME type of the `Manifest`.
        mime_type: &'a str,
    },
    /// The signature's own `KeyInfo`, with the signer's certificates the
    /// operation writes into it (`XMLDSig` 1.1 §4.5), canonicalized as the
    /// other XML references are.
    KeyInfo {
        /// MIME type of the key information.
        mime_type: &'a str,
    },
    /// A reference the caller composes: any URI and the transforms applied to
    /// what it dereferences, in order (`XMLDSig` 1.1 §4.4.3.1, §6.6). The
    /// signing policy decides which URIs and transforms are admitted.
    Reference {
        /// URI of the reference: empty for the whole document, `#id` for an
        /// element, `#xpointer(...)` or an external URI.
        uri: &'a str,
        /// The transforms, in order; none signs the dereferenced data as is.
        transforms: Vec<Transform>,
        /// MIME type of the signed data.
        mime_type: &'a str,
    },
}

/// Where a new signature goes, relative to an element named by its ID. An
/// enveloped reference signs the document whatever the placement; only
/// which nodes the signature's own transforms leave out depends on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Placement<'a> {
    /// The last child of the document element.
    #[default]
    DocumentEnd,
    /// The last child of the element.
    LastChildOf(&'a str),
    /// Before every existing child of the element.
    FirstChildOf(&'a str),
    /// Immediately before the element.
    Before(&'a str),
    /// Immediately after the element.
    After(&'a str),
}

/// Where a signature template is inserted: before a node, or appended to one.
#[derive(Debug, Clone, Copy)]
enum Anchor {
    Before(NodeIdentity),
    Append(NodeIdentity),
}

/// The anchor of a placement that the signer's append path cannot reach.
fn anchor<W: Work>(
    view: DocumentView<'_>,
    placement: Placement<'_>,
    registrations: &[IdAttributeRegistration],
    work: &W,
) -> Result<Anchor, CreateError> {
    let (Placement::FirstChildOf(id) | Placement::Before(id) | Placement::After(id)) = placement
    else {
        return Err(CreateError::UnknownPlacement(String::new()));
    };
    let unknown = || CreateError::UnknownPlacement(id.into());
    let element = view.node_for_id(id, registrations).ok_or_else(unknown)?;
    Ok(match placement {
        Placement::FirstChildOf(_) => match first_child(view, element, work)? {
            Some(child) => Anchor::Before(child),
            None => Anchor::Append(element),
        },
        Placement::Before(_) => Anchor::Before(element),
        _ => {
            let parent = parent(view, element, work)?.ok_or_else(unknown)?;
            match next_sibling(view, parent, element, work)? {
                Some(next) => Anchor::Before(next),
                None => Anchor::Append(parent),
            }
        }
    })
}

/// One datum a signed `Manifest` lists, with its MIME type: each one gets a
/// `DataObjectFormat` as a signed data object (EN 319 132-1 §6.3(k)).
#[derive(Debug, Clone)]
pub struct ManifestEntry<'a> {
    /// URI of the datum: empty for the document holding the signature, `#id`
    /// for an element, or detached data.
    pub uri: &'a str,
    /// The transforms applied to what the URI dereferences, in order
    /// (`XMLDSig` 1.1 §4.4.3.1); none digests detached data as it is.
    pub transforms: Vec<Transform>,
    /// MIME type of the datum.
    pub mime_type: &'a str,
}

/// One reference of a supplied `Manifest`, named by its `Id`, with the MIME
/// type of the datum its `DataObjectFormat` states.
#[derive(Debug, Clone, Copy)]
pub struct SuppliedEntry<'a> {
    /// `Id` of the reference.
    pub id: &'a str,
    /// MIME type of the datum.
    pub mime_type: &'a str,
}

/// What one new signature signs and where it goes.
pub struct Request<'a> {
    /// ID of the new `Signature`. The IDs of its parts derive from it, as
    /// `{id}-signed-properties`, `{id}-value`, `{id}-reference-{n}`,
    /// `{id}-object-{n}` and, when [`DataObject::KeyInfo`] signs it,
    /// `{id}-key-info`; none of them may already be declared.
    pub id: &'a str,
    /// Claimed signing time, an XML Schema dateTime with an explicit timezone.
    /// This is the signer's claim, not a clock reading or temporal evidence.
    pub signing_time: &'a str,
    /// The data objects, in reference order. Enveloping content moves into
    /// the signature.
    pub objects: Vec<DataObject<'a>>,
    /// Where the signature goes in the document.
    pub placement: Placement<'a>,
    /// Detached data, keyed as the signing operation resolves its URIs.
    pub resources: Option<&'a BTreeMap<String, Vec<u8>>>,
    /// ID attributes beyond the standard spellings.
    pub id_attributes: &'a [IdAttributeRegistration],
    /// The optional qualifying properties; their references name the data
    /// objects by the reference URIs [`Request::id`] describes.
    pub properties: Properties<'a>,
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
    /// The optional qualifying properties. A countersignature signs no data
    /// object, so it takes no commitment and no format details.
    pub properties: Properties<'a>,
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
    /// An evidence record seals the parent signature, which then takes no
    /// countersignature (ETSI TS 119 132-3 §5.1.1).
    #[error("signature {0:?} is sealed by an evidence record")]
    Sealed(String),
    /// No element has the ID the placement names, or it has no parent to
    /// place a sibling in.
    #[error("no element to place the signature at: {0:?}")]
    UnknownPlacement(String),
    /// The parent has no `QualifyingProperties` targeting it.
    #[error("signature {0:?} has no XAdES qualifying properties")]
    NotXades(String),
    /// The parent's `SignatureValue` has no ID a countersignature can
    /// reference. Adding one would change bytes its timestamps may cover.
    #[error("signature {0:?} has no SignatureValue ID to countersign")]
    Uncountersignable(String),
    /// The shared property rules or xml-sec refused a property.
    #[error("property construction refused: {0:?}")]
    Properties(produce::Error<PropertyError>),
    /// A commitment or format details on a countersignature, which signs
    /// no data object they could qualify (EN 319 132-1 §5.2.3, §5.2.4).
    #[error("a countersignature has no data objects to qualify")]
    NoQualifiedObject,
    /// A supplied `Manifest` is not one `ds:Manifest` element.
    #[error("the supplied Manifest is not a ds:Manifest element")]
    NotManifest,
    /// A supplied `Manifest` has no `Id`, so no reference can name it
    /// (`XMLDSig` 1.1 §5.1).
    #[error("the supplied Manifest has no Id")]
    ManifestWithoutId,
    /// Format details name a reference that is not one of the signature's
    /// data objects, or name one twice.
    #[error("format details for {0:?} name no data object or one already described")]
    FormatReference(String),
    /// Signing processes `Manifest`s, so each reference of a supplied one is
    /// a signed data object that needs its `DataObjectFormat` (EN 319 132-1
    /// §6.3(k)): no entry names this reference, `#Id`, or it has no `Id`
    /// (`None`) an entry could name.
    #[error("the supplied Manifest reference {0:?} has no format a signed data object needs")]
    UndescribedManifestReference(Option<String>),
    /// A policy store without the explicit signature policy it stores
    /// (EN 319 132-1 §5.2.10).
    #[error("a policy store needs an explicit signature policy")]
    PolicyStoreWithoutPolicy,
    /// A historical profile carries a signature policy computed from its
    /// document beside the signing certificate, and no other optional
    /// property, content timestamp or countersignature.
    #[error("the historical profile carries no such property")]
    HistoricalProperty,
    /// A content timestamp could not be requested, checked or kept.
    #[error(transparent)]
    Content(Box<ContentError>),
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

impl From<ContentError> for CreateError {
    fn from(error: ContentError) -> Self {
        Self::Content(Box::new(error))
    }
}

impl From<PlacementError> for CreateError {
    fn from(error: PlacementError) -> Self {
        match error {
            PlacementError::UnknownSignature(id) => Self::UnknownSignature(id),
            PlacementError::NotXades(id) => Self::NotXades(id),
            PlacementError::Sealed(id) => Self::Sealed(id),
            PlacementError::Tree(error) => Self::Tree(error),
            PlacementError::Scalar(error) => Self::Scalar(error),
            PlacementError::Resource(error) => Self::Resource(error),
        }
    }
}

/// The IDs of one new signature's parts.
struct Ids {
    signature: String,
    properties: String,
    value: String,
    key_info: String,
}

impl Ids {
    fn new(signature: &str) -> Self {
        Self {
            signature: signature.into(),
            properties: format!("{signature}-signed-properties"),
            value: format!("{signature}-value"),
            key_info: format!("{signature}-key-info"),
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
    let layout = Layout::new(document, &request, signer.policy, work)?;
    let key_info = checked_key_info(signer, work)?;
    let stamps = request.properties.content_timestamps;
    if stamps.is_empty() {
        let properties = layout.properties(signer, &request, None, work)?;
        let historical = request.properties.historical;
        let template = layout.template(signer, request.objects, properties, historical)?;
        return document.transaction(|document| {
            let placed = Placed::new(
                document,
                signer,
                &key_info,
                &layout,
                &request.placement,
                (request.resources, request.id_attributes),
                work,
            )?;
            placed.sign(document, &template, signer.policy, KeptInputs::NONE)?;
            match historical {
                Some(profile) => assess_historical(
                    document,
                    &layout.ids.signature,
                    profile,
                    request.id_attributes,
                    assessment,
                    work,
                ),
                None => assess(
                    document,
                    &layout.ids.signature,
                    request.id_attributes,
                    assessment,
                    work,
                ),
            }
        });
    }
    let replayed = layout.replayed(document, signer, &key_info, &request, work)?;
    let cms = assessment.context.cms_provider();
    content::with_checked(
        &replayed,
        stamps,
        request.properties.content_evidence.as_ref(),
        &cms,
        work,
        |checked| {
            let properties =
                layout.properties(signer, &request, Some((&replayed, checked)), work)?;
            // Content timestamps exist only in the EN 319 132-1 vocabulary.
            let template = layout.template(signer, request.objects.clone(), properties, None)?;
            document.transaction(|document| {
                let placed = Placed::new(
                    document,
                    signer,
                    &key_info,
                    &layout,
                    &request.placement,
                    (request.resources, request.id_attributes),
                    work,
                )?;
                let digested = placed.sign(document, &template, signer.policy, CONTENT_INPUTS)?;
                // The timestamps cover the bytes of the dry run; a reference
                // that digests others depends on the signature it is part of.
                if !replayed.unchanged(&digested, stamps) {
                    return Err(ContentError::Changed.into());
                }
                assess(
                    document,
                    &layout.ids.signature,
                    request.id_attributes,
                    assessment,
                    work,
                )
            })
        },
    )
}

/// Encode the RFC 3161 request of each content timestamp of `request`, in
/// order, for the caller to send to its TSA (EN 319 132-1 §5.2.8).
///
/// The input of each timestamp is computed by the signing operation of
/// [`create`] stopped before any signature value: the key signs nothing and
/// `document` keeps its generation. Pass the responses in
/// [`ContentTimestamp::response`](crate::ContentTimestamp::response) to
/// [`create`] with the same request otherwise, which computes the inputs
/// again and checks each response against its exact request.
///
/// # Errors
/// Returns the original cause; the document is unchanged.
///
/// # Examples
///
/// ```no_run
/// use structured_pkix::algorithm::digest::Algorithm;
/// use xml_sec_xades::properties::Properties;
/// use xml_sec_xades::{
///     Assessment, ContentEvidence, ContentScope, ContentTimestamp, Request, Signer, create,
///     request_content_timestamps,
/// };
/// # fn sign(
/// #     document: &mut xml_sec::XmlDocument,
/// #     signer: &Signer<'_>,
/// #     assessment: &Assessment<'_, '_>,
/// #     request: impl Fn(Properties<'_>) -> Request<'_>,
/// #     evidence: ContentEvidence<'_>,
/// #     tsa: impl Fn(&[u8]) -> Vec<u8>,
/// #     work: &structured_asn1::memory::Memory,
/// # ) -> Result<(), xml_sec_xades::CreateError> {
/// let asked = [ContentTimestamp {
///     scope: ContentScope::All,
///     digest: Algorithm::Sha256,
///     policy: None,
///     nonce: Some(&[0x2a; 8]),
///     response: None,
/// }];
/// let pending = request_content_timestamps(
///     document,
///     signer,
///     &request(Properties { content_timestamps: &asked, ..Properties::default() }),
///     assessment,
///     work,
/// )?;
/// let response = tsa(pending.get(0).expect("one request"));
/// let answered = [ContentTimestamp { response: Some(&response), ..asked[0] }];
/// create(
///     document,
///     signer,
///     request(Properties {
///         content_timestamps: &answered,
///         content_evidence: Some(evidence),
///         ..Properties::default()
///     }),
///     assessment,
///     work,
/// )
/// # }
/// ```
pub fn request_content_timestamps<W: Work>(
    document: &mut XmlDocument,
    signer: &Signer<'_>,
    request: &Request<'_>,
    assessment: &Assessment<'_, '_>,
    work: &W,
) -> Result<ContentRequests, CreateError> {
    let layout = Layout::new(document, request, signer.policy, work)?;
    let key_info = checked_key_info(signer, work)?;
    let replayed = layout.replayed(document, signer, &key_info, request, work)?;
    let cms = assessment.context.cms_provider();
    Ok(content::requests(
        &replayed,
        request.properties.content_timestamps,
        &cms,
        work,
    )?)
}

/// The signing inputs a content timestamp covers: every reference's bytes.
const CONTENT_INPUTS: KeptInputs = KeptInputs::NONE
    .with_signed_info_references()
    .with_manifest_references();

/// The names of one new signature's parts that derive from its request,
/// and the plan its properties resolve their references in.
struct Layout<'r> {
    ids: Ids,
    /// `#ID` of each data object's reference, in order.
    references: Vec<String>,
    /// `#ID` of each data object's possible enveloping `Object`.
    objects: Vec<String>,
    /// Each signed `Manifest`'s references, in order.
    manifest_references: Vec<ManifestReference<'r>>,
    /// Whether signing processes the `Manifest`s, which makes their
    /// references signed data objects (EN 319 132-1 §6.3(k)).
    processes_manifests: bool,
    /// The `Id` of each supplied `Manifest`, in order.
    supplied: Vec<String>,
    /// Whether a reference signs `KeyInfo`, which then gets an ID.
    signs_key_info: bool,
    plan: Vec<Planned>,
}

impl<'r> Layout<'r> {
    /// The layout of `request`, whose new IDs `document` must not declare,
    /// after refusing more references than `policy` admits.
    fn new<W: Work>(
        document: &XmlDocument,
        request: &Request<'r>,
        policy: &SigningPolicy,
        work: &W,
    ) -> Result<Self, CreateError> {
        if request.objects.is_empty() {
            return Err(CreateError::NoDataObject);
        }
        // The generated entries are counted before any of their IDs exists;
        // a supplied Manifest's references only once it is read.
        let generated = request
            .objects
            .iter()
            .map(|object| match object {
                DataObject::Manifest { entries, .. } => entries.len(),
                _ => 0,
            })
            .fold(0_usize, usize::saturating_add);
        check_reference_count(policy, request.objects.len(), generated)?;
        let (manifest_references, supplied) = manifest_references(&request.objects, policy, work)?;
        check_reference_count(policy, request.objects.len(), manifest_references.len())?;
        let processes_manifests = policy.manifest_processing == ManifestProcessing::Process;
        let ids = Ids::new(request.id);
        // Same-document URIs; the IDs are the text after '#'.
        let references: Vec<String> = (0..request.objects.len())
            .map(|index| format!("#{}-reference-{index}", ids.signature))
            .collect();
        let objects: Vec<String> = (0..request.objects.len())
            .map(|index| format!("#{}-object-{index}", ids.signature))
            .collect();
        // KeyInfo gets an ID only when a reference signs it, so every other
        // signature keeps its exact form.
        let signs_key_info = request
            .objects
            .iter()
            .any(|object| matches!(object, DataObject::KeyInfo { .. }));
        let new_ids = new_ids(
            &request.objects,
            &ids,
            signs_key_info.then_some(ids.key_info.as_str()),
            &references,
            &objects,
            (&manifest_references, &supplied),
        );
        require_free(document, &new_ids, request.id_attributes)?;
        let signed = if processes_manifests {
            manifest_references.as_slice()
        } else {
            &[]
        };
        // Each signed Manifest reference is a data object the signature
        // describes (EN 319 132-1 §6.3(k)); one it cannot is refused here,
        // before anything is signed.
        if let Some(undescribed) = signed
            .iter()
            .find(|reference| reference.uri.is_none() || reference.mime_type.is_none())
        {
            return Err(CreateError::UndescribedManifestReference(
                undescribed.uri.clone(),
            ));
        }
        let plan = reference_plan(&request.objects, &references, signed);
        Ok(Self {
            ids,
            references,
            objects,
            manifest_references,
            processes_manifests,
            supplied,
            signs_key_info,
            plan,
        })
    }

    /// The `Manifest` references signing digests, none when it leaves the
    /// `Manifest`s unprocessed.
    fn signed_manifest_references(&self) -> &[ManifestReference<'r>] {
        if self.processes_manifests {
            &self.manifest_references
        } else {
            &[]
        }
    }

    /// The `QualifyingProperties` of the new signature, with the content
    /// timestamps checked over `content`, if any.
    fn properties<W: Work>(
        &self,
        signer: &Signer<'_>,
        request: &Request<'_>,
        content: Option<Stamps<'_, '_>>,
        work: &W,
    ) -> Result<ObjectElement, CreateError> {
        let described: Vec<produce::DataObject<'_>> = request
            .objects
            .iter()
            .zip(&self.references)
            .map(|(object, reference)| produce::DataObject {
                reference,
                mime_type: mime_type(object),
            })
            .chain(
                self.signed_manifest_references()
                    .iter()
                    .filter_map(|entry| {
                        Some(produce::DataObject {
                            reference: entry.uri.as_deref()?,
                            mime_type: entry.mime_type?,
                        })
                    }),
            )
            .collect();
        let target = format!("#{}", self.ids.signature);
        if let Some(profile) = request.properties.historical {
            refuse_beyond_policy(&request.properties, content.is_some())?;
            let (&leaf, _) = signer.chain.split_first().ok_or(CreateError::EmptyChain)?;
            return historical_properties(
                signer,
                profile,
                [&self.ids.properties, &target, request.signing_time],
                leaf,
                &described,
                request.properties.policy.as_ref(),
                work,
            );
        }
        signed_properties(
            signer,
            &self.ids,
            &target,
            request.signing_time,
            &described,
            None,
            &Optional {
                properties: &request.properties,
                plan: &self.plan,
                content,
            },
            work,
        )
    }

    /// The template of the new signature: one reference per data object,
    /// then the `SignedProperties` one, and the `Object`s.
    fn template(
        &self,
        signer: &Signer<'_>,
        data: Vec<DataObject<'_>>,
        properties: ObjectElement,
        historical: Option<Profile>,
    ) -> Result<SignatureBuilder, CreateError> {
        let mut skeleton = signature_template(signer, &self.ids);
        if self.signs_key_info {
            skeleton = skeleton.key_info_id(self.ids.key_info.as_str());
        }
        Ok(data_template(
            signer,
            data,
            (&self.references, &self.objects, &self.supplied),
            &self.ids.key_info,
            skeleton,
        )?
        .add_reference(properties_reference(signer, &self.ids, historical))
        .add_object(ObjectBuilder::new(ObjectContent::Element(properties))))
    }

    /// The bytes every reference of the new signature digests, from a dry
    /// run of its signing operation with the properties but no content
    /// timestamp; `document` keeps its generation.
    fn replayed<W: Work>(
        &self,
        document: &mut XmlDocument,
        signer: &Signer<'_>,
        key_info: &X509CertificateKeyInfoWriter,
        request: &Request<'_>,
        work: &W,
    ) -> Result<Replayed<'_>, CreateError> {
        let properties = self.properties(signer, request, None, work)?;
        // Content timestamps exist only in the EN 319 132-1 vocabulary.
        let template = self.template(signer, request.objects.clone(), properties, None)?;
        let placed = Placed::new(
            document,
            signer,
            key_info,
            self,
            &request.placement,
            (request.resources, request.id_attributes),
            work,
        )?;
        let inputs = placed.inputs(document, &template, signer.policy)?;
        Ok(Replayed::new(
            inputs,
            &self.references,
            self.signed_manifest_references(),
            (&signer.canonicalization, signer.policy),
        )?)
    }
}

/// Content timestamps checked over the dry run, each with its input.
type Stamps<'s, 'l> = (
    &'s Replayed<'l>,
    &'s [(
        &'s ContentInput<'s, Replayed<'l>>,
        CheckedContent<'s, 's, 's, Replayed<'l>>,
    )],
);

/// Where a template goes and the operation that signs it there.
struct Placed<'a> {
    context: SignContext<'a>,
    at: Option<Anchor>,
}

impl<'a> Placed<'a> {
    /// The signing operation of `layout` at `placement` in `document`.
    fn new<W: Work>(
        document: &XmlDocument,
        signer: &'a Signer<'a>,
        key_info: &'a X509CertificateKeyInfoWriter,
        layout: &'a Layout<'_>,
        placement: &Placement<'a>,
        (resources, id_attributes): (
            Option<&'a BTreeMap<String, Vec<u8>>>,
            &'a [IdAttributeRegistration],
        ),
        work: &W,
    ) -> Result<Self, CreateError> {
        let mut context = context(signer, key_info, id_attributes);
        if let Some(resources) = resources {
            context = context.external_resources(resources);
        }
        // The signer appends a new signature; any other placement inserts
        // the template first and signs it where it stands, as a
        // countersignature is.
        let at = match *placement {
            Placement::DocumentEnd => None,
            Placement::LastChildOf(parent) => {
                context = context.start_node_id(parent);
                None
            }
            other => Some(document.with_view(|view| anchor(view, other, id_attributes, work))?),
        };
        if at.is_some() {
            context = context
                .start_node_id(&layout.ids.signature)
                .signature_template_selection(SignatureTemplateSelection::FirstDescendant);
        }
        Ok(Self { context, at })
    }

    /// Sign `template` in place, keeping the signing inputs `kept` names.
    fn sign(
        &self,
        document: &mut XmlDocument,
        template: &SignatureBuilder,
        policy: &SigningPolicy,
        kept: KeptInputs,
    ) -> Result<SigningInputs, CreateError> {
        let Some(at) = self.at else {
            return Ok(self
                .context
                .sign_document_with_builder_keeping(document, template, kept)?
                .1);
        };
        insert(document, template, policy, at)?;
        Ok(self.context.sign_document_keeping(document, kept)?.1)
    }

    /// The bytes every reference of `template` digests where it goes,
    /// without signing; `document` keeps its generation.
    fn inputs(
        &self,
        document: &mut XmlDocument,
        template: &SignatureBuilder,
        policy: &SigningPolicy,
    ) -> Result<SigningInputs, CreateError> {
        let Some(at) = self.at else {
            return Ok(self.context.reference_inputs_with_builder(
                document,
                template,
                CONTENT_INPUTS,
            )?);
        };
        // Failing the transaction on purpose discards the inserted template;
        // the dry run's outcome leaves it as the rollback value.
        let Err(outcome) = document.transaction(|document| {
            Err::<core::convert::Infallible, _>(
                insert(document, template, policy, at)
                    .and_then(|()| Ok(self.context.reference_inputs(document, CONTENT_INPUTS)?)),
            )
        });
        outcome
    }
}

/// Insert `template` at `at`, as markup, before a signing run.
fn insert(
    document: &mut XmlDocument,
    template: &SignatureBuilder,
    policy: &SigningPolicy,
    at: Anchor,
) -> Result<(), CreateError> {
    let markup = template.build_template_with_policy(policy)?;
    match at {
        Anchor::Before(node) => document.insert_before(node, &markup)?,
        Anchor::Append(node) => document.append_child(node, &markup)?,
    }
    Ok(())
}

/// Add one reference per data object, in order, and an `Object` holding each
/// enveloping object's content, which moves into the template uncopied.
fn data_template(
    signer: &Signer<'_>,
    data: Vec<DataObject<'_>>,
    (references, objects, supplied): (&[String], &[String], &[String]),
    key_info: &str,
    mut template: SignatureBuilder,
) -> Result<SignatureBuilder, CreateError> {
    let mut enveloping = Vec::new();
    let mut supplied = supplied.iter();
    for ((object, reference), object_uri) in data.into_iter().zip(references).zip(objects) {
        let c14n = || Transform::C14n(signer.canonicalization.clone());
        // A Manifest is XML the signature references: with no transforms of
        // the caller's, the signer canonicalizes it as its other XML ones.
        let or_canonicalized = |transforms: Vec<Transform>| {
            if transforms.is_empty() {
                Vec::from([c14n()])
            } else {
                transforms
            }
        };
        // XMLDSig 1.1 §5.1: a reference to a Manifest says so in its Type.
        let manifest = matches!(
            object,
            DataObject::Manifest { .. } | DataObject::SuppliedManifest { .. }
        );
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
            DataObject::Object {
                id,
                content,
                encoding,
                transforms,
                mime_type,
            } => {
                let mut object = ObjectBuilder::new(content).id(id).mime_type(mime_type);
                if let Some(encoding) = encoding {
                    object = object.encoding(encoding);
                }
                enveloping.push(object);
                (format!("#{id}"), transforms)
            }
            DataObject::Manifest {
                id,
                entries,
                transforms,
                ..
            } => {
                let element = manifest_element(signer, id, entries)?;
                enveloping.push(ObjectBuilder::new(ObjectContent::Element(element)));
                (format!("#{id}"), or_canonicalized(transforms))
            }
            DataObject::SuppliedManifest {
                manifest,
                transforms,
                ..
            } => {
                // Layout read one Id per supplied Manifest, in order.
                let id = supplied.next().ok_or(CreateError::ManifestWithoutId)?;
                enveloping.push(ObjectBuilder::new(ObjectContent::Element(manifest)));
                (format!("#{id}"), or_canonicalized(transforms))
            }
            DataObject::KeyInfo { .. } => (format!("#{key_info}"), Vec::from([c14n()])),
            DataObject::Reference {
                uri, transforms, ..
            } => (String::from(uri), transforms),
        };
        let mut built = ReferenceBuilder::new(signer.digest)
            .uri(uri)
            .id(&reference[1..]);
        if manifest {
            built = built.ref_type(MANIFEST_TYPE);
        }
        for transform in transforms {
            built = built.transform(transform);
        }
        template = template.add_reference(built);
    }
    for object in enveloping {
        template = template.add_object(object);
    }
    Ok(template)
}

/// Every ID a new signature declares: its parts, its references, the
/// enveloping and named objects and the references of its `Manifest`s.
fn new_ids<'a>(
    data: &'a [DataObject<'a>],
    ids: &'a Ids,
    key_info: Option<&'a str>,
    references: &'a [String],
    objects: &'a [String],
    (manifest_references, supplied): (&'a [ManifestReference<'_>], &'a [String]),
) -> Vec<&'a str> {
    let enveloping = data
        .iter()
        .zip(objects)
        .filter(|(object, _)| matches!(object, DataObject::Enveloping { .. }))
        .map(|(_, uri)| &uri[1..]);
    let named = data.iter().filter_map(|object| match object {
        DataObject::Object { id, .. } | DataObject::Manifest { id, .. } => Some(*id),
        _ => None,
    });
    [ids.signature.as_str(), &ids.properties, &ids.value]
        .into_iter()
        .chain(key_info)
        .chain(references.iter().map(|uri| &uri[1..]))
        .chain(enveloping)
        .chain(named)
        .chain(supplied.iter().map(String::as_str))
        .chain(
            manifest_references
                .iter()
                .filter_map(|entry| Some(&entry.uri.as_deref()?[1..])),
        )
        .collect()
}

/// Refuses a signature before any ID is laid out when it would hold more
/// references than `policy` admits: one per data object and the
/// `SignedProperties` one, with the `Manifest` references when the policy
/// processes them, as signing then counts them.
fn check_reference_count(
    policy: &SigningPolicy,
    objects: usize,
    manifest_references: usize,
) -> Result<(), CreateError> {
    // A count past usize::MAX is past any limit, so the sums saturate.
    let mut actual = objects.saturating_add(1);
    if policy.manifest_processing == ManifestProcessing::Process {
        actual = actual.saturating_add(manifest_references);
    }
    policy
        .resources
        .validate_reference_count(actual)
        .map_err(|violation| CreateError::Template(violation.into()))
}

/// One reference of a signed `Manifest`: `#ID` when it has one, and the MIME
/// type of its datum when the signature describes it.
pub(crate) struct ManifestReference<'a> {
    pub(crate) uri: Option<String>,
    mime_type: Option<&'a str>,
}

/// Each reference of the signed `Manifest`s among `objects`, then the `Id`
/// of each supplied `Manifest`, read from its element under `policy`.
fn manifest_references<'a, W: Work>(
    objects: &[DataObject<'a>],
    policy: &SigningPolicy,
    work: &W,
) -> Result<(Vec<ManifestReference<'a>>, Vec<String>), CreateError> {
    let mut references = Vec::new();
    let mut supplied = Vec::new();
    for object in objects {
        match object {
            DataObject::Manifest { id, entries, .. } => {
                references.extend(entries.iter().enumerate().map(|(index, entry)| {
                    ManifestReference {
                        uri: Some(format!("#{}", manifest_reference_id(id, index))),
                        mime_type: Some(entry.mime_type),
                    }
                }));
            }
            DataObject::SuppliedManifest {
                manifest, entries, ..
            } => {
                let (id, ids) = supplied_manifest(manifest, policy, work)?;
                let start = references.len();
                references.extend(ids.into_iter().map(|id| ManifestReference {
                    uri: id.map(|id| format!("#{id}")),
                    mime_type: None,
                }));
                for entry in entries {
                    let uri = format!("#{}", entry.id);
                    let reference = references[start..]
                        .iter_mut()
                        .find(|reference| reference.uri.as_deref() == Some(uri.as_str()))
                        .filter(|reference| reference.mime_type.is_none())
                        .ok_or_else(|| CreateError::FormatReference(uri.clone()))?;
                    reference.mime_type = Some(entry.mime_type);
                }
                supplied.push(id);
            }
            _ => {}
        }
    }
    Ok((references, supplied))
}

/// The `Id` of a supplied `ds:Manifest` and the `Id`, if any, of each of
/// its references, read under the signer's XML and resource limits.
fn supplied_manifest<W: Work>(
    manifest: &ObjectElement,
    policy: &SigningPolicy,
    work: &W,
) -> Result<(String, Vec<Option<String>>), CreateError> {
    let document = XmlDocument::parse_with_policy(manifest.as_ref(), policy)?;
    document.with_view(|view| {
        let root = view.root_element();
        if !placement::is_element(view, root, DS, "Manifest", work)? {
            return Err(CreateError::NotManifest);
        }
        let id =
            placement::attribute(view, root, "Id", work)?.ok_or(CreateError::ManifestWithoutId)?;
        let mut references = Vec::new();
        for child in placement::children(view, root, work)? {
            if placement::is_element(view, child, DS, "Reference", work)? {
                references.push(placement::attribute(view, child, "Id", work)?);
            }
        }
        Ok((id, references))
    })
}

/// The ID of the `index`th reference of `Manifest` `id`.
fn manifest_reference_id(id: &str, index: usize) -> String {
    format!("{id}-reference-{index}")
}

/// `XMLDSig` 1.1 §5.1: the `Type` of a reference to a `Manifest`.
const MANIFEST_TYPE: &str = "http://www.w3.org/2000/09/xmldsig#Manifest";

/// A `Manifest` whose references name `entries`, each with its own
/// transforms, with empty digest values the signing operation fills before
/// it digests the `Manifest` itself.
fn manifest_element(
    signer: &Signer<'_>,
    id: &str,
    entries: Vec<ManifestEntry<'_>>,
) -> Result<ObjectElement, CreateError> {
    let mut manifest = ManifestBuilder::new(id);
    if !signer.prefixes.ds.is_empty() {
        manifest = manifest.ns_prefix(signer.prefixes.ds);
    }
    for (index, entry) in entries.into_iter().enumerate() {
        let mut reference = ReferenceBuilder::new(signer.digest)
            .uri(entry.uri)
            .id(manifest_reference_id(id, index));
        for transform in entry.transforms {
            reference = reference.transform(transform);
        }
        manifest = manifest.add_reference(reference);
    }
    Ok(manifest.build_with_policy(signer.policy)?)
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
    let (located, value) = document.with_view(|view| {
        let located = placement::locate(
            view,
            countersignature.parent,
            countersignature.id_attributes,
            work,
        )?;
        let value = signature_value_id(view, located.signature, countersignature.parent, work)?;
        Ok::<_, CreateError>((located, value))
    })?;
    let value_uri = format!("#{value}");

    if countersignature.properties.qualifies_objects() {
        return Err(CreateError::NoQualifiedObject);
    }
    // A historical profile carries no countersignature; writing the EN
    // 319 132-1 one instead would not be the form asked for.
    if countersignature.properties.historical.is_some() {
        return Err(CreateError::HistoricalProperty);
    }
    let target = format!("#{}", ids.signature);
    let properties = signed_properties(
        signer,
        &ids,
        &target,
        countersignature.signing_time,
        &[],
        Some(&value_uri),
        &Optional {
            properties: &countersignature.properties,
            plan: &[],
            content: None,
        },
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
        .add_reference(properties_reference(signer, &ids, None))
        .add_object(ObjectBuilder::new(ObjectContent::Element(properties)))
        .build_template_with_policy(signer.policy)?;
    let key_info = key_info(signer)?;
    let context = context(signer, &key_info, countersignature.id_attributes)
        .start_node_id(&ids.signature)
        .signature_template_selection(SignatureTemplateSelection::FirstDescendant);

    let counter = match signer.prefixes.xades {
        "" => format!("<CounterSignature xmlns=\"{XADES}\">{template}</CounterSignature>"),
        prefix => format!(
            "<{prefix}:CounterSignature xmlns:{prefix}=\"{XADES}\">{template}</{prefix}:CounterSignature>"
        ),
    };
    document.transaction(|document| {
        located.unsigned.insert(document, &counter)?;
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
        | DataObject::Enveloping { mime_type, .. }
        | DataObject::Object { mime_type, .. }
        | DataObject::Manifest { mime_type, .. }
        | DataObject::SuppliedManifest { mime_type, .. }
        | DataObject::KeyInfo { mime_type }
        | DataObject::Reference { mime_type, .. } => mime_type,
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

/// The reference plan the properties resolve their references in: each data
/// object's reference with the `MimeType` and `Encoding` of the `ds:Object`
/// it targets, then the references of the signed `Manifest`s.
fn reference_plan(
    objects: &[DataObject<'_>],
    references: &[String],
    manifest_references: &[ManifestReference<'_>],
) -> Vec<Planned> {
    objects
        .iter()
        .zip(references)
        .map(|(object, uri)| {
            let (mime_type, encoding) = match object {
                DataObject::Object {
                    mime_type,
                    encoding,
                    ..
                } => (Some(String::from(*mime_type)), encoding.map(String::from)),
                _ => (None, None),
            };
            Planned {
                uri: uri.clone(),
                mime_type,
                encoding,
            }
        })
        .chain(manifest_references.iter().filter_map(|entry| {
            Some(Planned {
                uri: entry.uri.clone()?,
                mime_type: None,
                encoding: None,
            })
        }))
        .collect()
}

/// The optional properties of one new signature with what drafting them
/// needs: the reference plan and the checked content timestamps.
struct Optional<'p, 's, 'l> {
    properties: &'p Properties<'p>,
    plan: &'p [Planned],
    content: Option<Stamps<'s, 'l>>,
}

/// The explicit signature policy of `properties`, after refusing a store
/// without one and format details that name no data object of `objects`
/// or one already described.
fn checked_optional<'p>(
    properties: &'p Properties<'p>,
    objects: &[produce::DataObject<'_>],
) -> Result<
    Option<&'p crate::properties::ExplicitPolicy<'p, crate::properties::Fragment>>,
    CreateError,
> {
    // A supplied digest comes without the document a store would carry.
    let staged = match &properties.policy {
        Some(Policy::Document(SignaturePolicy::Explicit(policy))) => Some(policy),
        _ => None,
    };
    if properties.policy_store.is_some() && staged.is_none() {
        return Err(CreateError::PolicyStoreWithoutPolicy);
    }
    if properties.formats.is_empty() {
        return Ok(staged);
    }
    // One pass each way: the objects' references, then each format's
    // reference checked against them and against those already described.
    let known: alloc::collections::BTreeSet<&str> =
        objects.iter().map(|object| object.reference).collect();
    let mut described = alloc::collections::BTreeSet::new();
    for details in properties.formats {
        if !known.contains(details.reference) || !described.insert(details.reference) {
            return Err(CreateError::FormatReference(details.reference.into()));
        }
    }
    Ok(staged)
}

/// Write `policy`'s `SignaturePolicyIdentifier`; a supplied digest must have
/// the width of its method, which the signing policy admits.
fn write_policy<W: Work>(
    policy: &Policy<'_>,
    signing: &SigningPolicy,
    writer: &mut PropertyDraft<'_>,
    work: &W,
) -> Result<(), produce::Error<PropertyError>> {
    match policy {
        Policy::Document(policy) => policy.write(writer, work),
        Policy::Supplied(policy) => policy.write(writer, work, |method, _| {
            Ok(policy_digest_method(signing, method)?.output_len())
        }),
    }
}

/// The `QualifyingProperties` of a new signature, drafted from the shared
/// B-B rules and the optional properties, and checked as `Object` content
/// under the signing policy.
/// The signer's certificate `leaf`, exactly one DER certificate.
fn leaf_certificate<'p>(
    parser: &'p Parser,
    leaf: &'p [u8],
) -> Result<Certificate<'p>, CreateError> {
    let certificate = Certificate::read(parser, leaf, 0).map_err(CreateError::Certificate)?;
    if certificate.as_bytes().len() != leaf.len() {
        return Err(CreateError::TrailingBytes);
    }
    Ok(certificate)
}

/// `key_info(signer)` after the signer's certificate is checked, so a leaf
/// that is no certificate keeps that cause.
fn checked_key_info<W: Work>(
    signer: &Signer<'_>,
    work: &W,
) -> Result<X509CertificateKeyInfoWriter, CreateError> {
    let (&leaf, _) = signer.chain.split_first().ok_or(CreateError::EmptyChain)?;
    leaf_certificate(&Parser::der(work.memory().clone()), leaf)?;
    key_info(signer)
}

#[expect(
    clippy::too_many_arguments,
    reason = "the B-B inputs of one signature, each a distinct required value"
)]
fn signed_properties<W: Work>(
    signer: &Signer<'_>,
    ids: &Ids,
    target: &str,
    signing_time: &str,
    objects: &[produce::DataObject<'_>],
    counter_signature: Option<&str>,
    optional: &Optional<'_, '_, '_>,
    work: &W,
) -> Result<ObjectElement, CreateError> {
    let &Optional {
        properties,
        plan,
        content,
    } = optional;
    let staged = checked_optional(properties, objects)?;
    let (&leaf, _) = signer.chain.split_first().ok_or(CreateError::EmptyChain)?;
    let parser = Parser::der(work.memory().clone());
    let certificate = leaf_certificate(&parser, leaf)?;
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
    let mut writer = PropertyDraft {
        draft: Draft::with_prefixes(&[(DS, signer.prefixes.ds), (XADES, signer.prefixes.xades)])?,
        plan,
        provider: signer.provider,
        policy: signer.policy,
        bound: staged.map_or(Bound::None, Bound::Staged),
        specified: properties.specified,
        content: content.map(|(replayed, _)| replayed),
    };
    // EN 319 132-1 Annex A orders SignedSignatureProperties as policy,
    // production place, signer role after the signing certificate, and
    // SignedDataObjectProperties as formats, commitments, then content
    // timestamps.
    basic
        .write_with_properties(
            &mut writer,
            work,
            |writer, work| {
                if let Some(policy) = &properties.policy {
                    write_policy(policy, signer.policy, writer, work)?;
                }
                if let Some(place) = properties.production_place {
                    place.write(writer, work)?;
                }
                if let Some(role) = &properties.signer_role {
                    role.write(writer, work)?;
                }
                Ok(())
            },
            |writer, work| {
                for object in objects {
                    let details = properties
                        .formats
                        .iter()
                        .find(|details| details.reference == object.reference);
                    produce::DataObjectFormat {
                        reference: object.reference,
                        description: details.and_then(|details| details.description),
                        identifier: details.and_then(|details| details.identifier),
                        mime_type: Some(object.mime_type),
                        encoding: details.and_then(|details| details.encoding),
                    }
                    .write(writer, work)?;
                }
                for commitment in properties.commitments {
                    commitment.write(writer, work)?;
                }
                for (input, checked) in content.map_or(&[][..], |(_, stamps)| stamps) {
                    input.write(core::slice::from_ref(checked), writer, work)?;
                }
                Ok(())
            },
            |writer, work| {
                let (Some(store), Some(policy)) = (&properties.policy_store, staged) else {
                    return Ok(());
                };
                for local in ["UnsignedProperties", "UnsignedSignatureProperties"] {
                    writer
                        .write(
                            Event::Begin(Name {
                                namespace: XADES,
                                local,
                            }),
                            work,
                        )
                        .map_err(produce::Error::Writer)?;
                }
                policy.write_store(store, writer, work)?;
                for _ in 0..2 {
                    writer
                        .write(Event::End, work)
                        .map_err(produce::Error::Writer)?;
                }
                Ok(())
            },
        )
        .map_err(CreateError::Properties)?;
    let (markup, _) = writer.draft.finish()?;
    Ok(ObjectElement::parse(markup, signer.policy)?)
}

/// Refuse every optional property a historical profile does not carry here:
/// it signs a signature policy beside the signing certificate, and nothing
/// else (`content` for content timestamps or a countersignature). Nor does
/// TS 101 903 know a policy digested as its specification defines, or the
/// specification qualifier: EN 319 132-1 §5.2.9.2 introduced both, so a rule
/// the caller supplies for them has nothing to apply to.
fn refuse_beyond_policy(properties: &Properties<'_>, content: bool) -> Result<(), CreateError> {
    let specified_only = matches!(
        properties.policy,
        Some(Policy::Document(SignaturePolicy::Explicit(ref explicit)))
            if matches!(explicit.transform, produce::PolicyTransform::InSpecification(_))
                || explicit.qualifiers.iter().any(|qualifier| {
                    matches!(qualifier, produce::PolicyQualifier::DocumentSpecification(_))
                })
    );
    let beyond = specified_only
        || properties.policy_store.is_some()
        || properties.production_place.is_some()
        || properties.signer_role.is_some()
        || !properties.commitments.is_empty()
        || !properties.formats.is_empty()
        || !properties.content_timestamps.is_empty()
        || content
        || matches!(properties.policy, Some(Policy::Supplied(_)));
    if beyond {
        return Err(CreateError::HistoricalProperty);
    }
    Ok(())
}

/// The `QualifyingProperties` of a new signature in the historical
/// vocabulary of `profile`: `SigningTime`, `SigningCertificate` with the
/// issuer and serial of `leaf`, the signature policy (which V1.1.1 requires)
/// and each object's `DataObjectFormat`.
fn historical_properties<W: Work>(
    signer: &Signer<'_>,
    profile: Profile,
    [properties_id, target, signing_time]: [&str; 3],
    leaf: &[u8],
    objects: &[produce::DataObject<'_>],
    policy: Option<&Policy<'_>>,
    work: &W,
) -> Result<ObjectElement, CreateError> {
    let parser = Parser::der(work.memory().clone());
    let certificate = Certificate::read(&parser, leaf, 0).map_err(CreateError::Certificate)?;
    if certificate.as_bytes().len() != leaf.len() {
        return Err(CreateError::TrailingBytes);
    }
    let digest = compute_digest_with_provider(signer.provider, signer.digest, leaf, work.memory())?;
    let basic = produce::Basic {
        target,
        signed_properties_id: properties_id,
        signing_time,
        certificate: &certificate,
        certificate_digest_method: signer.digest.uri(),
        certificate_digest: &digest,
        objects,
        counter_signature: None,
    };
    let mut writer = PropertyDraft {
        draft: Draft::with_prefixes(&[
            (DS, signer.prefixes.ds),
            (profile.namespace(), signer.prefixes.xades),
        ])?,
        plan: &[],
        provider: signer.provider,
        policy: signer.policy,
        bound: Bound::None,
        // A specified digest rule serves only the EN 319 132-1 policy
        // transform, which `refuse_beyond_policy` refuses for these profiles.
        specified: None,
        content: None,
    };
    let policy = match policy {
        Some(Policy::Document(policy)) => Some(policy),
        _ => None,
    };
    basic
        .write_historical(profile, policy, &mut writer, work)
        .map_err(CreateError::Properties)?;
    let (markup, _) = writer.draft.finish()?;
    Ok(ObjectElement::parse(markup, signer.policy)?)
}

/// The signature skeleton every new signature shares.
fn signature_template(signer: &Signer<'_>, ids: &Ids) -> SignatureBuilder {
    let template = SignatureBuilder::new(signer.canonicalization.clone(), signer.method)
        .signature_id(ids.signature.as_str())
        .signature_value_id(ids.value.as_str())
        .key_info(true);
    // The builder writes the default namespace when no prefix is set.
    match signer.prefixes.ds {
        "" => template,
        prefix => template.ns_prefix(prefix),
    }
}

/// EN 319 132-1 §4.4.2: a typed reference covers the complete
/// `SignedProperties`; a historical profile names its own `Type`.
fn properties_reference(
    signer: &Signer<'_>,
    ids: &Ids,
    historical: Option<Profile>,
) -> ReferenceBuilder {
    let kind = historical.map_or(
        ReferenceKind::SignedProperties.type_uri(),
        Profile::signed_properties_type,
    );
    ReferenceBuilder::new(signer.digest)
        .uri(format!("#{}", ids.properties))
        .ref_type(kind)
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

/// [`assess`] for a signature in the historical vocabulary of `profile`,
/// which must meet the BES requirements of that profile (TS 101 903 V1.2.2
/// §4.4.1): signed properties bound to the signature and a protected signing
/// certificate holding the verifying key.
fn assess_historical<W: Work>(
    document: &XmlDocument,
    signature: &str,
    profile: Profile,
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
            Ok(crate::ts101903::validate_historical(
                &session,
                node,
                profile,
                assessment.certificates,
                bes_met,
            )
            .map_err(CreateError::from))
        },
    )??;
    match outcome {
        Outcome::Assessed(true) => Ok(()),
        outcome => Err(CreateError::Unmet(outcome.map(|_| ()))),
    }
}

/// Whether the historical signature meets its BES requirements; a function
/// item is general over the report's lifetime where a method path is not.
fn bes_met(report: &crate::ts101903::Ts101903Report<'_>) -> bool {
    report.bes_met()
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

/// The ID of `signature`'s `SignatureValue`, which a countersignature
/// references. Adding one would change bytes its timestamps may cover.
fn signature_value_id<W: Work>(
    view: DocumentView<'_>,
    signature: NodeIdentity,
    id: &str,
    work: &W,
) -> Result<String, CreateError> {
    let value = placement::child(view, signature, DS, "SignatureValue", work)?
        .ok_or_else(|| CreateError::UnknownSignature(id.into()))?;
    placement::attribute(view, value, "Id", work)?
        .ok_or_else(|| CreateError::Uncountersignable(id.into()))
}
