//! URI dereference for XMLDSig `<Reference>` elements.
//!
//! Implements same-document URI resolution per
//! [XMLDSig §4.3.3.2](https://www.w3.org/TR/xmldsig-core1/#sec-Same-Document):
//!
//! - **Empty URI** (`""` or absent): the entire document, excluding comments.
//! - **Bare-name `#id`**: the element whose ID attribute matches `id`, as a subtree
//!   with comments removed by the XMLDSig same-document dereference rule.
//! - **`#xpointer(/)`**: the entire document, including comments.
//! - **`#xpointer(id('id'))` / `#xpointer(id("id"))`**: element by ID, with comments retained.
//!
//! External URI bytes are resolved only from an explicit caller-owned map; this
//! module never performs network or filesystem I/O.

use crate::c14n::scratch::{Accounted, Bytes as _, Native, Scratch, Text as _};
use std::cell::Cell;
use std::collections::HashMap;
use std::rc::Rc;

use crate::xml::dom::{Document, Node, NodeId};

use crate::c14n::xml_base::{
    XmlBaseResolutionBudget, XmlBaseResolutionError, resolve_uri_from_node_with_budget,
};
use crate::policy::SameDocumentIdSemantics;
use crate::xml::{XmlIdIndex, is_xml_ncname};

use super::types::{
    NodeSet, NodeSetMaterializationBudget, TransformData, TransformError, transform_resource_limit,
};

/// Original resource identity, before choosing operation-owned projection storage.
pub(crate) enum ReferenceInput<'a> {
    Xml {
        root: Node<'a, 'a>,
        with_comments: bool,
    },
    Binary {
        bytes: &'a [u8],
        uri: &'a str,
    },
}

pub(crate) enum NormalizedFragment<'uri, B> {
    Borrowed(&'uri str),
    Owned(B),
}

impl<B: std::ops::Deref<Target = [u8]>> NormalizedFragment<'_, B> {
    pub(crate) fn view(&self, scratch: &impl Scratch) -> Result<&str, TransformError> {
        match self {
            Self::Borrowed(text) => Ok(text),
            Self::Owned(bytes) => {
                scratch.charge(bytes.len())?;
                std::str::from_utf8(bytes).map_err(|_| invalid_fragment())
            }
        }
    }
}

fn invalid_fragment() -> TransformError {
    TransformError::InvalidFragment
}

pub(crate) enum UriFailureKind {
    MissingId,
    Unsupported,
}

pub(crate) trait UriScratch: Scratch {
    fn diagnostic(&self, kind: UriFailureKind, parts: &[&str]) -> TransformError;
}

impl UriScratch for Native {
    fn diagnostic(&self, kind: UriFailureKind, parts: &[&str]) -> TransformError {
        match kind {
            UriFailureKind::MissingId => TransformError::ElementNotFound(parts.concat()),
            UriFailureKind::Unsupported => TransformError::UnsupportedUri(parts.concat()),
        }
    }
}

impl<W: structured_asn1::memory::Work> UriScratch for Accounted<'_, W> {
    fn diagnostic(&self, kind: UriFailureKind, parts: &[&str]) -> TransformError {
        match self.text(parts) {
            Ok(text) => match kind {
                UriFailureKind::MissingId => {
                    TransformError::AccountedElementNotFound(text.into_owned())
                }
                UriFailureKind::Unsupported => {
                    TransformError::AccountedUnsupportedUri(text.into_owned())
                }
            },
            Err(cause) => cause.into(),
        }
    }
}

enum FragmentFailure<'uri> {
    MissingId(&'uri str),
    Unsupported(&'uri str),
}

impl FragmentFailure<'_> {
    fn diagnostic(self, scratch: &impl UriScratch) -> TransformError {
        match self {
            Self::MissingId(id) => scratch.diagnostic(UriFailureKind::MissingId, &[id]),
            Self::Unsupported(fragment) => {
                scratch.diagnostic(UriFailureKind::Unsupported, &["#", fragment])
            }
        }
    }
}

/// Validate signing URI policy independently of request-scoped resource bytes.
pub(crate) fn validate_signing_reference_uri(
    uri: &str,
    policy: &crate::policy::SigningPolicy,
) -> Result<(), crate::policy::PolicyViolation> {
    if !policy.uris.references.allows(uri) {
        return Err(crate::policy::PolicyViolation::Uri {
            operation: "signing",
            reason: "signing reference URI class is not permitted",
        });
    }
    Ok(())
}

/// Require a request resource boundary before processing a detached signing URI.
pub(crate) fn validate_signing_reference_request(
    uri: &str,
    has_external_resources: bool,
) -> Result<(), crate::policy::PolicyViolation> {
    if !uri.is_empty() && !uri.starts_with('#') && !has_external_resources {
        return Err(crate::policy::PolicyViolation::Uri {
            operation: "signing",
            reason: "external signing references require request-scoped resource bytes",
        });
    }
    Ok(())
}

struct ExternalResourceBudget {
    remaining_total_bytes: Cell<usize>,
    max_resource_bytes: usize,
    max_total_bytes: usize,
}

pub(crate) enum ExternalResourceMapError {
    Policy(crate::policy::PolicyViolation),
    TotalLengthOverflow,
}

pub(crate) fn validate_external_resource_map(
    resources: &HashMap<String, Vec<u8>>,
    max_resource_bytes: usize,
    max_total_bytes: usize,
) -> Result<(), ExternalResourceMapError> {
    let mut total = 0usize;
    for bytes in resources.values() {
        if bytes.len() > max_resource_bytes {
            return Err(ExternalResourceMapError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
                    maximum: max_resource_bytes,
                    actual: bytes.len(),
                },
            ));
        }
        total = total
            .checked_add(bytes.len())
            .ok_or(ExternalResourceMapError::TotalLengthOverflow)?;
    }
    if total > max_total_bytes {
        return Err(ExternalResourceMapError::Policy(
            crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                maximum: max_total_bytes,
                actual: total,
            },
        ));
    }
    Ok(())
}

/// Request-scoped external bytes and their shared aggregate work budget.
///
/// Signing reparses its staged document while filling dependent digests. This
/// context keeps the external-resource budget continuous across every resolver
/// rebound instead of silently resetting it for each parsed generation.
pub(crate) struct ExternalResourceContext<'a> {
    resources: Option<&'a HashMap<String, Vec<u8>>>,
    budget: Rc<ExternalResourceBudget>,
}

impl<'a> ExternalResourceContext<'a> {
    pub(crate) fn new(
        resources: Option<&'a HashMap<String, Vec<u8>>>,
        max_resource_bytes: usize,
        max_total_bytes: usize,
    ) -> Self {
        Self {
            resources,
            budget: Rc::new(ExternalResourceBudget::with_limits(
                max_resource_bytes,
                max_total_bytes,
            )),
        }
    }

    pub(crate) fn is_configured(&self) -> bool {
        self.resources.is_some()
    }

    pub(crate) fn bind<'doc>(
        &'doc self,
        doc: &'doc Document<'doc>,
        registrations: &[crate::IdAttributeRegistration],
        same_document_id_semantics: SameDocumentIdSemantics,
    ) -> UriReferenceResolver<'doc>
    where
        'a: 'doc,
    {
        let mut resolver = UriReferenceResolver::with_id_registrations(doc, registrations)
            .with_same_document_id_semantics(same_document_id_semantics);
        resolver.external_resources = self.resources;
        resolver.external_resource_budget = Rc::clone(&self.budget);
        resolver
    }
}

impl Default for ExternalResourceBudget {
    fn default() -> Self {
        Self::with_limits(
            crate::hard_limits::EXTERNAL_RESOURCE_BYTE_CEILING,
            crate::hard_limits::EXTERNAL_RESOURCE_TOTAL_BYTE_CEILING,
        )
    }
}

impl ExternalResourceBudget {
    fn with_limits(max_resource_bytes: usize, max_total_bytes: usize) -> Self {
        Self {
            remaining_total_bytes: Cell::new(max_total_bytes),
            max_resource_bytes,
            max_total_bytes,
        }
    }

    fn charge(&self, bytes: usize) -> Result<(), TransformError> {
        if bytes > self.max_resource_bytes {
            return Err(transform_resource_limit(
                crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
                self.max_resource_bytes,
                bytes,
            ));
        }
        let remaining = self.remaining_total_bytes.get();
        let Some(next) = remaining.checked_sub(bytes) else {
            self.remaining_total_bytes.set(0);
            return Err(transform_resource_limit(
                crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                self.max_total_bytes,
                self.max_total_bytes
                    .saturating_add(bytes.saturating_sub(remaining)),
            ));
        };
        self.remaining_total_bytes.set(next);
        Ok(())
    }
}

/// Resolves same-document URI references against a parsed XML document.
///
/// Builds a `HashMap<&str, Node>` index on construction for O(1) fragment
/// lookups. Supports caller-provided ID attribute names (important for SAML
/// which uses `ID` rather than the xml:id mechanism).
///
/// # Example
///
/// ```
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use xml_sec::Document;
/// use xml_sec::xmldsig::uri::UriReferenceResolver;
///
/// let xml = r#"<root><item ID="abc">content</item></root>"#;
/// let doc = Document::parse(xml)?;
/// let resolver = UriReferenceResolver::new(&doc);
///
/// assert!(resolver.has_id("abc"));
/// assert_eq!(resolver.id_count(), 1);
/// # Ok(())
/// # }
/// ```
pub struct UriReferenceResolver<'a> {
    doc: &'a Document<'a>,
    view: Option<crate::DocumentView<'a>>,
    resource_identity: Option<String>,
    id_registrations: Vec<crate::IdAttributeRegistration>,
    id_index: ResolverIdIndex<'a>,
    external_resources: Option<&'a HashMap<String, Vec<u8>>>,
    external_resource_budget: Rc<ExternalResourceBudget>,
    same_document_id_semantics: SameDocumentIdSemantics,
}

enum ResolverIdIndex<'a> {
    Borrowed(XmlIdIndex<'a>),
    Retained(HashMap<String, NodeId>),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum TraversalDocumentIdentity {
    Owned(crate::DocumentIdentity),
    External(String),
    Borrowed(usize),
}

impl<'a> ResolverIdIndex<'a> {
    fn node(&self, document: &'a Document<'a>, id: &str) -> Option<Node<'a, 'a>> {
        match self {
            Self::Borrowed(index) => index.node(id),
            Self::Retained(index) => index.get(id).and_then(|node| document.get_node(*node)),
        }
    }

    fn contains(&self, id: &str) -> bool {
        match self {
            Self::Borrowed(index) => index.contains(id),
            Self::Retained(index) => index.contains_key(id),
        }
    }

    fn node_id(&self, id: &str) -> Option<NodeId> {
        match self {
            Self::Borrowed(index) => index.node_id(id),
            Self::Retained(index) => index.get(id).copied(),
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Borrowed(index) => index.len(),
            Self::Retained(index) => index.len(),
        }
    }
}

impl<'a> UriReferenceResolver<'a> {
    pub(crate) fn id_registrations(&self) -> &[crate::IdAttributeRegistration] {
        &self.id_registrations
    }
    /// Build a resolver with default ID attribute names (`ID`, `Id`, `id`).
    pub fn new(doc: &'a Document<'a>) -> Self {
        Self::with_id_attrs(doc, &[])
    }

    /// Build a resolver scanning additional ID attribute names beyond the defaults.
    ///
    /// The defaults (`ID`, `Id`, `id`) are always included; `extra_attrs`
    /// adds to them (does not replace). Pass an empty slice to use only defaults.
    ///
    /// Attribute names use the semantic DOM's local-name view, independent of
    /// the selected XML parser backend. For example, `wsu:Id="..."` is
    /// registered as `"Id"`, not `"wsu:Id"` or `"{namespace}Id"`.
    pub fn with_id_attrs(doc: &'a Document<'a>, extra_attrs: &[&str]) -> Self {
        let id_registrations = extra_attrs
            .iter()
            .map(|name| crate::IdAttributeRegistration::global(*name))
            .collect::<Vec<_>>();
        Self {
            doc,
            view: None,
            resource_identity: None,
            id_index: ResolverIdIndex::Borrowed(XmlIdIndex::with_registrations(
                doc,
                &id_registrations,
            )),
            id_registrations,
            external_resources: None,
            external_resource_budget: Rc::new(ExternalResourceBudget::default()),
            same_document_id_semantics: SameDocumentIdSemantics::Specification,
        }
    }

    /// Build a resolver with typed global and element-scoped ID registrations.
    pub fn with_id_registrations(
        doc: &'a Document<'a>,
        registrations: &[crate::IdAttributeRegistration],
    ) -> Self {
        let id_registrations = registrations.to_vec();
        Self {
            doc,
            view: None,
            resource_identity: None,
            id_index: ResolverIdIndex::Borrowed(XmlIdIndex::with_registrations(
                doc,
                &id_registrations,
            )),
            id_registrations,
            external_resources: None,
            external_resource_budget: Rc::new(ExternalResourceBudget::default()),
            same_document_id_semantics: SameDocumentIdSemantics::Specification,
        }
    }

    pub(crate) fn with_document_view(
        view: crate::DocumentView<'a>,
        registrations: &[crate::IdAttributeRegistration],
    ) -> Self {
        let id_registrations = registrations.to_vec();
        Self {
            doc: view.document(),
            view: Some(view),
            resource_identity: None,
            id_index: ResolverIdIndex::Retained(view.id_index(&id_registrations)),
            id_registrations,
            external_resources: None,
            external_resource_budget: Rc::new(ExternalResourceBudget::default()),
            same_document_id_semantics: SameDocumentIdSemantics::Specification,
        }
    }

    pub(crate) fn with_same_document_id_semantics(
        mut self,
        semantics: SameDocumentIdSemantics,
    ) -> Self {
        self.same_document_id_semantics = semantics;
        self
    }

    /// Rebind document-local URI resolution while retaining caller-owned
    /// external resources and their aggregate byte budget.
    pub(crate) fn for_document_view<'b>(
        &self,
        view: crate::DocumentView<'b>,
    ) -> UriReferenceResolver<'b>
    where
        'a: 'b,
    {
        UriReferenceResolver {
            doc: view.document(),
            view: Some(view),
            resource_identity: None,
            id_index: ResolverIdIndex::Retained(view.id_index(&self.id_registrations)),
            id_registrations: self.id_registrations.clone(),
            external_resources: self.external_resources,
            external_resource_budget: Rc::clone(&self.external_resource_budget),
            same_document_id_semantics: self.same_document_id_semantics,
        }
    }

    /// Rebind document-local URI resolution to a stable external resource.
    ///
    /// The identity survives reparsing, so recursive reference traversal can
    /// distinguish equal fragments in different resources without overlooking
    /// a cycle that returns to the same resource.
    pub(crate) fn for_external_document_view<'b>(
        &self,
        view: crate::DocumentView<'b>,
        resource_identity: &str,
    ) -> UriReferenceResolver<'b>
    where
        'a: 'b,
    {
        let mut resolver = self.for_document_view(view);
        resolver.resource_identity = Some(resource_identity.to_owned());
        resolver
    }

    pub(crate) fn traversal_document_identity(&self) -> TraversalDocumentIdentity {
        if let Some(identity) = &self.resource_identity {
            TraversalDocumentIdentity::External(identity.clone())
        } else if let Some(view) = self.view {
            TraversalDocumentIdentity::Owned(view.identity())
        } else {
            TraversalDocumentIdentity::Borrowed(self.doc as *const Document<'_> as usize)
        }
    }

    /// Attach an explicit caller-owned external-resource map.
    ///
    /// No network or filesystem access is performed by this resolver. Keys are
    /// RFC 3986 resolved URI identities: paths have dot segments removed while
    /// query and fragment suffixes are retained.
    pub fn with_external_resources(mut self, resources: &'a HashMap<String, Vec<u8>>) -> Self {
        self.external_resources = Some(resources);
        self
    }

    pub(crate) fn with_external_resource_limits(
        mut self,
        max_resource_bytes: usize,
        max_total_bytes: usize,
    ) -> Self {
        self.external_resource_budget = Rc::new(ExternalResourceBudget::with_limits(
            max_resource_bytes,
            max_total_bytes,
        ));
        self
    }

    pub(crate) fn external_resource(&self, uri: &str) -> Result<Option<&'a [u8]>, TransformError> {
        let Some(bytes) = self
            .external_resources
            .and_then(|resources| resources.get(uri))
        else {
            return Ok(None);
        };
        self.external_resource_budget.charge(bytes.len())?;
        Ok(Some(bytes))
    }

    fn external_resource_input(
        &self,
        uri: &str,
    ) -> Result<Option<ReferenceInput<'a>>, TransformError> {
        let Some((uri, bytes)) = self
            .external_resources
            .and_then(|resources| resources.get_key_value(uri))
        else {
            return Ok(None);
        };
        self.external_resource_budget.charge(bytes.len())?;
        Ok(Some(ReferenceInput::Binary { bytes, uri }))
    }

    pub(crate) fn external_resource_identity(
        &self,
        uri: &str,
    ) -> Option<crate::operation::OperationResourceIdentity> {
        self.external_resources
            .and_then(|resources| resources.get(uri))
            .map(|bytes| crate::operation::OperationResourceIdentity::external(uri, bytes))
    }

    pub(crate) fn external_resource_set_identity(
        &self,
    ) -> crate::operation::OperationResourceIdentity {
        use sha2::Digest;

        let mut entries = self
            .external_resources
            .into_iter()
            .flat_map(HashMap::iter)
            .collect::<Vec<_>>();
        entries.sort_unstable_by_key(|(uri, _)| *uri);
        let mut hasher = sha2::Sha256::new();
        for (uri, bytes) in entries {
            hasher.update(uri.len().to_be_bytes());
            hasher.update(uri.as_bytes());
            hasher.update(bytes.len().to_be_bytes());
            hasher.update(bytes);
        }
        crate::operation::OperationResourceIdentity::External {
            uri: "caller-owned-external-resource-set".to_owned(),
            fingerprint: hasher.finalize().into(),
        }
    }

    /// Dereference a URI string to a [`TransformData`].
    ///
    /// # URI forms
    ///
    /// | URI | Result |
    /// |-----|--------|
    /// | `""` (empty) | Entire document, comments excluded |
    /// | `"#foo"` | Subtree rooted at element with ID `foo`, comments excluded |
    /// | `"#xpointer(/)"` | Entire document, comments included |
    /// | `"#xpointer(id('foo'))"` | Subtree rooted at element with ID `foo`, comments included |
    /// | external URI in caller map | `TransformData::Resource` borrowing the mapped bytes and their resolved map key |
    /// | other | `Err(UnsupportedUri)` |
    pub fn dereference(&self, uri: &str) -> Result<TransformData<'a>, TransformError> {
        self.dereference_with_optional_budget(uri, None)
    }

    pub(crate) fn dereference_with_budget(
        &self,
        uri: &str,
        budget: &NodeSetMaterializationBudget,
    ) -> Result<TransformData<'a>, TransformError> {
        self.dereference_with_optional_budget(uri, Some(budget))
    }

    pub(crate) fn dereference_from_with_budget(
        &self,
        uri: &str,
        origin: Node<'_, '_>,
        budget: &NodeSetMaterializationBudget,
        xml_base_budget: &XmlBaseResolutionBudget,
    ) -> Result<TransformData<'a>, TransformError> {
        // XMLDSig assigns special dereference semantics to lexical empty and
        // fragment-only references. Only external references use XML Base.
        if uri.is_empty() || uri.starts_with('#') {
            return self.dereference_with_budget(uri, budget);
        }
        let resolved = resolve_uri_from_node_with_budget(origin, uri, xml_base_budget)
            .map_err(map_xml_base_resolution_error)?;
        self.dereference_with_budget(&resolved, budget)
    }

    /// Preserve an admitted external lookup's absence. Unsupported fragment
    /// syntax, ambiguous IDs and resource failures are never recast as absence.
    pub(crate) fn replay_input_from_with_budget<S: UriScratch>(
        &self,
        uri: &str,
        origin: Node<'_, '_>,
        budget: &NodeSetMaterializationBudget,
        xml_base_budget: &XmlBaseResolutionBudget,
        scratch: &S,
    ) -> Result<Option<ReferenceInput<'a>>, TransformError> {
        if uri.is_empty() {
            return Ok(Some(ReferenceInput::Xml {
                root: self.doc.root(),
                with_comments: false,
            }));
        }
        if let Some(fragment) = uri.strip_prefix('#') {
            let normalized = Self::normalize_fragment_in(
                fragment,
                Some(budget),
                self.same_document_id_semantics,
                scratch,
            )?;
            let fragment = normalized.view(scratch)?;
            scratch.charge(fragment.len())?;
            return self
                .normalized_fragment_input(fragment)
                .map(Some)
                .map_err(|cause| cause.diagnostic(scratch));
        }
        let resolved = crate::c14n::xml_base::resolve_uri_from_node_in(
            origin,
            uri,
            None,
            xml_base_budget,
            scratch,
        )
        .map_err(map_xml_base_execution_error)?;
        let resolved = resolved.view().map_err(map_xml_base_execution_error)?;
        scratch
            .charge(resolved.len())
            .map_err(map_xml_base_execution_error)?;
        self.external_resource_input(resolved)
    }

    fn dereference_with_optional_budget(
        &self,
        uri: &str,
        budget: Option<&NodeSetMaterializationBudget>,
    ) -> Result<TransformData<'a>, TransformError> {
        if uri.is_empty() {
            // Empty URI = entire document without comments
            // XMLDSig §4.3.3.2: "the reference is to the document [...],
            // and the comment nodes are not included"
            let nodes = match self.view {
                Some(view) => NodeSet::entire_document_without_comments_from_view(view, budget)?,
                None => match budget {
                    Some(budget) => {
                        NodeSet::entire_document_without_comments_with_budget(self.doc, budget)?
                    }
                    None => NodeSet::entire_document_without_comments(self.doc)?,
                },
            };
            Ok(TransformData::NodeSet(nodes))
        } else if let Some(fragment) = uri.strip_prefix('#') {
            self.dereference_fragment(fragment, budget)
        } else {
            self.external_resource_input(uri)?
                .map(|input| match input {
                    ReferenceInput::Binary { bytes, uri } => TransformData::Resource { bytes, uri },
                    ReferenceInput::Xml { .. } => unreachable!("external resources are octets"),
                })
                .ok_or_else(|| TransformError::UnsupportedUri(uri.to_string()))
        }
    }

    /// Resolve a URI fragment (the part after `#`).
    ///
    /// Handles:
    /// - `xpointer(/)` → entire document (with comments, per XPointer spec)
    /// - `xpointer(id('foo'))` → element by ID, retaining comments
    /// - bare name `foo` → element by ID attribute
    fn dereference_fragment(
        &self,
        fragment: &str,
        budget: Option<&NodeSetMaterializationBudget>,
    ) -> Result<TransformData<'a>, TransformError> {
        let normalized =
            Self::normalize_fragment(fragment, budget, self.same_document_id_semantics)?;
        let fragment = normalized.as_ref();
        self.dereference_normalized_fragment(fragment, budget)
    }

    fn dereference_normalized_fragment(
        &self,
        fragment: &str,
        budget: Option<&NodeSetMaterializationBudget>,
    ) -> Result<TransformData<'a>, TransformError> {
        let ReferenceInput::Xml {
            root,
            with_comments,
        } = self
            .normalized_fragment_input(fragment)
            .map_err(|cause| cause.diagnostic(&Native))?
        else {
            unreachable!("a same-document fragment resolves to XML");
        };
        NodeSet::projected(root, with_comments, budget).map(TransformData::NodeSet)
    }

    fn normalized_fragment_input<'uri>(
        &self,
        fragment: &'uri str,
    ) -> Result<ReferenceInput<'a>, FragmentFailure<'uri>> {
        if fragment.is_empty() {
            // Bare "#" is not a valid same-document reference
            return Err(FragmentFailure::Unsupported(fragment));
        }

        if is_xpointer_root(fragment) {
            // XPointer root: entire document WITH comments (unlike empty URI).
            // Per XMLDSig §4.3.3.3: "the XPointer expression [...] includes
            // comment nodes"
            Ok(ReferenceInput::Xml {
                root: self.doc.root(),
                with_comments: true,
            })
        } else {
            let (id, with_comments) = self
                .same_document_id_fragment(fragment)
                .ok_or(FragmentFailure::Unsupported(fragment))?;
            self.id_index
                .node(self.doc, id)
                .map(|root| ReferenceInput::Xml {
                    root,
                    with_comments,
                })
                .ok_or(FragmentFailure::MissingId(id))
        }
    }

    fn same_document_id_fragment<'uri>(&self, fragment: &'uri str) -> Option<(&'uri str, bool)> {
        Self::id_fragment(fragment, self.same_document_id_semantics)
    }

    pub(crate) fn id_fragment(
        fragment: &str,
        semantics: SameDocumentIdSemantics,
    ) -> Option<(&str, bool)> {
        if fragment.is_empty() {
            return None;
        }
        if let Some(id) = parse_xpointer_id_fragment(fragment) {
            // Explicit XPointer dereference retains comments, unlike every
            // barename mode, including libxmlsec1's internal wrapper.
            if id.is_empty() {
                return None;
            }
            return Some((id, true));
        }
        if fragment.starts_with("xpointer(") {
            return None;
        }
        match semantics {
            SameDocumentIdSemantics::Specification if !is_xml_ncname(fragment) => {
                return None;
            }
            SameDocumentIdSemantics::XmlSecBarename if fragment.contains('\'') => {
                return None;
            }
            SameDocumentIdSemantics::Specification
            | SameDocumentIdSemantics::XmlSecBarename
            | SameDocumentIdSemantics::XmlSecVisa3d => {}
        }
        Some((fragment, false))
    }

    /// Check if an ID is registered in the resolver's index.
    pub fn has_id(&self, id: &str) -> bool {
        self.id_index.contains(id)
    }

    /// Resolve an unambiguous XML ID to its element node.
    ///
    /// Returns `None` when the ID is absent or duplicated, matching fragment
    /// dereferencing and operation start-node selection.
    pub fn node_for_id(&self, id: &str) -> Option<Node<'a, 'a>> {
        self.id_index.node(self.doc, id)
    }

    /// Resolve a same-document URI to an element under the configured grammar.
    /// An empty URI selects the document element for element-valued consumers.
    pub fn node_for_same_document_reference(
        &self,
        uri: &str,
    ) -> Result<Option<Node<'a, 'a>>, TransformError> {
        self.node_for_same_document_reference_with_budget(uri, None)
    }

    pub(crate) fn node_for_same_document_reference_with_budget(
        &self,
        uri: &str,
        budget: Option<&NodeSetMaterializationBudget>,
    ) -> Result<Option<Node<'a, 'a>>, TransformError> {
        self.node_for_same_document_reference_in(uri, budget, &Native)
    }

    pub(crate) fn node_for_same_document_reference_in(
        &self,
        uri: &str,
        budget: Option<&NodeSetMaterializationBudget>,
        scratch: &impl UriScratch,
    ) -> Result<Option<Node<'a, 'a>>, TransformError> {
        if uri.is_empty() {
            return Ok(Some(self.doc.root_element()));
        }
        let target = self.node_id_for_reference_resource_in(uri, budget, scratch)?;
        if target == Some(self.doc.root().id()) {
            return Err(scratch.diagnostic(UriFailureKind::Unsupported, &[uri]));
        }
        Ok(target.and_then(|id| self.doc.get_node(id)))
    }

    /// Resolve a `#name` URI only when it is a bare name under this resolver's
    /// fragment normalization and ID semantics. `None` means another form: a
    /// non-fragment URI, an XPointer, or a fragment the grammar rejects;
    /// `Some(None)` is a bare name no single element carries.
    pub(crate) fn bare_name_node_in(
        &self,
        uri: &str,
        budget: Option<&NodeSetMaterializationBudget>,
        scratch: &impl UriScratch,
    ) -> Result<Option<Option<Node<'a, 'a>>>, TransformError> {
        let Some(fragment) = uri.strip_prefix('#') else {
            return Ok(None);
        };
        let normalized = match Self::normalize_fragment_in(
            fragment,
            budget,
            self.same_document_id_semantics,
            scratch,
        ) {
            Ok(normalized) => normalized,
            Err(TransformError::InvalidFragment) => return Ok(None),
            Err(error) => return Err(error),
        };
        let fragment = normalized.view(scratch)?;
        scratch.charge(fragment.len())?;
        // `same_document_id_fragment` returns `None` only when the grammar
        // rejects the fragment. A missing or duplicated ID takes the first arm,
        // where the index lookup yields `Some(None)`.
        Ok(match self.same_document_id_fragment(fragment) {
            Some((id, false)) => Some(self.id_index.node(self.doc, id)),
            Some((_, true)) | None => None,
        })
    }

    /// Borrowed association prefilter, sharing the normal URI grammar and ID
    /// index without constructing errors for unrelated or malformed references.
    #[cfg(feature = "xmlenc")]
    pub(crate) fn same_document_reference_targets(&self, uri: &str, target: NodeId) -> bool {
        if uri.is_empty() {
            return self.doc.root_element().id() == target;
        }
        let Some(fragment) = uri.strip_prefix('#') else {
            return false;
        };
        let Ok(normalized) =
            Self::normalize_fragment(fragment, None, self.same_document_id_semantics)
        else {
            return false;
        };
        let fragment = normalized.as_ref();
        if fragment.is_empty() || is_xpointer_root(fragment) {
            return false;
        }
        let Some((id, _)) = self.same_document_id_fragment(fragment) else {
            return false;
        };
        self.id_index.node_id(id) == Some(target)
    }

    /// Resolve a same-document URI to a stable node identity under the
    /// configured grammar, for secondary consumers such as Manifest trust.
    pub(crate) fn node_id_for_same_document_reference(
        &self,
        uri: &str,
    ) -> Result<Option<NodeId>, TransformError> {
        let target = self.node_id_for_reference_resource(uri, None)?;
        if uri.is_empty() || target == Some(self.doc.root().id()) {
            return Err(TransformError::UnsupportedUri(uri.to_owned()));
        }
        Ok(target)
    }

    /// Classify the resource once using the same normalization as dereference;
    /// unlike element-only consumers, evidence may bind the document root.
    pub(crate) fn node_id_for_reference_resource(
        &self,
        uri: &str,
        budget: Option<&NodeSetMaterializationBudget>,
    ) -> Result<Option<NodeId>, TransformError> {
        self.node_id_for_reference_resource_in(uri, budget, &Native)
    }

    fn node_id_for_reference_resource_in(
        &self,
        uri: &str,
        budget: Option<&NodeSetMaterializationBudget>,
        scratch: &impl UriScratch,
    ) -> Result<Option<NodeId>, TransformError> {
        if uri.is_empty() {
            return Ok(Some(self.doc.root().id()));
        }
        let fragment = uri
            .strip_prefix('#')
            .ok_or_else(|| scratch.diagnostic(UriFailureKind::Unsupported, &[uri]))?;
        let normalized = Self::normalize_fragment_in(
            fragment,
            budget,
            self.same_document_id_semantics,
            scratch,
        )?;
        let fragment = normalized.view(scratch)?;
        scratch.charge(fragment.len())?;
        if fragment.is_empty() {
            return Err(scratch.diagnostic(UriFailureKind::Unsupported, &[uri]));
        }
        if is_xpointer_root(fragment) {
            return Ok(Some(self.doc.root().id()));
        }
        let (id, _) = self
            .same_document_id_fragment(fragment)
            .ok_or_else(|| scratch.diagnostic(UriFailureKind::Unsupported, &[uri]))?;
        Ok(self.id_index.node_id(id))
    }

    pub(crate) fn node_for_node_id(&self, id: NodeId) -> Option<Node<'a, 'a>> {
        self.doc.get_node(id)
    }

    /// Get the number of registered IDs.
    pub fn id_count(&self) -> usize {
        self.id_index.len()
    }

    pub(crate) fn normalize_fragment<'uri>(
        fragment: &'uri str,
        budget: Option<&NodeSetMaterializationBudget>,
        semantics: SameDocumentIdSemantics,
    ) -> Result<std::borrow::Cow<'uri, str>, TransformError> {
        match Self::normalize_fragment_in(fragment, budget, semantics, &Native)? {
            NormalizedFragment::Borrowed(text) => Ok(std::borrow::Cow::Borrowed(text)),
            NormalizedFragment::Owned(bytes) => Ok(std::borrow::Cow::Owned(
                String::from_utf8(bytes).map_err(|_| invalid_fragment())?,
            )),
        }
    }

    pub(crate) fn normalize_fragment_in<'uri, S: Scratch>(
        fragment: &'uri str,
        budget: Option<&NodeSetMaterializationBudget>,
        semantics: SameDocumentIdSemantics,
        scratch: &S,
    ) -> Result<NormalizedFragment<'uri, S::Bytes>, TransformError> {
        let invalid = invalid_fragment;
        if fragment.len() > crate::hard_limits::XML_DOCUMENT_BYTE_CEILING {
            return Err(invalid());
        }
        scratch.charge(fragment.len())?;
        let mut result = NormalizedFragment::Borrowed(fragment);
        // XPointer Framework sections 3 and 4 reverse URI escaping before
        // evaluating the pointer. libxmlsec1's barename/Visa3D modes instead
        // use literal bare ID strings. Explicit pointers still follow the
        // Framework, independently of the selected barename compatibility mode.
        // https://www.w3.org/TR/2003/REC-xptr-framework-20030325/#escaping
        if fragment.contains('%')
            && (semantics == SameDocumentIdSemantics::Specification
                || has_encoded_xpointer_prefix(fragment))
        {
            if let Some(budget) = budget {
                budget.reserve_workspace(fragment.len())?;
            }
            let mut decoded = scratch.bytes();
            decoded.reserve(fragment.len())?;
            scratch.charge(fragment.len())?;
            let bytes = fragment.as_bytes();
            let mut position = 0;
            let mut chunk = [0; 1024];
            let mut used = 0;
            while position < bytes.len() {
                let byte = if bytes[position] == b'%' {
                    let high = bytes
                        .get(position + 1)
                        .and_then(|byte| hex_digit(*byte))
                        .ok_or_else(invalid)?;
                    let low = bytes
                        .get(position + 2)
                        .and_then(|byte| hex_digit(*byte))
                        .ok_or_else(invalid)?;
                    position += 3;
                    high * 16 + low
                } else {
                    let byte = bytes[position];
                    position += 1;
                    byte
                };
                chunk[used] = byte;
                used += 1;
                if used == chunk.len() {
                    decoded.append(&chunk)?;
                    used = 0;
                }
            }
            decoded.append(&chunk[..used])?;
            result = NormalizedFragment::Owned(decoded);
        }
        let text = result.view(scratch)?;
        if text.starts_with("xpointer(") {
            // Framework [7] balances parentheses even inside XPath literals;
            // only ^(, ^), and ^^ are escaping pairs.
            scratch.charge(text.len())?;
            let bytes = text.as_bytes();
            let mut depth = 0usize;
            let mut position = "xpointer".len();
            while position < bytes.len() {
                match bytes[position] {
                    b'^' => {
                        if !matches!(bytes.get(position + 1), Some(b'(' | b')' | b'^')) {
                            return Err(invalid());
                        }
                        position += 2;
                        continue;
                    }
                    b'(' => depth += 1,
                    b')' => {
                        if depth == 0 {
                            return Err(invalid());
                        }
                        depth -= 1;
                        if depth == 0 && position + 1 != bytes.len() {
                            return Err(invalid());
                        }
                    }
                    _ => {}
                }
                position += 1;
            }
            if depth != 0 {
                return Err(invalid());
            }
            scratch.charge(text.len())?;
            if text.contains('^') {
                if let NormalizedFragment::Borrowed(text) = result {
                    if let Some(budget) = budget {
                        budget.reserve_workspace(text.len())?;
                    }
                    let mut bytes = scratch.bytes();
                    bytes.reserve(text.len())?;
                    bytes.append(text.as_bytes())?;
                    result = NormalizedFragment::Owned(bytes);
                }
                let NormalizedFragment::Owned(ref mut bytes) = result else {
                    unreachable!()
                };
                scratch.charge(bytes.len())?;
                let mut escaped = false;
                let mut write = 0;
                for read in 0..bytes.len() {
                    let character = bytes[read];
                    if escaped {
                        escaped = false;
                    } else if character == b'^' {
                        escaped = true;
                        continue;
                    }
                    bytes[write] = character;
                    write += 1;
                }
                bytes.truncate(write);
            }
        }
        Ok(result)
    }
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn has_encoded_xpointer_prefix(fragment: &str) -> bool {
    // Recognize URI-escaped scheme syntax without materializing a candidate.
    let mut bytes = fragment.bytes();
    for expected in b"xpointer(" {
        let Some(mut actual) = bytes.next() else {
            return false;
        };
        if actual == b'%' {
            let Some(high) = bytes.next().and_then(hex_digit) else {
                return false;
            };
            let Some(low) = bytes.next().and_then(hex_digit) else {
                return false;
            };
            actual = high * 16 + low;
        }
        if actual != *expected {
            return false;
        }
    }
    true
}

fn is_xpointer_root(fragment: &str) -> bool {
    fragment
        .strip_prefix("xpointer(")
        .and_then(|value| value.strip_suffix(')'))
        .is_some_and(|expression| xml_space_trim(expression) == "/")
}

pub(crate) fn map_xml_base_execution_error(error: crate::c14n::C14nError) -> TransformError {
    match error {
        crate::c14n::C14nError::XmlBaseComponentsTooLarge { max, actual } => {
            map_xml_base_resolution_error(XmlBaseResolutionError::Components {
                maximum: max,
                actual,
            })
        }
        crate::c14n::C14nError::XmlBaseResolutionTooLarge { max_bytes, actual } => {
            map_xml_base_resolution_error(XmlBaseResolutionError::Bytes {
                maximum: max_bytes,
                actual,
            })
        }
        error => error.into(),
    }
}

pub(crate) fn map_xml_base_resolution_error(error: XmlBaseResolutionError) -> TransformError {
    match error {
        XmlBaseResolutionError::Components { maximum, actual } => transform_resource_limit(
            crate::policy::resource_name::XML_BASE_COMPONENTS,
            maximum,
            actual,
        ),
        XmlBaseResolutionError::Bytes { maximum, actual } => transform_resource_limit(
            crate::policy::resource_name::XML_BASE_RESOLUTION_BYTES,
            maximum,
            actual,
        ),
    }
}

/// Parse `xpointer(id('value'))` or `xpointer(id("value"))` and return the ID value.
/// Returns `None` if the fragment doesn't match this pattern.
pub(crate) fn parse_xpointer_id_fragment(fragment: &str) -> Option<&str> {
    // XPath 1.0 section 3.7 [29]: a Literal cannot contain its delimiter.
    // Whitespace may separate tokens, but must not split the function name.
    // https://www.w3.org/TR/1999/REC-xpath-19991116/#exprlex
    let expression = fragment.strip_prefix("xpointer(")?.strip_suffix(')')?;
    let argument = xml_space_trim(expression)
        .strip_prefix("id")?
        .trim_start_matches(is_xml_space)
        .strip_prefix('(')?;
    let literal = xml_space_trim(argument.strip_suffix(')')?);
    let quote = literal.as_bytes().first().copied()?;
    if !matches!(quote, b'\'' | b'"')
        || literal.len() < 2
        || literal.as_bytes().last() != Some(&quote)
    {
        return None;
    }
    let value = &literal[1..literal.len() - 1];
    if value.as_bytes().contains(&quote) {
        return None;
    }
    Some(value)
}

fn is_xml_space(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\r' | '\n')
}

fn xml_space_trim(value: &str) -> &str {
    value.trim_matches(is_xml_space)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::types::NodeSet;
    use super::*;

    #[test]
    fn fragment_current_execution_admits_work_and_capacity() {
        // Escaping must be paid by the current query, not the retained parser;
        // refused and completed temporaries release their capacity immediately.
        use crate::c14n::scratch::Accounted;
        use structured_asn1::memory::{Memory, MemoryAccount};

        let work = Memory::new(std::sync::Arc::new(MemoryAccount::new(1 << 20, 1 << 20)));
        for (source, expected) in [
            ("target", "target"),
            ("caf%C3%A9", "café"),
            ("xpointer(id('a^(b^)'))", "xpointer(id('a(b)'))"),
            ("%78pointer(id('a%5E(b%5E)'))", "xpointer(id('a(b)'))"),
        ] {
            let normalized = UriReferenceResolver::normalize_fragment_in(
                source,
                None,
                SameDocumentIdSemantics::Specification,
                &Accounted(&work),
            )
            .unwrap();
            assert_eq!(normalized.view(&Accounted(&work)).unwrap(), expected);
            drop(normalized);
            assert_eq!(work.used(), 0);
        }
        let tiny = Memory::new(std::sync::Arc::new(MemoryAccount::new(1, 1 << 20)));
        assert!(
            UriReferenceResolver::normalize_fragment_in(
                "tar%67et",
                None,
                SameDocumentIdSemantics::Specification,
                &Accounted(&tiny),
            )
            .is_err()
        );
        let zero = Memory::new(std::sync::Arc::new(MemoryAccount::new(1 << 20, 0)));
        assert!(
            UriReferenceResolver::normalize_fragment_in(
                "target",
                None,
                SameDocumentIdSemantics::Specification,
                &Accounted(&zero),
            )
            .is_err()
        );
    }

    #[test]
    fn fragment_query_local_and_aggregate_boundaries_agree() {
        // A retained source must not replace a query's local ceiling with its
        // aggregate account. Exact admission succeeds; one-less refuses before
        // returning a normalized view, releasing all temporary storage.
        use crate::c14n::scratch::Accounted;
        use structured_asn1::{
            Encoding, Limits, Parser,
            memory::{Memory, MemoryAccount},
        };
        let source = "%78pointer(id('caf%C3%A9%5E(x%5E)'))";
        let run = |local: u64, aggregate: usize| {
            let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(4096, aggregate)));
            let parser = Parser::new(
                Encoding::Der,
                Limits {
                    max_work: local,
                    ..Limits::default()
                },
                memory.clone(),
            );
            let reader = parser.read(&[], 0).unwrap();
            let work = reader.execution();
            let before = memory.work_used();
            let result = (|| {
                let fragment = UriReferenceResolver::normalize_fragment_in(
                    source,
                    None,
                    SameDocumentIdSemantics::Specification,
                    &Accounted(&work),
                )?;
                assert_eq!(fragment.view(&Accounted(&work))?, "xpointer(id('café(x)'))");
                Ok::<_, TransformError>(())
            })();
            assert_eq!(memory.used(), 0);
            (result, memory.work_used() - before)
        };
        let (result, cost) = run(1 << 20, 1 << 20);
        result.unwrap();
        assert!(cost > source.len());
        for (local, aggregate, success) in [
            (cost as u64, cost, true),
            (cost as u64 - 1, cost, false),
            (cost as u64, cost - 1, false),
            (0, cost, false),
            (cost as u64, 0, false),
        ] {
            let (result, _) = run(local, aggregate);
            if success {
                result.unwrap();
            } else {
                assert!(matches!(
                    result,
                    Err(TransformError::C14n(
                        crate::c14n::C14nError::SharedExecution(
                            structured_asn1::memory::MemoryError::WorkExceeded
                        )
                    ))
                ));
            }
        }
    }

    #[test]
    fn escaped_fragments_preserve_target_and_comment_semantics() {
        // Framework URI/caret escaping must identify the same node; only the
        // explicit XPointer form retains comments (XMLDSig 4.4.3.3).
        let document =
            Document::parse(r#"<root><item ID="café"><!--kept--></item><item ID="a(b)"/></root>"#)
                .unwrap();
        let resolver = UriReferenceResolver::new(&document);
        let plain = resolver
            .dereference("#caf%C3%A9")
            .unwrap()
            .into_node_set()
            .unwrap();
        let pointer = resolver
            .dereference("#xpointer(id('caf%C3%A9'))")
            .unwrap()
            .into_node_set()
            .unwrap();
        let comment = document
            .descendants()
            .find(|node| node.is_comment())
            .unwrap();
        assert!(!plain.contains(comment));
        assert!(pointer.contains(comment));
        assert!(resolver.dereference("#xpointer(id('a^(b^)'))").is_ok());
        assert!(resolver.dereference("#xpointer( / )").is_ok());
        for uri in [
            "#caf%",
            "#caf%FF",
            "#xpointer(id('a^x'))",
            "#xpointer(id('a(b'))",
            "#xpointer(id('a') or 'b')",
        ] {
            assert!(resolver.dereference(uri).is_err(), "{uri}");
        }
    }

    #[test]
    fn fragment_decoding_reserves_workspace_before_allocation() {
        // A reference cannot bypass the cumulative projection budget through
        // its URI-decoding workspace, while a borrowed fragment costs nothing.
        let budget = NodeSetMaterializationBudget::with_limit(0);
        assert!(
            UriReferenceResolver::normalize_fragment(
                "target",
                Some(&budget),
                SameDocumentIdSemantics::Specification
            )
            .is_ok()
        );
        assert!(matches!(
            UriReferenceResolver::normalize_fragment(
                "tar%67et",
                Some(&budget),
                SameDocumentIdSemantics::Specification
            ),
            Err(TransformError::Policy(_))
        ));
        assert!(matches!(
            UriReferenceResolver::normalize_fragment(
                "xpointer(id('a^(b^)'))",
                Some(&budget),
                SameDocumentIdSemantics::Specification
            ),
            Err(TransformError::Policy(_))
        ));
    }

    #[test]
    fn xpointer_id_requires_one_complete_literal() {
        // XPath 1.0 Literal excludes its own delimiter; accepting a compound
        // expression here incorrectly resolves a different element.
        assert_eq!(parse_xpointer_id_fragment("xpointer(id('a' or 'b'))"), None);
        assert_eq!(
            parse_xpointer_id_fragment("xpointer(id(\"a\" or \"b\"))"),
            None
        );
        assert_eq!(
            parse_xpointer_id_fragment("xpointer( id ( 'target' ) )"),
            Some("target")
        );
    }

    #[test]
    fn empty_same_document_node_reference_selects_the_document_element() {
        // Element-valued consumers of the Reference URI contract interpret an
        // empty URI as the root element of the current XML document.
        let document = Document::parse("<root><child/></root>").unwrap();
        let resolver = UriReferenceResolver::new(&document);

        assert_eq!(
            resolver
                .node_for_same_document_reference("")
                .unwrap()
                .unwrap(),
            document.root_element()
        );
    }

    #[test]
    fn empty_uri_returns_whole_document() {
        let xml = "<root><child>text</child></root>";
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        let data = resolver.dereference("").unwrap();
        let node_set = data.into_node_set().unwrap();

        // Whole document: root and child should be in the set
        let root = doc.root_element();
        assert!(node_set.contains(root));
        let child = root.first_child().unwrap();
        assert!(node_set.contains(child));
    }

    #[test]
    fn empty_uri_excludes_comments() {
        let xml = "<root><!-- comment --><child/></root>";
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        let data = resolver.dereference("").unwrap();
        let node_set = data.into_node_set().unwrap();

        // Comment should be excluded
        for node in doc.descendants() {
            if node.is_comment() {
                assert!(
                    !node_set.contains(node),
                    "comment should be excluded for empty URI"
                );
            }
        }
        // Element should still be included
        assert!(node_set.contains(doc.root_element()));
    }

    #[test]
    fn fragment_uri_resolves_by_id_attr() {
        let xml = r#"<root><item ID="abc">content</item><item ID="def">other</item></root>"#;
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        let data = resolver.dereference("#abc").unwrap();
        let node_set = data.into_node_set().unwrap();

        // The element with ID="abc" and its children should be in the set
        let abc_elem = doc
            .descendants()
            .find(|n| n.attribute("ID") == Some("abc"))
            .unwrap();
        assert!(node_set.contains(abc_elem));

        // The text child "content" should also be in the set
        let text_child = abc_elem.first_child().unwrap();
        assert!(node_set.contains(text_child));

        // The root element should NOT be in the set (subtree only)
        assert!(!node_set.contains(doc.root_element()));

        // The element with ID="def" should NOT be in the set
        let def_elem = doc
            .descendants()
            .find(|n| n.attribute("ID") == Some("def"))
            .unwrap();
        assert!(!node_set.contains(def_elem));
    }

    #[test]
    fn fragment_uri_resolves_lowercase_id() {
        let xml = r#"<root><item id="lower">text</item></root>"#;
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        let data = resolver.dereference("#lower").unwrap();
        let node_set = data.into_node_set().unwrap();

        let elem = doc
            .descendants()
            .find(|n| n.attribute("id") == Some("lower"))
            .unwrap();
        assert!(node_set.contains(elem));
    }

    #[test]
    fn fragment_uri_resolves_mixed_case_id() {
        let xml = r#"<root><ds:Signature Id="sig1" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/></root>"#;
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        assert!(resolver.has_id("sig1"));
        let data = resolver.dereference("#sig1").unwrap();
        assert!(data.into_node_set().is_ok());
    }

    #[test]
    fn fragment_uri_not_found() {
        let xml = "<root><child>text</child></root>";
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        let result = resolver.dereference("#nonexistent");
        assert!(result.is_err());
        match result.unwrap_err() {
            TransformError::ElementNotFound(id) => assert_eq!(id, "nonexistent"),
            other => panic!("expected ElementNotFound, got: {other:?}"),
        }
    }

    #[test]
    fn missing_fragment_diagnostic_obeys_current_capacity() {
        // An unresolved attacker-controlled ID must not escape as an uncharged
        // String when the query cannot retain its diagnostic.
        use crate::c14n::scratch::Accounted;
        use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};

        let doc = Document::parse("<root/>").unwrap();
        let resolver = UriReferenceResolver::new(&doc);
        let uri = format!("#{}", "x".repeat(65536));
        let work = Memory::new(std::sync::Arc::new(MemoryAccount::new(1024, 1 << 22)));
        let result = resolver.replay_input_from_with_budget(
            &uri,
            doc.root_element(),
            &NodeSetMaterializationBudget::default(),
            &XmlBaseResolutionBudget::default(),
            &Accounted(&work),
        );
        assert!(matches!(
            result,
            Err(TransformError::C14n(
                crate::c14n::C14nError::SharedExecution(MemoryError::LimitExceeded)
            ))
        ));
        assert_eq!(work.used(), 0);
    }

    #[test]
    fn rejected_fragment_diagnostics_obey_current_capacity() {
        // Unsupported parsed pointers also carry attacker-controlled text;
        // malformed normalization itself needs no owned diagnostic at all.
        use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
        let doc = Document::parse("<root/>").unwrap();
        let resolver = UriReferenceResolver::new(&doc);
        let uri = format!("#xpointer('{}')", "x".repeat(65536));
        let work = Memory::new(std::sync::Arc::new(MemoryAccount::new(1024, 1 << 22)));
        assert!(matches!(
            resolver.replay_input_from_with_budget(
                &uri,
                doc.root_element(),
                &NodeSetMaterializationBudget::default(),
                &XmlBaseResolutionBudget::default(),
                &Accounted(&work),
            ),
            Err(TransformError::C14n(
                crate::c14n::C14nError::SharedExecution(MemoryError::LimitExceeded)
            ))
        ));
        assert_eq!(work.used(), 0);
        let work = Memory::new(std::sync::Arc::new(MemoryAccount::new(0, 1024)));
        assert!(matches!(
            resolver.replay_input_from_with_budget(
                "#xpointer(^)",
                doc.root_element(),
                &NodeSetMaterializationBudget::default(),
                &XmlBaseResolutionBudget::default(),
                &Accounted(&work),
            ),
            Err(TransformError::InvalidFragment)
        ));
        assert_eq!(work.used(), 0);
    }

    #[test]
    fn unsupported_external_uri() {
        let xml = "<root/>";
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        let result = resolver.dereference("http://example.com/doc.xml");
        assert!(result.is_err());
        match result.unwrap_err() {
            TransformError::UnsupportedUri(uri) => {
                assert_eq!(uri, "http://example.com/doc.xml")
            }
            other => panic!("expected UnsupportedUri, got: {other:?}"),
        }
    }

    #[test]
    fn unsupported_xpointer_expression() {
        // XPointer expressions other than xpointer(/) and xpointer(id(...))
        // should return UnsupportedUri, not fall through to ID lookup
        let xml = "<root/>";
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        let result = resolver.dereference("#xpointer(foo())");
        assert!(result.is_err());
        match result.unwrap_err() {
            TransformError::UnsupportedUri(uri) => {
                assert_eq!(uri, "#xpointer(foo())")
            }
            other => panic!("expected UnsupportedUri, got: {other:?}"),
        }

        // Generic XPointer with XPath should also be unsupported
        let result = resolver.dereference("#xpointer(//element)");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TransformError::UnsupportedUri(_)
        ));
    }

    #[test]
    fn empty_fragment_rejected() {
        // Bare "#" (empty fragment) is not a valid same-document reference
        let xml = "<root/>";
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        let result = resolver.dereference("#");
        assert!(result.is_err());
        match result.unwrap_err() {
            TransformError::UnsupportedUri(uri) => assert_eq!(uri, "#"),
            other => panic!("expected UnsupportedUri, got: {other:?}"),
        }
    }

    #[test]
    fn foreign_document_node_rejected() {
        // NodeSet.contains() must reject nodes from a different document
        let xml1 = "<root><child/></root>";
        let xml2 = "<other><item/></other>";
        let doc1 = Document::parse(xml1).unwrap();
        let doc2 = Document::parse(xml2).unwrap();

        let node_set = NodeSet::entire_document_without_comments(&doc1).unwrap();

        // Node from doc2 should NOT be in doc1's node set
        let foreign_node = doc2.root_element();
        assert!(
            !node_set.contains(foreign_node),
            "foreign document node should be rejected"
        );

        // Node from doc1 should be in the set
        let own_node = doc1.root_element();
        assert!(node_set.contains(own_node));
    }

    #[test]
    fn custom_id_attr_name() {
        // roxmltree stores `wsu:Id` with local name "Id" — already in DEFAULT_ID_ATTRS.
        // Test with a truly custom attribute name instead.
        let xml = r#"<root><elem myid="custom1">data</elem></root>"#;
        let doc = Document::parse(xml).unwrap();

        // Default resolver doesn't know about "myid"
        let resolver_default = UriReferenceResolver::new(&doc);
        assert!(!resolver_default.has_id("custom1"));

        // Custom resolver with "myid" added
        let resolver_custom = UriReferenceResolver::with_id_attrs(&doc, &["myid"]);
        assert!(resolver_custom.has_id("custom1"));

        let data = resolver_custom.dereference("#custom1").unwrap();
        assert!(data.into_node_set().is_ok());
    }

    #[test]
    fn absolute_external_uri_uses_normalized_resource_identity() {
        // Caller maps are keyed by the resolved RFC 3986 identity, not by an
        // unnormalized spelling embedded in an untrusted Signature document.
        let xml = r#"<root xml:base="https://base.example/ignored/">
            <reference URI="https://example.test/a/../data.bin"/>
        </root>"#;
        let doc = Document::parse(xml).unwrap();
        let reference = doc
            .descendants()
            .find(|node| node.has_tag_name("reference"))
            .unwrap();
        let resources = HashMap::from([(
            "https://example.test/data.bin".to_owned(),
            b"payload".to_vec(),
        )]);
        let budget = NodeSetMaterializationBudget::default();
        let xml_base_budget = XmlBaseResolutionBudget::default();
        let resolver = UriReferenceResolver::new(&doc).with_external_resources(&resources);

        let data = resolver
            .dereference_from_with_budget(
                reference.attribute("URI").unwrap(),
                reference,
                &budget,
                &xml_base_budget,
            )
            .unwrap();

        assert_eq!(data.into_binary().unwrap(), b"payload");
    }

    #[test]
    fn absolute_external_uri_does_not_consume_xml_base_components() {
        // A scheme-bearing reference supplies its own base and must remain
        // resolvable even when inherited XML Base components are disallowed.
        let xml = r#"<root xml:base="ignored/"><reference URI="https://example.test/a/../data.bin"/></root>"#;
        let doc = Document::parse(xml).unwrap();
        let reference = doc
            .descendants()
            .find(|node| node.has_tag_name("reference"))
            .unwrap();
        let resources = HashMap::from([(
            "https://example.test/data.bin".to_owned(),
            b"payload".to_vec(),
        )]);
        let resolver = UriReferenceResolver::new(&doc).with_external_resources(&resources);

        let data = resolver
            .dereference_from_with_budget(
                reference.attribute("URI").unwrap(),
                reference,
                &NodeSetMaterializationBudget::default(),
                &XmlBaseResolutionBudget::with_limits(0, 1_024),
            )
            .expect("absolute references must bypass inherited XML Base traversal");

        assert_eq!(data.into_binary().unwrap(), b"payload");
    }

    #[test]
    fn external_uri_without_xml_base_uses_normalized_resource_identity() {
        // RFC 3986 normalization defines the caller map key even when the
        // document does not provide an explicit XML Base ancestor.
        let xml = r#"<root><reference URI="https://example.test/a/../data.bin"/></root>"#;
        let doc = Document::parse(xml).unwrap();
        let reference = doc
            .descendants()
            .find(|node| node.has_tag_name("reference"))
            .unwrap();
        let resources = HashMap::from([(
            "https://example.test/data.bin".to_owned(),
            b"payload".to_vec(),
        )]);
        let budget = NodeSetMaterializationBudget::default();
        let xml_base_budget = XmlBaseResolutionBudget::default();
        let resolver = UriReferenceResolver::new(&doc).with_external_resources(&resources);

        let data = resolver
            .dereference_from_with_budget(
                reference.attribute("URI").unwrap(),
                reference,
                &budget,
                &xml_base_budget,
            )
            .expect("the normalized resource key must resolve without xml:base");

        assert_eq!(data.into_binary().unwrap(), b"payload");
    }

    #[test]
    fn pathless_relative_xml_base_preserves_relative_resource_identity() {
        // Query-only xml:base values do not turn a relative URI into an
        // absolute-path reference when resolving caller-owned resources.
        let xml = r#"<root xml:base="?old">
            <reference URI="data.bin"/>
        </root>"#;
        let doc = Document::parse(xml).unwrap();
        let reference = doc
            .descendants()
            .find(|node| node.has_tag_name("reference"))
            .unwrap();
        let resources = HashMap::from([("data.bin".to_owned(), b"payload".to_vec())]);
        let budget = NodeSetMaterializationBudget::default();
        let xml_base_budget = XmlBaseResolutionBudget::default();
        let resolver = UriReferenceResolver::new(&doc).with_external_resources(&resources);

        let data = resolver
            .dereference_from_with_budget(
                reference.attribute("URI").unwrap(),
                reference,
                &budget,
                &xml_base_budget,
            )
            .unwrap();

        assert_eq!(data.into_binary().unwrap(), b"payload");
    }

    #[test]
    fn relative_xml_base_normalizes_absolute_external_path() {
        // An absolute-path reference replaces a relative base path, but RFC
        // 3986 dot-segment removal still defines the caller resource identity.
        let xml = r#"<root xml:base="a/b">
            <reference URI="/x/../data.bin"/>
        </root>"#;
        let doc = Document::parse(xml).unwrap();
        let reference = doc
            .descendants()
            .find(|node| node.has_tag_name("reference"))
            .unwrap();
        let resources = HashMap::from([("/data.bin".to_owned(), b"payload".to_vec())]);
        let budget = NodeSetMaterializationBudget::default();
        let xml_base_budget = XmlBaseResolutionBudget::default();
        let resolver = UriReferenceResolver::new(&doc).with_external_resources(&resources);

        let data = resolver
            .dereference_from_with_budget(
                reference.attribute("URI").unwrap(),
                reference,
                &budget,
                &xml_base_budget,
            )
            .unwrap();

        assert_eq!(data.into_binary().unwrap(), b"payload");
    }

    #[test]
    fn network_path_xml_base_preserves_external_resource_authority() {
        // A schemeless authority remains part of the resolved caller-owned
        // resource identity when an absolute-path URI replaces the base path.
        let xml = r#"<root xml:base="//cdn.example/a/b/">
            <reference URI="/x/../data.bin"/>
        </root>"#;
        let doc = Document::parse(xml).unwrap();
        let reference = doc
            .descendants()
            .find(|node| node.has_tag_name("reference"))
            .unwrap();
        let resources = HashMap::from([("//cdn.example/data.bin".to_owned(), b"payload".to_vec())]);
        let budget = NodeSetMaterializationBudget::default();
        let xml_base_budget = XmlBaseResolutionBudget::default();
        let resolver = UriReferenceResolver::new(&doc).with_external_resources(&resources);

        let data = resolver
            .dereference_from_with_budget(
                reference.attribute("URI").unwrap(),
                reference,
                &budget,
                &xml_base_budget,
            )
            .unwrap();

        assert_eq!(data.into_binary().unwrap(), b"payload");
    }

    #[test]
    fn unicode_external_uri_resolves_without_panicking() {
        // Untrusted XML may start a relative URI with a multibyte scalar; the
        // resolver must produce its UTF-8 resource identity without panicking.
        let xml = r#"<root xml:base="https://example.test/base/">
            <reference URI="é?x"/>
        </root>"#;
        let doc = Document::parse(xml).unwrap();
        let reference = doc
            .descendants()
            .find(|node| node.has_tag_name("reference"))
            .unwrap();
        let resources = HashMap::from([(
            "https://example.test/base/é?x".to_owned(),
            b"payload".to_vec(),
        )]);
        let budget = NodeSetMaterializationBudget::default();
        let xml_base_budget = XmlBaseResolutionBudget::default();
        let resolver = UriReferenceResolver::new(&doc).with_external_resources(&resources);

        let data = resolver
            .dereference_from_with_budget(
                reference.attribute("URI").unwrap(),
                reference,
                &budget,
                &xml_base_budget,
            )
            .unwrap();

        assert_eq!(data.into_binary().unwrap(), b"payload");
    }

    #[test]
    fn absolute_rootless_external_uri_discards_leading_parent_segment() {
        let xml = r#"<root xml:base="https://example.test/base/">
            <reference URI="urn:../payload"/>
        </root>"#;
        let doc = Document::parse(xml).unwrap();
        let reference = doc
            .descendants()
            .find(|node| node.has_tag_name("reference"))
            .unwrap();
        let resources = HashMap::from([("urn:payload".to_owned(), b"payload".to_vec())]);
        let budget = NodeSetMaterializationBudget::default();
        let xml_base_budget = XmlBaseResolutionBudget::default();
        let resolver = UriReferenceResolver::new(&doc).with_external_resources(&resources);

        let data = resolver
            .dereference_from_with_budget(
                reference.attribute("URI").unwrap(),
                reference,
                &budget,
                &xml_base_budget,
            )
            .unwrap();

        assert_eq!(data.into_binary().unwrap(), b"payload");
    }

    #[test]
    fn namespaced_id_attr_found_by_local_name() {
        // roxmltree strips prefix: `wsu:Id` → local name "Id", which is in DEFAULT_ID_ATTRS
        let xml =
            r#"<root><elem wsu:Id="ts1" xmlns:wsu="http://example.com/wsu">data</elem></root>"#;
        let doc = Document::parse(xml).unwrap();

        let resolver = UriReferenceResolver::new(&doc);
        assert!(resolver.has_id("ts1"));
    }

    #[test]
    fn id_count_reports_unique_ids() {
        let xml = r#"<root ID="r1"><a ID="a1"/><b Id="b1"/><c id="c1"/></root>"#;
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        // 4 elements with ID-like attributes
        assert_eq!(resolver.id_count(), 4);
    }

    #[test]
    fn duplicate_ids_are_rejected() {
        // Duplicate IDs are removed from the index to prevent signature-wrapping
        // attacks — lookups for ambiguous IDs fail instead of picking arbitrarily.
        let xml = r#"<root><a ID="dup">first</a><b ID="dup">second</b></root>"#;
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        // "dup" appears twice → removed from index
        assert!(!resolver.has_id("dup"));
        let result = resolver.dereference("#dup");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TransformError::ElementNotFound(_)
        ));
    }

    #[test]
    fn triple_duplicate_ids_stay_rejected() {
        // Verify that 3+ occurrences don't re-insert (the HashSet tracks
        // permanently removed IDs so Entry::Vacant after remove doesn't re-add)
        let xml = r#"<root><a ID="dup">1</a><b ID="dup">2</b><c ID="dup">3</c></root>"#;
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        assert!(!resolver.has_id("dup"));
        assert!(resolver.dereference("#dup").is_err());
    }

    #[test]
    fn node_set_exclude_subtree() {
        let xml = r#"<root><keep>yes</keep><remove><deep>no</deep></remove></root>"#;
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        let data = resolver.dereference("").unwrap();
        let mut node_set = data.into_node_set().unwrap();

        // Find and exclude the <remove> subtree
        let remove_elem = doc
            .descendants()
            .find(|n| n.is_element() && n.has_tag_name("remove"))
            .unwrap();
        node_set.exclude_subtree(remove_elem);

        // <keep> should still be in the set
        let keep_elem = doc
            .descendants()
            .find(|n| n.is_element() && n.has_tag_name("keep"))
            .unwrap();
        assert!(node_set.contains(keep_elem));

        // <remove> and its children should be excluded
        assert!(!node_set.contains(remove_elem));
        let deep_elem = doc
            .descendants()
            .find(|n| n.is_element() && n.has_tag_name("deep"))
            .unwrap();
        assert!(!node_set.contains(deep_elem));
    }

    #[test]
    fn bare_name_subtree_excludes_comments() {
        // XMLDSig's bare-name same-document shortcut removes comment nodes.
        let xml = r#"<root><item ID="x"><!-- comment --><child/></item></root>"#;
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        let data = resolver.dereference("#x").unwrap();
        let node_set = data.into_node_set().unwrap();

        for node in doc.descendants() {
            if node.is_comment() {
                assert!(
                    !node_set.contains(node),
                    "comment must be excluded from #id"
                );
            }
        }
    }

    #[test]
    fn xpointer_root_returns_whole_document_with_comments() {
        let xml = "<root><!-- comment --><child/></root>";
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        let data = resolver.dereference("#xpointer(/)").unwrap();
        let node_set = data.into_node_set().unwrap();

        // Unlike empty URI, xpointer(/) includes comments
        for node in doc.descendants() {
            if node.is_comment() {
                assert!(
                    node_set.contains(node),
                    "comment should be included for #xpointer(/)"
                );
            }
        }
        assert!(node_set.contains(doc.root_element()));
    }

    #[test]
    fn xpointer_id_single_quotes() {
        // XPointer ID dereference retains comments, unlike bare-name fragments.
        let xml = r#"<root><item ID="abc"><!-- retained -->content</item></root>"#;
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        let data = resolver.dereference("#xpointer(id('abc'))").unwrap();
        let node_set = data.into_node_set().unwrap();

        let elem = doc
            .descendants()
            .find(|n| n.attribute("ID") == Some("abc"))
            .unwrap();
        assert!(node_set.contains(elem));
        assert!(
            elem.children()
                .any(|node| node.is_comment() && node_set.contains(node))
        );
    }

    #[test]
    fn xpointer_id_double_quotes() {
        let xml = r#"<root><item ID="xyz">content</item></root>"#;
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        let data = resolver.dereference(r#"#xpointer(id("xyz"))"#).unwrap();
        let node_set = data.into_node_set().unwrap();

        let elem = doc
            .descendants()
            .find(|n| n.attribute("ID") == Some("xyz"))
            .unwrap();
        assert!(node_set.contains(elem));
    }

    #[test]
    fn xpointer_id_not_found() {
        let xml = "<root/>";
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        let result = resolver.dereference("#xpointer(id('missing'))");
        assert!(result.is_err());
        match result.unwrap_err() {
            TransformError::ElementNotFound(id) => assert_eq!(id, "missing"),
            other => panic!("expected ElementNotFound, got: {other:?}"),
        }
    }

    #[test]
    fn xpointer_id_empty_value_rejected() {
        // xpointer(id('')) parses to empty string — reject as UnsupportedUri
        let xml = "<root/>";
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        let result = resolver.dereference("#xpointer(id(''))");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TransformError::UnsupportedUri(_)
        ));
    }

    #[test]
    fn bare_fragment_rejects_non_ncname_without_visa3d_compatibility() {
        // XMLDSig bare-name fragments use an XML Name. Numeric identifiers are
        // accepted by libxmlsec1 only through its explicit Visa3D compatibility
        // mode and must not leak into the standards-default resolver.
        let xml = r#"<root><item ID="12345">content</item></root>"#;
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        assert!(matches!(
            resolver.dereference("#12345"),
            Err(TransformError::UnsupportedUri(uri)) if uri == "#12345"
        ));
    }

    #[test]
    fn visa3d_compatibility_resolves_non_ncname_id_directly() {
        // The compatibility mode is deliberately narrow: it changes only the
        // bare-fragment lookup grammar and retains duplicate-safe ID indexing.
        let xml = r#"<root><item ID="12345">content</item></root>"#;
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc)
            .with_same_document_id_semantics(SameDocumentIdSemantics::XmlSecVisa3d);

        assert!(resolver.dereference("#12345").is_ok());
    }

    #[test]
    fn xmlsec_barename_compatibility_matches_donor_literal_and_comment_semantics() {
        // The donor internally wraps a barename in XPointer to accept numeric
        // IDs, but still selects TreeWithoutComments; an apostrophe cannot be
        // represented in the wrapper's single-quoted expression.
        let xml = r#"<root><item ID="12345"><!-- excluded -->numeric</item><item ID="visa'3d">quoted</item></root>"#;
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc)
            .with_same_document_id_semantics(SameDocumentIdSemantics::XmlSecBarename);

        let nodes = resolver
            .dereference("#12345")
            .unwrap()
            .into_node_set()
            .unwrap();
        assert!(
            doc.descendants()
                .filter(|node| node.is_comment())
                .all(|node| !nodes.contains(node))
        );
        assert!(matches!(
            resolver.dereference("#visa'3d"),
            Err(TransformError::UnsupportedUri(uri)) if uri == "#visa'3d"
        ));
    }

    #[test]
    fn explicit_xpointer_decoding_is_independent_of_barename_mode() {
        // Compatibility modes change bare IDs, not explicit XPointer escaping.
        let document = Document::parse("<root><item ID='café'/></root>").unwrap();
        for semantics in [
            SameDocumentIdSemantics::Specification,
            SameDocumentIdSemantics::XmlSecBarename,
            SameDocumentIdSemantics::XmlSecVisa3d,
        ] {
            let resolver =
                UriReferenceResolver::new(&document).with_same_document_id_semantics(semantics);
            for uri in [
                "#xpointer(id('caf%C3%A9'))",
                "#%78pointer%28id('caf%C3%A9')%29",
            ] {
                assert!(resolver.dereference(uri).is_ok(), "{semantics:?}: {uri}");
            }
        }
    }

    #[test]
    fn parse_xpointer_id_variants() {
        // Valid forms
        assert_eq!(
            super::parse_xpointer_id_fragment("xpointer(id('foo'))"),
            Some("foo")
        );
        assert_eq!(
            super::parse_xpointer_id_fragment(r#"xpointer(id("bar"))"#),
            Some("bar")
        );

        // Invalid forms
        assert_eq!(super::parse_xpointer_id_fragment("xpointer(/)"), None);
        assert_eq!(super::parse_xpointer_id_fragment("xpointer(id(foo))"), None); // no quotes
        assert_eq!(super::parse_xpointer_id_fragment("not-xpointer"), None);
        assert_eq!(super::parse_xpointer_id_fragment(""), None);

        // Malformed: single quote char — must not panic (was slicing bug)
        assert_eq!(super::parse_xpointer_id_fragment("xpointer(id('))"), None);
        assert_eq!(
            super::parse_xpointer_id_fragment(r#"xpointer(id("))"#),
            None
        );
    }

    #[test]
    fn same_document_reference_nodes_reject_non_id_fragments() {
        let document = Document::parse(r#"<root><item ID="target"/></root>"#).unwrap();
        let resolver = UriReferenceResolver::new(&document);
        for uri in [
            "#target",
            "#xpointer(id('target'))",
            r#"#xpointer(id("target"))"#,
        ] {
            assert!(
                resolver
                    .node_id_for_same_document_reference(uri)
                    .unwrap()
                    .is_some()
            );
        }
        for uri in [
            "",
            "target",
            "#",
            "#xpointer(/)",
            "#xpointer(id(''))",
            "#xpointer(id(target))",
        ] {
            assert!(
                resolver.node_id_for_same_document_reference(uri).is_err(),
                "{uri}"
            );
        }
    }

    #[test]
    fn same_element_multiple_id_attrs_not_duplicate() {
        // An element with both ID="x" and Id="x" should NOT be treated as
        // duplicate — it's the same element exposing the same value via
        // different scanned attribute names.
        let xml = r#"<root><item ID="x" Id="x">data</item></root>"#;
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        assert!(resolver.has_id("x"));
        assert!(resolver.dereference("#x").is_ok());
    }

    #[test]
    fn saml_style_document() {
        // Realistic SAML-like structure
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                                     ID="_resp1">
            <saml:Assertion ID="_assert1">
                <saml:Subject>user@example.com</saml:Subject>
            </saml:Assertion>
            <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="sig1">
                <ds:SignedInfo/>
            </ds:Signature>
        </samlp:Response>"#;

        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        // Should find all three IDs
        assert!(resolver.has_id("_resp1"));
        assert!(resolver.has_id("_assert1"));
        assert!(resolver.has_id("sig1"));
        assert_eq!(resolver.id_count(), 3);

        // Dereference the assertion
        let data = resolver.dereference("#_assert1").unwrap();
        let node_set = data.into_node_set().unwrap();

        // Assertion element should be in the set
        let assertion = doc
            .descendants()
            .find(|n| n.attribute("ID") == Some("_assert1"))
            .unwrap();
        assert!(node_set.contains(assertion));

        // Subject (child of assertion) should be in the set
        let subject = assertion
            .children()
            .find(|n| n.is_element() && n.has_tag_name("Subject"))
            .unwrap();
        assert!(node_set.contains(subject));

        // Response (parent) should NOT be in the set
        assert!(!node_set.contains(doc.root_element()));
    }
}
