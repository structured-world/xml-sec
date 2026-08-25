//! Owned XML documents with stable semantic identities.
//!
//! [`XmlDocument`] owns both the serialized XML and its parsed view. Read-only
//! operations reuse that view. Structural mutation replaces the parsed
//! generation atomically, so identities from an older generation cannot be
//! confused with nodes in the new tree.

use std::collections::{HashMap, HashSet, hash_map::Entry};
use std::sync::atomic::{AtomicU64, Ordering};

use roxmltree::{Document, Node, NodeId, ParsingOptions};
use self_cell::self_cell;

use crate::IdAttributeRegistration;

static NEXT_DOCUMENT_ID: AtomicU64 = AtomicU64::new(1);
const VALIDATION_WRAPPER_NS: &str = "urn:xml-sec:owned-document-validation";
const VALIDATION_WRAPPER_OPEN: &str = "<xmlsec_owned_document:wrapper xmlns:xmlsec_owned_document=\"urn:xml-sec:owned-document-validation\">";
const VALIDATION_WRAPPER_CLOSE: &str = "</xmlsec_owned_document:wrapper>";

/// Process-local provenance of one owned XML document.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DocumentIdentity(u64);

/// Identity of one tree node in one immutable document generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NodeIdentity {
    document: DocumentIdentity,
    generation: u64,
    backend: NodeId,
}

/// Identity of one XPath attribute node and its owning element.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AttributeIdentity {
    owner: NodeIdentity,
    namespace: Option<String>,
    local_name: String,
}

/// Identity of one XPath namespace node and its owning element.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NamespaceIdentity {
    owner: NodeIdentity,
    prefix: String,
    uri: String,
}

/// Deterministic total order for tree, namespace, and attribute identities.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SemanticOrder {
    node: usize,
    phase: u8,
    position: usize,
}

impl AttributeIdentity {
    /// Return the element that owns this XPath attribute node.
    #[must_use]
    pub const fn owner(&self) -> NodeIdentity {
        self.owner
    }

    /// Return the attribute namespace URI.
    #[must_use]
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    /// Return the attribute local name.
    #[must_use]
    pub fn local_name(&self) -> &str {
        &self.local_name
    }
}

impl NamespaceIdentity {
    /// Return the element that owns this XPath namespace node.
    #[must_use]
    pub const fn owner(&self) -> NodeIdentity {
        self.owner
    }

    /// Return the namespace prefix, or an empty string for the default namespace.
    #[must_use]
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Return the namespace URI.
    #[must_use]
    pub fn uri(&self) -> &str {
        &self.uri
    }
}

#[derive(Clone, Copy)]
pub(crate) struct DocumentParseSettings {
    pub(crate) allow_dtd: bool,
    pub(crate) nodes_limit: u32,
    pub(crate) max_bytes: usize,
}

impl Default for DocumentParseSettings {
    fn default() -> Self {
        Self {
            allow_dtd: false,
            nodes_limit: crate::hard_limits::XML_DOCUMENT_NODE_CEILING,
            max_bytes: crate::hard_limits::XML_DOCUMENT_BYTE_CEILING,
        }
    }
}

impl DocumentParseSettings {
    pub(crate) const fn new(allow_dtd: bool, nodes_limit: u32, max_bytes: usize) -> Self {
        Self {
            allow_dtd,
            nodes_limit,
            max_bytes,
        }
    }
}

#[derive(Debug)]
struct DocumentIndexes {
    order: HashMap<NodeId, usize>,
    default_ids: HashMap<String, Option<NodeId>>,
    attributes_by_value: HashMap<(String, String), Vec<NodeId>>,
}

#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
mod policy_sealed {
    pub trait Sealed {}
}

/// Operation policy snapshots that can configure owned-document parsing.
///
/// This sealed trait keeps XML parser policy derived from the same immutable
/// signing, verification, encryption, or decryption snapshot used by the
/// subsequent operation. Applications cannot create a second parser-only
/// configuration path that drifts from operation enforcement.
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub trait XmlDocumentPolicy: policy_sealed::Sealed {
    #[doc(hidden)]
    fn xml_input_policy(&self) -> &crate::policy::XmlInputPolicy;

    #[doc(hidden)]
    fn resource_policy(&self) -> &crate::policy::ResourcePolicy;
}

#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
macro_rules! impl_document_policy {
    ($policy:ty) => {
        impl policy_sealed::Sealed for $policy {}

        impl XmlDocumentPolicy for $policy {
            fn xml_input_policy(&self) -> &crate::policy::XmlInputPolicy {
                &self.xml
            }

            fn resource_policy(&self) -> &crate::policy::ResourcePolicy {
                &self.resources
            }
        }
    };
}

#[cfg(feature = "xmldsig")]
impl_document_policy!(crate::policy::SigningPolicy);
#[cfg(feature = "xmldsig")]
impl_document_policy!(crate::policy::VerificationPolicy);
#[cfg(feature = "xmlenc")]
impl_document_policy!(crate::policy::EncryptionPolicy);
#[cfg(feature = "xmlenc")]
impl_document_policy!(crate::policy::DecryptionPolicy);

struct ParsedDocument<'input> {
    document: Document<'input>,
    indexes: DocumentIndexes,
}

self_cell!(
    struct DocumentCell {
        owner: String,

        #[covariant]
        dependent: ParsedDocument,
    }
);

/// Errors from owned document parsing, identity validation, and mutation.
#[derive(Debug, thiserror::Error)]
pub enum XmlDocumentError {
    /// The immutable operation policy contains invalid resource limits.
    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    #[error("XML document policy violation: {0}")]
    Policy(#[from] crate::policy::PolicyViolation),

    /// The input exceeds the active XML document byte limit.
    #[error("XML document exceeds the maximum size of {maximum} bytes: {actual} bytes")]
    DocumentTooLarge {
        /// Maximum accepted byte length.
        maximum: usize,
        /// Actual byte length.
        actual: usize,
    },
    /// The XML parser rejected the document.
    #[error("XML parsing error: {0}")]
    Parse(#[from] roxmltree::Error),
    /// An identity belongs to another document.
    #[error("XML identity belongs to a different document")]
    ForeignIdentity,
    /// An identity belongs to an earlier document generation.
    #[error("XML identity belongs to stale generation {identity}; current generation is {current}")]
    StaleIdentity {
        /// Generation captured by the identity.
        identity: u64,
        /// Current document generation.
        current: u64,
    },
    /// The node no longer exists in the current parsed tree.
    #[error("XML identity does not resolve to a node")]
    MissingNode,
    /// A mutation target is not an element.
    #[error("XML mutation target must be an element")]
    TargetNotElement,
    /// Replacement content does not satisfy the requested structural shape.
    #[error("invalid XML replacement: {0}")]
    InvalidReplacement(String),
    /// Process-local document provenance space is exhausted.
    #[error("XML document identity space is exhausted")]
    IdentityExhausted,
    /// A projected mutation exceeds the caller's active node ceiling.
    #[error("projected XML document exceeds the maximum node count of {maximum}")]
    ProjectedNodeLimit {
        /// Maximum accepted parser node count.
        maximum: usize,
    },
}

/// Reusable owned XML document.
///
/// The parsed view is retained across read-only operations. Every successful
/// mutation increments [`Self::generation`] and invalidates all identities
/// captured from previous views.
pub struct XmlDocument {
    identity: DocumentIdentity,
    generation: u64,
    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    requires_internal_dtd: bool,
    settings: DocumentParseSettings,
    cell: DocumentCell,
}

/// Borrowed semantic view of one immutable [`XmlDocument`] generation.
#[derive(Clone, Copy)]
pub struct DocumentView<'a> {
    identity: DocumentIdentity,
    generation: u64,
    parsed: &'a ParsedDocument<'a>,
}

impl XmlDocument {
    /// Parse and own an XML document using conservative XML input defaults.
    pub fn parse(xml: impl Into<String>) -> Result<Self, XmlDocumentError> {
        Self::parse_with_settings(xml.into(), DocumentParseSettings::default())
    }

    /// Parse and own XML under the same immutable policy used by an operation.
    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    pub fn parse_with_policy(
        xml: impl Into<String>,
        policy: &impl XmlDocumentPolicy,
    ) -> Result<Self, XmlDocumentError> {
        let resources = policy.resource_policy();
        resources.validate()?;
        Self::parse_with_settings(
            xml.into(),
            DocumentParseSettings::new(
                policy.xml_input_policy().allow_internal_dtd,
                resources.effective_xml_nodes(),
                resources.max_xml_document_bytes,
            ),
        )
    }

    pub(crate) fn parse_with_settings(
        xml: String,
        settings: DocumentParseSettings,
    ) -> Result<Self, XmlDocumentError> {
        if xml.len() > settings.max_bytes {
            return Err(XmlDocumentError::DocumentTooLarge {
                maximum: settings.max_bytes,
                actual: xml.len(),
            });
        }
        #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
        let requires_internal_dtd = document_requires_internal_dtd(&xml, settings);
        let cell = build_cell(xml, settings)?;
        let identity = allocate_document_identity(&NEXT_DOCUMENT_ID)?;
        Ok(Self {
            identity,
            generation: 0,
            #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
            requires_internal_dtd,
            settings,
            cell,
        })
    }

    /// Return this document's stable provenance identity.
    #[must_use]
    pub const fn identity(&self) -> DocumentIdentity {
        self.identity
    }

    /// Return the current mutation generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    pub(crate) fn validate_xml_input_policy(
        &self,
        allow_internal_dtd: bool,
    ) -> Result<(), crate::policy::PolicyViolation> {
        if self.requires_internal_dtd && !allow_internal_dtd {
            return Err(crate::policy::PolicyViolation::XmlInput {
                reason: "owned document requires internal DTD support",
            });
        }
        Ok(())
    }

    /// Return the deterministic serialized representation of this generation.
    #[must_use]
    pub fn as_xml(&self) -> &str {
        self.cell.borrow_owner()
    }

    /// Consume the document and return its deterministic serialization.
    #[must_use]
    pub fn into_xml(self) -> String {
        self.cell.into_owner()
    }

    #[cfg(feature = "xmldsig")]
    pub(crate) fn staged_copy(&self) -> Result<Self, XmlDocumentError> {
        Self::parse_with_settings(self.as_xml().to_owned(), self.settings)
    }

    /// Borrow the retained parsed view without reparsing.
    pub fn with_view<R>(&self, operation: impl for<'a> FnOnce(DocumentView<'a>) -> R) -> R {
        self.cell.with_dependent(|_, parsed| {
            operation(DocumentView {
                identity: self.identity,
                generation: self.generation,
                parsed,
            })
        })
    }

    /// Replace one complete element with a well-formed element fragment.
    pub fn replace_element(
        &mut self,
        target: NodeIdentity,
        replacement: &str,
    ) -> Result<(), XmlDocumentError> {
        let range = self.with_view(|view| {
            let node = view.resolve_node(target)?;
            if !node.is_element() {
                return Err(XmlDocumentError::TargetNotElement);
            }
            Ok(node.range())
        })?;
        self.ensure_replacement_fits(&range, replacement.len())?;
        self.validate_single_element_in_parent_context(target, replacement)?;
        self.replace_range(range, replacement)
    }

    #[cfg(feature = "xmlenc")]
    pub(crate) fn replace_element_with_node_limit(
        &mut self,
        target: NodeIdentity,
        replacement: &str,
        maximum: usize,
    ) -> Result<(), XmlDocumentError> {
        let range = self.with_view(|view| {
            let node = view.resolve_node(target)?;
            if !node.is_element() {
                return Err(XmlDocumentError::TargetNotElement);
            }
            Ok(node.range())
        })?;
        self.ensure_replacement_fits(&range, replacement.len())?;
        self.validate_single_element_in_parent_context(target, replacement)?;
        self.replace_range_with_node_limit(range, replacement, maximum)
    }

    /// Replace one complete node with an XML fragment valid in its parent context.
    ///
    /// This operation is intended for XMLEnc Content replacement, where one
    /// `EncryptedData` element can expand into multiple sibling nodes.
    pub fn replace_node_with_fragment(
        &mut self,
        target: NodeIdentity,
        replacement: &str,
    ) -> Result<(), XmlDocumentError> {
        let range =
            self.with_view(|view| Ok::<_, XmlDocumentError>(view.resolve_node(target)?.range()))?;
        self.ensure_replacement_fits(&range, replacement.len())?;
        self.validate_fragment_in_parent_context(target, replacement)?;
        self.replace_range(range, replacement)
    }

    #[cfg(feature = "xmlenc")]
    pub(crate) fn replace_node_with_fragment_with_node_limit(
        &mut self,
        target: NodeIdentity,
        replacement: &str,
        maximum: usize,
    ) -> Result<(), XmlDocumentError> {
        let range =
            self.with_view(|view| Ok::<_, XmlDocumentError>(view.resolve_node(target)?.range()))?;
        self.ensure_replacement_fits(&range, replacement.len())?;
        self.validate_fragment_in_parent_context(target, replacement)?;
        self.replace_range_with_node_limit(range, replacement, maximum)
    }

    /// Replace all children of one element with a well-formed XML fragment.
    pub fn replace_content(
        &mut self,
        target: NodeIdentity,
        replacement: &str,
    ) -> Result<(), XmlDocumentError> {
        self.replace_content_inner(target, replacement, None)
    }

    #[cfg(feature = "xmldsig")]
    pub(crate) fn replace_content_with_node_limit(
        &mut self,
        target: NodeIdentity,
        replacement: &str,
        maximum: usize,
    ) -> Result<(), XmlDocumentError> {
        self.replace_content_inner(target, replacement, Some(maximum))
    }

    fn replace_content_inner(
        &mut self,
        target: NodeIdentity,
        replacement: &str,
        maximum: Option<usize>,
    ) -> Result<(), XmlDocumentError> {
        let (range, serialized_replacement) = self.with_view(|view| {
            let node = view.resolve_node(target)?;
            if !node.is_element() {
                return Err(XmlDocumentError::TargetNotElement);
            }
            let range = node.range();
            let source = &view.xml()[range.clone()];
            let (content, qualified_name, self_closing) = element_content_range(source)?;
            if self_closing {
                let slash = source.rfind("/>").ok_or_else(|| {
                    XmlDocumentError::InvalidReplacement(
                        "self-closing element has no terminator".into(),
                    )
                })?;
                return Ok((
                    range,
                    format!("{}>{replacement}</{qualified_name}>", &source[..slash]),
                ));
            }
            Ok((
                (range.start + content.start)..(range.start + content.end),
                replacement.to_owned(),
            ))
        })?;
        self.ensure_replacement_fits(&range, serialized_replacement.len())?;
        self.validate_content_in_element_context(target, replacement)?;
        if let Some(maximum) = maximum {
            self.replace_range_with_node_limit(range, &serialized_replacement, maximum)
        } else {
            self.replace_range(range, &serialized_replacement)
        }
    }

    /// Replace the children of several non-overlapping elements atomically.
    ///
    /// All identities must belong to the current generation. The candidate is
    /// parsed once and either every replacement commits in one new generation
    /// or the document remains unchanged.
    pub fn replace_contents(
        &mut self,
        replacements: &[(NodeIdentity, String)],
    ) -> Result<(), XmlDocumentError> {
        self.replace_contents_inner(replacements, None)
    }

    #[cfg(feature = "xmldsig")]
    pub(crate) fn replace_contents_with_node_limit(
        &mut self,
        replacements: &[(NodeIdentity, String)],
        maximum: usize,
    ) -> Result<(), XmlDocumentError> {
        self.replace_contents_inner(replacements, Some(maximum))
    }

    fn replace_contents_inner(
        &mut self,
        replacements: &[(NodeIdentity, String)],
        maximum: Option<usize>,
    ) -> Result<(), XmlDocumentError> {
        if replacements.is_empty() {
            return Ok(());
        }
        let mut targets = HashSet::with_capacity(replacements.len());
        if replacements
            .iter()
            .any(|(target, _)| !targets.insert(*target))
        {
            return Err(XmlDocumentError::InvalidReplacement(
                "replacement targets must be unique".into(),
            ));
        }
        if let Some(actual) = replacements
            .iter()
            .map(|(_, replacement)| replacement.len())
            .filter(|length| *length > self.settings.max_bytes)
            .max()
        {
            return Err(XmlDocumentError::DocumentTooLarge {
                maximum: self.settings.max_bytes,
                actual,
            });
        }
        for (target, replacement) in replacements {
            self.validate_content_in_element_context(*target, replacement)?;
        }
        let mut edits = self.with_view(|view| {
            replacements
                .iter()
                .map(|(target, replacement)| {
                    let node = view.resolve_node(*target)?;
                    if !node.is_element() {
                        return Err(XmlDocumentError::TargetNotElement);
                    }
                    let range = node.range();
                    let source = &view.xml()[range.clone()];
                    let (content, qualified_name, self_closing) = element_content_range(source)?;
                    if self_closing {
                        let slash = source.rfind("/>").ok_or_else(|| {
                            XmlDocumentError::InvalidReplacement(
                                "self-closing element has no terminator".into(),
                            )
                        })?;
                        Ok((
                            range,
                            format!("{}>{replacement}</{qualified_name}>", &source[..slash]),
                        ))
                    } else {
                        Ok((
                            (range.start + content.start)..(range.start + content.end),
                            replacement.clone(),
                        ))
                    }
                })
                .collect::<Result<Vec<_>, XmlDocumentError>>()
        })?;
        edits.sort_by_key(|(range, _)| range.start);
        if edits.windows(2).any(|pair| pair[0].0.end > pair[1].0.start) {
            return Err(XmlDocumentError::InvalidReplacement(
                "replacement targets overlap".into(),
            ));
        }
        let projected =
            edits
                .iter()
                .try_fold(self.as_xml().len(), |length, (range, replacement)| {
                    length
                        .checked_sub(range.len())
                        .and_then(|length| length.checked_add(replacement.len()))
                        .ok_or(XmlDocumentError::DocumentTooLarge {
                            maximum: self.settings.max_bytes,
                            actual: usize::MAX,
                        })
                })?;
        if projected > self.settings.max_bytes {
            return Err(XmlDocumentError::DocumentTooLarge {
                maximum: self.settings.max_bytes,
                actual: projected,
            });
        }
        let mut output = self.as_xml().to_owned();
        for (range, replacement) in edits.into_iter().rev() {
            output.replace_range(range, &replacement);
        }
        if let Some(maximum) = maximum {
            self.replace_serialized_with_node_limit(output, maximum)
        } else {
            self.replace_serialized(output)
        }
    }

    /// Append a well-formed XML fragment as the last child of an element.
    pub fn append_child(
        &mut self,
        target: NodeIdentity,
        child: &str,
    ) -> Result<(), XmlDocumentError> {
        self.append_child_inner(target, child, None)
    }

    #[cfg(feature = "xmldsig")]
    pub(crate) fn append_child_with_node_limit(
        &mut self,
        target: NodeIdentity,
        child: &str,
        maximum: usize,
    ) -> Result<(), XmlDocumentError> {
        self.append_child_inner(target, child, Some(maximum))
    }

    fn append_child_inner(
        &mut self,
        target: NodeIdentity,
        child: &str,
        maximum: Option<usize>,
    ) -> Result<(), XmlDocumentError> {
        let (range, replacement) = self.with_view(|view| {
            let node = view.resolve_node(target)?;
            if !node.is_element() {
                return Err(XmlDocumentError::TargetNotElement);
            }
            let range = node.range();
            let source = &view.xml()[range.clone()];
            let (content, qualified_name, self_closing) = element_content_range(source)?;
            if self_closing {
                let slash = source.rfind("/>").ok_or_else(|| {
                    XmlDocumentError::InvalidReplacement(
                        "self-closing element has no terminator".into(),
                    )
                })?;
                return Ok((
                    range,
                    format!("{}>{child}</{qualified_name}>", &source[..slash]),
                ));
            }
            Ok((
                (range.start + content.end)..(range.start + content.end),
                child.to_owned(),
            ))
        })?;
        self.ensure_replacement_fits(&range, replacement.len())?;
        self.validate_content_in_element_context(target, child)?;
        if let Some(maximum) = maximum {
            self.replace_range_with_node_limit(range, &replacement, maximum)
        } else {
            self.replace_range(range, &replacement)
        }
    }

    pub(crate) fn replace_serialized(&mut self, xml: String) -> Result<(), XmlDocumentError> {
        let next = build_cell(xml, self.settings)?;
        self.commit_cell(next)
    }

    pub(crate) fn replace_serialized_with_node_limit(
        &mut self,
        xml: String,
        maximum: usize,
    ) -> Result<(), XmlDocumentError> {
        let effective_maximum = maximum.min(self.settings.nodes_limit as usize);
        let nodes_limit = u32::try_from(effective_maximum).unwrap_or(u32::MAX);
        let next = build_cell(
            xml,
            DocumentParseSettings {
                nodes_limit,
                ..self.settings
            },
        )
        .map_err(|error| match error {
            XmlDocumentError::Parse(roxmltree::Error::NodesLimitReached) => {
                XmlDocumentError::ProjectedNodeLimit {
                    maximum: effective_maximum,
                }
            }
            error => error,
        })?;
        self.commit_cell(next)
    }

    fn commit_cell(&mut self, next: DocumentCell) -> Result<(), XmlDocumentError> {
        self.cell = next;
        self.generation = self.generation.checked_add(1).ok_or_else(|| {
            XmlDocumentError::InvalidReplacement("document generation overflow".into())
        })?;
        Ok(())
    }

    #[cfg(feature = "xmldsig")]
    pub(crate) fn projected_content_replacement_len(
        &self,
        target: NodeIdentity,
        replacement_len: usize,
    ) -> Result<usize, XmlDocumentError> {
        self.with_view(|view| {
            let node = view.resolve_node(target)?;
            if !node.is_element() {
                return Err(XmlDocumentError::TargetNotElement);
            }
            let range = node.range();
            let source = &view.xml()[range.clone()];
            let (content, qualified_name, self_closing) = element_content_range(source)?;
            let removed = if self_closing {
                range.len()
            } else {
                content.len()
            };
            let added = if self_closing {
                let slash = source.rfind("/>").ok_or_else(|| {
                    XmlDocumentError::InvalidReplacement(
                        "self-closing element has no terminator".into(),
                    )
                })?;
                slash
                    .checked_add(1)
                    .and_then(|length| length.checked_add(replacement_len))
                    .and_then(|length| length.checked_add(2))
                    .and_then(|length| length.checked_add(qualified_name.len()))
                    .and_then(|length| length.checked_add(1))
                    .ok_or_else(|| {
                        XmlDocumentError::InvalidReplacement(
                            "content replacement length overflow".into(),
                        )
                    })?
            } else {
                replacement_len
            };
            view.xml()
                .len()
                .checked_sub(removed)
                .and_then(|length| length.checked_add(added))
                .ok_or_else(|| {
                    XmlDocumentError::InvalidReplacement(
                        "content replacement length overflow".into(),
                    )
                })
        })
    }

    fn replace_range(
        &mut self,
        range: std::ops::Range<usize>,
        replacement: &str,
    ) -> Result<(), XmlDocumentError> {
        let output = self.replaced_range(range, replacement)?;
        self.replace_serialized(output)
    }

    fn replace_range_with_node_limit(
        &mut self,
        range: std::ops::Range<usize>,
        replacement: &str,
        maximum: usize,
    ) -> Result<(), XmlDocumentError> {
        let output = self.replaced_range(range, replacement)?;
        self.replace_serialized_with_node_limit(output, maximum)
    }

    fn replaced_range(
        &self,
        range: std::ops::Range<usize>,
        replacement: &str,
    ) -> Result<String, XmlDocumentError> {
        let projected = self.ensure_replacement_fits(&range, replacement.len())?;
        let mut output = String::with_capacity(projected);
        output.push_str(&self.as_xml()[..range.start]);
        output.push_str(replacement);
        output.push_str(&self.as_xml()[range.end..]);
        Ok(output)
    }

    fn ensure_replacement_fits(
        &self,
        range: &std::ops::Range<usize>,
        replacement_len: usize,
    ) -> Result<usize, XmlDocumentError> {
        let projected = self
            .as_xml()
            .len()
            .checked_sub(range.len())
            .and_then(|length| length.checked_add(replacement_len))
            .ok_or(XmlDocumentError::DocumentTooLarge {
                maximum: self.settings.max_bytes,
                actual: usize::MAX,
            })?;
        if projected > self.settings.max_bytes {
            return Err(XmlDocumentError::DocumentTooLarge {
                maximum: self.settings.max_bytes,
                actual: projected,
            });
        }
        Ok(projected)
    }

    fn validate_single_element_in_parent_context(
        &self,
        target: NodeIdentity,
        replacement: &str,
    ) -> Result<(), XmlDocumentError> {
        let (parsed, wrapper_range) = self.parse_fragment_in_parent_context(target, replacement)?;
        parsed.with_dependent(|_, parsed| {
            let wrapper = validation_wrapper(parsed, wrapper_range.clone())?;
            if wrapper.children().filter(Node::is_element).count() != 1
                || wrapper.children().any(|node| {
                    !node.is_element()
                        && !node.is_comment()
                        && !node.is_pi()
                        && node.text().is_none_or(|text| !text.trim().is_empty())
                })
            {
                return Err(XmlDocumentError::InvalidReplacement(
                    "element replacement must contain exactly one element".into(),
                ));
            }
            Ok(())
        })
    }

    fn validate_fragment_in_parent_context(
        &self,
        target: NodeIdentity,
        replacement: &str,
    ) -> Result<(), XmlDocumentError> {
        self.parse_fragment_in_parent_context(target, replacement)
            .map(|_| ())
    }

    fn parse_fragment_in_parent_context(
        &self,
        target: NodeIdentity,
        replacement: &str,
    ) -> Result<(DocumentCell, std::ops::Range<usize>), XmlDocumentError> {
        let range =
            self.with_view(|view| Ok::<_, XmlDocumentError>(view.resolve_node(target)?.range()))?;
        self.parse_wrapped_range(range, replacement)
    }

    fn validate_content_in_element_context(
        &self,
        target: NodeIdentity,
        replacement: &str,
    ) -> Result<(), XmlDocumentError> {
        let (element_range, content_range, qualified_name, self_closing) =
            self.with_view(|view| {
                let target = view.resolve_node(target)?;
                if !target.is_element() {
                    return Err(XmlDocumentError::TargetNotElement);
                }
                let element_range = target.range();
                let source = &view.xml()[element_range.clone()];
                let (content, qualified_name, self_closing) = element_content_range(source)?;
                Ok::<_, XmlDocumentError>((
                    element_range.clone(),
                    (element_range.start + content.start)..(element_range.start + content.end),
                    qualified_name,
                    self_closing,
                ))
            })?;
        if !self_closing {
            return self
                .parse_wrapped_range(content_range, replacement)
                .map(|_| ());
        }

        let source = &self.as_xml()[element_range.clone()];
        let slash = source.rfind("/>").ok_or_else(|| {
            XmlDocumentError::InvalidReplacement("self-closing element has no terminator".into())
        })?;
        let wrapped = wrapped_fragment(replacement);
        let wrapper_start = element_range.start + slash + 1;
        let expanded = format!("{}>{wrapped}</{qualified_name}>", &source[..slash]);
        self.parse_wrapped_edit(
            element_range,
            &expanded,
            wrapper_start..(wrapper_start + wrapped.len()),
        )
        .map(|_| ())
    }

    fn parse_wrapped_range(
        &self,
        range: std::ops::Range<usize>,
        replacement: &str,
    ) -> Result<(DocumentCell, std::ops::Range<usize>), XmlDocumentError> {
        let wrapped = wrapped_fragment(replacement);
        let wrapper_range = range.start..(range.start + wrapped.len());
        self.parse_wrapped_edit(range, &wrapped, wrapper_range)
    }

    fn parse_wrapped_edit(
        &self,
        range: std::ops::Range<usize>,
        replacement: &str,
        wrapper_range: std::ops::Range<usize>,
    ) -> Result<(DocumentCell, std::ops::Range<usize>), XmlDocumentError> {
        let projected = self
            .as_xml()
            .len()
            .checked_sub(range.len())
            .and_then(|length| length.checked_add(replacement.len()))
            .ok_or_else(|| {
                XmlDocumentError::InvalidReplacement("validation length overflow".into())
            })?;
        let mut candidate = String::with_capacity(projected);
        candidate.push_str(&self.as_xml()[..range.start]);
        candidate.push_str(replacement);
        candidate.push_str(&self.as_xml()[range.end..]);
        let parsed = build_cell(
            candidate,
            DocumentParseSettings {
                nodes_limit: self.settings.nodes_limit.saturating_add(1),
                // Wrapper markup is validation scaffolding, not document input.
                // The committed candidate is checked against the real ceiling.
                max_bytes: projected,
                ..self.settings
            },
        )?;
        parsed.with_dependent(|_, document| {
            validation_wrapper(document, wrapper_range.clone()).map(|_| ())
        })?;
        Ok((parsed, wrapper_range))
    }
}

impl<'a> DocumentView<'a> {
    /// Return the owning document identity.
    #[must_use]
    pub const fn identity(self) -> DocumentIdentity {
        self.identity
    }

    /// Return the immutable generation represented by this view.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Return the serialized XML backing this parsed view.
    #[must_use]
    pub fn xml(self) -> &'a str {
        self.parsed.document.input_text()
    }

    /// Return the document root identity.
    #[must_use]
    pub fn root(self) -> NodeIdentity {
        self.node_identity(self.parsed.document.root())
    }

    /// Return the root element identity.
    #[must_use]
    pub fn root_element(self) -> NodeIdentity {
        self.node_identity(self.parsed.document.root_element())
    }

    /// Return the number of parser nodes in this generation.
    #[must_use]
    pub fn node_count(self) -> usize {
        self.parsed.document.descendants().count()
    }

    /// Resolve an ID using standard spellings plus caller registrations.
    #[must_use]
    pub fn node_for_id(
        self,
        value: &str,
        registrations: &[IdAttributeRegistration],
    ) -> Option<NodeIdentity> {
        let mut matches = HashSet::new();
        match self.parsed.indexes.default_ids.get(value) {
            Some(Some(node)) => {
                matches.insert(*node);
            }
            Some(None) => return None,
            None => {}
        }
        for registration in registrations {
            let key = (
                registration.attribute_local_name().to_owned(),
                value.to_owned(),
            );
            if let Some(nodes) = self.parsed.indexes.attributes_by_value.get(&key) {
                matches.extend(nodes.iter().copied().filter(|node_id| {
                    self.parsed
                        .document
                        .get_node(*node_id)
                        .is_some_and(|node| registration.matches_node(node))
                }));
            }
        }
        if matches.len() == 1 {
            matches
                .iter()
                .next()
                .map(|node| self.node_identity_by_id(*node))
        } else {
            None
        }
    }

    #[cfg(feature = "xmldsig")]
    pub(crate) fn id_index(
        self,
        registrations: &[IdAttributeRegistration],
    ) -> HashMap<String, NodeId> {
        let mut candidates: HashMap<String, HashSet<NodeId>> = HashMap::new();
        let mut ambiguous = HashSet::new();
        for (value, node) in &self.parsed.indexes.default_ids {
            if let Some(node) = node {
                candidates.entry(value.clone()).or_default().insert(*node);
            } else {
                ambiguous.insert(value.clone());
            }
        }
        for ((attribute_name, value), nodes) in &self.parsed.indexes.attributes_by_value {
            for registration in registrations
                .iter()
                .filter(|registration| registration.attribute_local_name() == attribute_name)
            {
                candidates
                    .entry(value.clone())
                    .or_default()
                    .extend(nodes.iter().copied().filter(|node_id| {
                        self.parsed
                            .document
                            .get_node(*node_id)
                            .is_some_and(|node| registration.matches_node(node))
                    }));
            }
        }
        candidates
            .into_iter()
            .filter_map(|(value, nodes)| {
                if nodes.len() == 1 && !ambiguous.contains(&value) {
                    nodes.into_iter().next().map(|node| (value, node))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return deterministic document order for a current tree-node identity.
    pub fn document_order(self, identity: NodeIdentity) -> Result<usize, XmlDocumentError> {
        self.validate_identity(identity)?;
        self.parsed
            .indexes
            .order
            .get(&identity.backend)
            .copied()
            .ok_or(XmlDocumentError::MissingNode)
    }

    /// Return a total order key for a current tree node.
    pub fn node_order(self, identity: NodeIdentity) -> Result<SemanticOrder, XmlDocumentError> {
        Ok(SemanticOrder {
            node: self.document_order(identity)?,
            phase: 0,
            position: 0,
        })
    }

    /// Return a total order key for a current attribute node.
    pub fn attribute_order(
        self,
        identity: &AttributeIdentity,
    ) -> Result<SemanticOrder, XmlDocumentError> {
        let owner = self.resolve_node(identity.owner)?;
        let position = owner
            .attributes()
            .position(|attribute| {
                attribute.namespace() == identity.namespace.as_deref()
                    && attribute.name() == identity.local_name
            })
            .ok_or(XmlDocumentError::MissingNode)?;
        Ok(SemanticOrder {
            node: self.document_order(identity.owner)?,
            phase: 2,
            position,
        })
    }

    /// Return a total order key for a current namespace node.
    pub fn namespace_order(
        self,
        identity: &NamespaceIdentity,
    ) -> Result<SemanticOrder, XmlDocumentError> {
        let owner = self.resolve_node(identity.owner)?;
        let target = (identity.prefix.as_str(), identity.uri.as_str());
        let mut found = false;
        let mut position = 0;
        // This is the same complete in-scope axis consumed by
        // namespace_identities(), not only declarations written on `owner`.
        for namespace in owner.namespaces() {
            let candidate = (namespace.name().unwrap_or_default(), namespace.uri());
            match candidate.cmp(&target) {
                std::cmp::Ordering::Less => position += 1,
                std::cmp::Ordering::Equal => found = true,
                std::cmp::Ordering::Greater => {}
            }
        }
        if !found {
            return Err(XmlDocumentError::MissingNode);
        }
        Ok(SemanticOrder {
            node: self.document_order(identity.owner)?,
            phase: 1,
            position,
        })
    }

    pub(crate) fn document(self) -> &'a Document<'a> {
        &self.parsed.document
    }

    pub(crate) fn node_identity(self, node: Node<'_, '_>) -> NodeIdentity {
        self.node_identity_by_id(node.id())
    }

    pub(crate) fn node_identity_by_id(self, backend: NodeId) -> NodeIdentity {
        NodeIdentity {
            document: self.identity,
            generation: self.generation,
            backend,
        }
    }

    pub(crate) fn resolve_node(
        self,
        identity: NodeIdentity,
    ) -> Result<Node<'a, 'a>, XmlDocumentError> {
        self.validate_identity(identity)?;
        self.parsed
            .document
            .get_node(identity.backend)
            .ok_or(XmlDocumentError::MissingNode)
    }

    /// Identify an attribute by expanded name on a current owner element.
    pub fn attribute_identity(
        self,
        owner: NodeIdentity,
        namespace: Option<&str>,
        local_name: &str,
    ) -> Result<AttributeIdentity, XmlDocumentError> {
        let node = self.resolve_node(owner)?;
        if !node.is_element()
            || !node.attributes().any(|attribute| {
                attribute.namespace() == namespace && attribute.name() == local_name
            })
        {
            return Err(XmlDocumentError::MissingNode);
        }
        Ok(AttributeIdentity {
            owner,
            namespace: namespace.map(str::to_owned),
            local_name: local_name.to_owned(),
        })
    }

    /// Return the in-scope XPath namespace nodes owned by one current element.
    pub fn namespace_identities(
        self,
        owner: NodeIdentity,
    ) -> Result<Vec<NamespaceIdentity>, XmlDocumentError> {
        let node = self.resolve_node(owner)?;
        if !node.is_element() {
            return Err(XmlDocumentError::MissingNode);
        }
        // roxmltree stores each element's complete in-scope namespace axis as
        // a compact range of shared namespace indices. This includes inherited
        // bindings with prefix shadowing already applied; walking ancestors
        // here would duplicate backend resolution and could diverge from it.
        let mut namespaces = node
            .namespaces()
            .map(|namespace| NamespaceIdentity {
                owner,
                prefix: namespace.name().unwrap_or_default().to_owned(),
                uri: namespace.uri().to_owned(),
            })
            .collect::<Vec<_>>();
        namespaces
            .sort_by(|left, right| (&left.prefix, &left.uri).cmp(&(&right.prefix, &right.uri)));
        Ok(namespaces)
    }

    fn validate_identity(self, identity: NodeIdentity) -> Result<(), XmlDocumentError> {
        if identity.document != self.identity {
            return Err(XmlDocumentError::ForeignIdentity);
        }
        if identity.generation != self.generation {
            return Err(XmlDocumentError::StaleIdentity {
                identity: identity.generation,
                current: self.generation,
            });
        }
        Ok(())
    }
}

fn build_cell(
    xml: String,
    settings: DocumentParseSettings,
) -> Result<DocumentCell, XmlDocumentError> {
    if xml.len() > settings.max_bytes {
        return Err(XmlDocumentError::DocumentTooLarge {
            maximum: settings.max_bytes,
            actual: xml.len(),
        });
    }
    DocumentCell::try_new(xml, |source| {
        let document = Document::parse_with_options(
            source,
            ParsingOptions {
                allow_dtd: settings.allow_dtd,
                nodes_limit: settings.nodes_limit,
                entity_resolver: None,
            },
        )?;
        let indexes = DocumentIndexes::build(&document);
        Ok::<_, roxmltree::Error>(ParsedDocument { document, indexes })
    })
    .map_err(XmlDocumentError::Parse)
}

fn allocate_document_identity(counter: &AtomicU64) -> Result<DocumentIdentity, XmlDocumentError> {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let next = current
            .checked_add(1)
            .ok_or(XmlDocumentError::IdentityExhausted)?;
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return Ok(DocumentIdentity(current)),
            Err(observed) => current = observed,
        }
    }
}

#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
fn document_requires_internal_dtd(xml: &str, settings: DocumentParseSettings) -> bool {
    // Parse provenance records what the source actually requires, not merely
    // whether its creator used a permissive policy. This lets a later strict
    // operation accept ordinary XML while rejecting DTD-dependent documents.
    settings.allow_dtd
        && Document::parse_with_options(
            xml,
            ParsingOptions {
                allow_dtd: false,
                nodes_limit: settings.nodes_limit,
                entity_resolver: None,
            },
        )
        .is_err()
}

fn wrapped_fragment(replacement: &str) -> String {
    format!("{VALIDATION_WRAPPER_OPEN}{replacement}{VALIDATION_WRAPPER_CLOSE}")
}

fn validation_wrapper<'a, 'input>(
    parsed: &'a ParsedDocument<'input>,
    expected_range: std::ops::Range<usize>,
) -> Result<Node<'a, 'input>, XmlDocumentError> {
    parsed
        .document
        .descendants()
        .find(|node| {
            node.has_tag_name((VALIDATION_WRAPPER_NS, "wrapper")) && node.range() == expected_range
        })
        .ok_or_else(|| {
            XmlDocumentError::InvalidReplacement(
                "replacement escaped its structural validation boundary".into(),
            )
        })
}

impl DocumentIndexes {
    fn build(document: &Document<'_>) -> Self {
        let mut order = HashMap::new();
        let mut default_ids = HashMap::new();
        let mut duplicate_ids = HashSet::new();
        let mut attributes_by_value: HashMap<(String, String), Vec<NodeId>> = HashMap::new();

        for (position, node) in document.descendants().enumerate() {
            order.insert(node.id(), position);
            if !node.is_element() {
                continue;
            }
            for attribute in node.attributes() {
                attributes_by_value
                    .entry((attribute.name().to_owned(), attribute.value().to_owned()))
                    .or_default()
                    .push(node.id());
                if !matches!(attribute.name(), "ID" | "Id" | "id")
                    || duplicate_ids.contains(attribute.value())
                {
                    continue;
                }
                match default_ids.entry(attribute.value().to_owned()) {
                    Entry::Vacant(entry) => {
                        entry.insert(Some(node.id()));
                    }
                    Entry::Occupied(mut entry) if entry.get() != &Some(node.id()) => {
                        entry.insert(None);
                        duplicate_ids.insert(attribute.value().to_owned());
                    }
                    Entry::Occupied(_) => {}
                }
            }
        }
        Self {
            order,
            default_ids,
            attributes_by_value,
        }
    }
}

fn element_content_range(
    element: &str,
) -> Result<(std::ops::Range<usize>, String, bool), XmlDocumentError> {
    let start_end = element_opening_end(element)?;
    let start_tag = &element[..=start_end];
    let qualified_name = start_tag[1..]
        .split(|character: char| character.is_ascii_whitespace() || matches!(character, '/' | '>'))
        .next()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| XmlDocumentError::InvalidReplacement("element name is missing".into()))?
        .to_owned();
    if start_tag[..start_tag.len() - 1].trim_end().ends_with('/') {
        return Ok((start_end..start_end, qualified_name, true));
    }
    let close = element
        .rfind("</")
        .ok_or_else(|| XmlDocumentError::InvalidReplacement("element end tag is missing".into()))?;
    Ok(((start_end + 1)..close, qualified_name, false))
}

fn element_opening_end(element: &str) -> Result<usize, XmlDocumentError> {
    let mut quote = None;
    for (index, byte) in element.bytes().enumerate() {
        match byte {
            b'\'' | b'"' => match quote {
                Some(active) if active == byte => quote = None,
                None => quote = Some(byte),
                Some(_) => {}
            },
            b'>' if quote.is_none() => return Ok(index),
            _ => {}
        }
    }
    Err(XmlDocumentError::InvalidReplacement(
        "element start tag is incomplete".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn views_reuse_identity_until_mutation_invalidates_generation() {
        let mut document =
            XmlDocument::parse("<root><child ID=\"target\"/></root>").expect("fixture must parse");
        let target = document.with_view(|view| {
            view.node_for_id("target", &[])
                .expect("ID target must resolve")
        });
        assert_eq!(document.generation(), 0);
        document
            .replace_element(target, "<replacement ID=\"target\"/>")
            .expect("replacement must succeed");

        let error = document
            .with_view(|view| view.resolve_node(target).map(|_| ()))
            .expect_err("old identity must be stale");
        assert!(matches!(error, XmlDocumentError::StaleIdentity { .. }));
        assert_eq!(document.generation(), 1);
    }

    #[test]
    fn identities_cannot_cross_documents() {
        let first = XmlDocument::parse("<root/>").expect("fixture must parse");
        let second = XmlDocument::parse("<root/>").expect("fixture must parse");
        let root = first.with_view(|view| view.root_element());

        let error = second
            .with_view(|view| view.resolve_node(root).map(|_| ()))
            .expect_err("foreign identity must fail closed");
        assert!(matches!(error, XmlDocumentError::ForeignIdentity));
    }

    #[test]
    fn document_identity_allocation_reports_exhaustion_without_wrapping() {
        let counter = AtomicU64::new(u64::MAX - 1);

        assert_eq!(
            allocate_document_identity(&counter).expect("last identity must be allocated"),
            DocumentIdentity(u64::MAX - 1)
        );
        assert!(matches!(
            allocate_document_identity(&counter),
            Err(XmlDocumentError::IdentityExhausted)
        ));
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }

    #[test]
    fn duplicate_and_caller_registered_ids_share_one_index() {
        let document = XmlDocument::parse(
            "<root><a ID=\"duplicate\" custom=\"selected\"/><b Id=\"duplicate\"/></root>",
        )
        .expect("fixture must parse");
        let registrations = [IdAttributeRegistration::global("custom")];

        document.with_view(|view| {
            assert!(view.node_for_id("duplicate", &[]).is_none());
            assert!(view.node_for_id("selected", &registrations).is_some());
        });
    }

    #[test]
    fn duplicate_default_id_stays_ambiguous_with_caller_registration() {
        // A caller registration must not turn an already ambiguous standard ID
        // into a unique match by selecting only one of the duplicate elements.
        let document = XmlDocument::parse(
            "<root><a ID=\"duplicate\" custom=\"duplicate\"/><b Id=\"duplicate\"/></root>",
        )
        .expect("fixture must parse");
        let registrations = [IdAttributeRegistration::global("custom")];

        document.with_view(|view| {
            assert!(view.node_for_id("duplicate", &registrations).is_none());
        });
    }

    #[test]
    fn content_replacement_uses_parent_namespace_context() {
        let mut document = XmlDocument::parse("<p:root xmlns:p=\"urn:test\"><p:old/></p:root>")
            .expect("fixture must parse");
        let root = document.with_view(|view| view.root_element());
        document
            .replace_content(root, "<p:new/>")
            .expect("in-scope prefix must be accepted");
        assert_eq!(
            document.as_xml(),
            "<p:root xmlns:p=\"urn:test\"><p:new/></p:root>"
        );
    }

    #[test]
    fn mutations_ignore_greater_than_inside_quoted_attributes() {
        // The opening-tag boundary is the unquoted '>', not a character in an
        // attribute value; both content replacement and append use that boundary.
        let mut document =
            XmlDocument::parse("<root marker=\">\"><old/></root>").expect("fixture must parse");
        let root = document.with_view(|view| view.root_element());

        document
            .replace_content(root, "<first/>")
            .expect("quoted greater-than must not corrupt content replacement");
        let root = document.with_view(|view| view.root_element());
        document
            .append_child(root, "<second/>")
            .expect("quoted greater-than must not corrupt child append");

        assert_eq!(
            document.as_xml(),
            "<root marker=\">\"><first/><second/></root>"
        );
    }

    #[test]
    fn fragment_validation_reuses_internal_dtd_entities() {
        // Validation must run in the original document context so an entity
        // declared by its internal subset remains available during mutation.
        let mut document = XmlDocument::parse_with_settings(
            "<!DOCTYPE root [<!ENTITY custom \"replacement\">]><root><old/></root>".into(),
            DocumentParseSettings::new(
                true,
                crate::hard_limits::XML_DOCUMENT_NODE_CEILING,
                crate::hard_limits::XML_DOCUMENT_BYTE_CEILING,
            ),
        )
        .expect("DTD fixture must parse when explicitly enabled");
        let root = document.with_view(|view| view.root_element());

        document
            .replace_content(root, "&custom;")
            .expect("declared entity must remain valid in replacement context");
        assert_eq!(
            document.as_xml(),
            "<!DOCTYPE root [<!ENTITY custom \"replacement\">]><root>&custom;</root>"
        );
    }

    #[test]
    fn serialization_is_stable_for_unchanged_views() {
        let document = XmlDocument::parse("<?pi value?><root a=\"1\"><!--c--></root>")
            .expect("fixture must parse");
        let first = document.as_xml().to_owned();
        document.with_view(|view| assert_eq!(view.xml(), first));
        document.with_view(|view| assert_eq!(view.xml(), first));
        assert_eq!(document.as_xml(), first);
    }

    #[test]
    fn rejected_mutation_keeps_source_and_generation_unchanged() {
        // Failed fragment parsing must be transactional: callers can safely
        // retry without observing a partially changed document or stale IDs.
        let mut document = XmlDocument::parse("<root><child/></root>").expect("fixture must parse");
        let root = document.with_view(|view| view.root_element());
        let before = document.as_xml().to_owned();

        assert!(document.replace_content(root, "<unclosed>").is_err());
        assert_eq!(document.as_xml(), before);
        assert_eq!(document.generation(), 0);
    }

    #[test]
    fn oversized_invalid_fragment_fails_at_the_document_byte_boundary() {
        // Resource rejection must happen before wrapper parsing, so malformed
        // attacker input cannot force allocations beyond the document ceiling.
        let mut document = XmlDocument::parse_with_settings(
            "<root><child/></root>".into(),
            DocumentParseSettings::new(false, 64, 64),
        )
        .expect("bounded fixture must parse");
        let root = document.with_view(|view| view.root_element());
        let replacement = "<".repeat(1_024);

        assert!(matches!(
            document.replace_content(root, &replacement),
            Err(XmlDocumentError::DocumentTooLarge {
                maximum: 64,
                actual,
            }) if actual > 64
        ));
        assert_eq!(document.as_xml(), "<root><child/></root>");
        assert_eq!(document.generation(), 0);
    }

    #[test]
    fn duplicate_empty_content_targets_are_rejected_atomically() {
        let mut document =
            XmlDocument::parse("<root><target></target></root>").expect("fixture must parse");
        let target = document.with_view(|view| {
            let target = view
                .document()
                .descendants()
                .find(|node| node.has_tag_name("target"))
                .expect("target must exist");
            view.node_identity(target)
        });

        let error = document
            .replace_contents(&[(target, "first".into()), (target, "second".into())])
            .expect_err("one identity cannot be replaced twice");

        assert!(matches!(error, XmlDocumentError::InvalidReplacement(_)));
        assert_eq!(document.as_xml(), "<root><target></target></root>");
        assert_eq!(document.generation(), 0);
    }

    #[cfg(feature = "xmldsig")]
    #[test]
    fn bounded_content_replacement_rejects_new_text_node_atomically() {
        let mut document =
            XmlDocument::parse("<root><target/></root>").expect("fixture must parse");
        let target = document.with_view(|view| {
            let root = view
                .resolve_node(view.root_element())
                .expect("root must resolve");
            view.node_identity(
                root.children()
                    .find(Node::is_element)
                    .expect("target must exist"),
            )
        });
        let maximum = document.with_view(|view| view.node_count());
        let before = document.as_xml().to_owned();

        assert!(matches!(
            document.replace_content_with_node_limit(target, "value", maximum),
            Err(XmlDocumentError::ProjectedNodeLimit { maximum: rejected })
                if rejected == maximum
        ));
        assert_eq!(document.as_xml(), before);
        assert_eq!(document.generation(), 0);
    }

    #[test]
    fn semantic_order_covers_namespace_attribute_and_tree_nodes() {
        let document =
            XmlDocument::parse("<root xmlns:p=\"urn:test\" p:value=\"1\"><child/></root>")
                .expect("fixture must parse");

        document.with_view(|view| {
            let root = view.root_element();
            let root_node = view.resolve_node(root).expect("root must resolve");
            let child = view.node_identity(
                root_node
                    .children()
                    .find(Node::is_element)
                    .expect("child must exist"),
            );
            let attribute = view
                .attribute_identity(root, Some("urn:test"), "value")
                .expect("attribute must exist");
            let namespace = view
                .namespace_identities(root)
                .expect("namespace axis must exist")
                .into_iter()
                .find(|namespace| namespace.prefix() == "p")
                .expect("p namespace must exist");

            let root_order = view.node_order(root).expect("root order must exist");
            let namespace_order = view
                .namespace_order(&namespace)
                .expect("namespace order must exist");
            let attribute_order = view
                .attribute_order(&attribute)
                .expect("attribute order must exist");
            let child_order = view.node_order(child).expect("child order must exist");
            assert!(root_order < namespace_order);
            assert!(namespace_order < attribute_order);
            assert!(attribute_order < child_order);
        });
    }

    #[test]
    fn inherited_namespace_axes_are_materialized_only_for_the_requested_owner() {
        // A wide namespace scope inherited by many descendants must remain in
        // roxmltree's structural representation instead of being cloned into an
        // O(elements * namespaces) eager document index.
        let declarations = (0..128)
            .map(|index| format!(r#" xmlns:p{index}="urn:namespace:{index}""#))
            .collect::<String>();
        let children = (0..1_024)
            .map(|index| format!("<child index=\"{index}\"/>"))
            .collect::<String>();
        let document = XmlDocument::parse(format!("<root{declarations}>{children}</root>"))
            .expect("wide namespace fixture must parse");

        document.with_view(|view| {
            let last_child = view
                .document()
                .descendants()
                .rfind(|node| node.has_tag_name("child"))
                .expect("last child must exist");
            let owner = view.node_identity(last_child);
            let namespaces = view
                .namespace_identities(owner)
                .expect("inherited namespace axis must materialize on demand");
            assert_eq!(namespaces.len(), 128);
            assert!(namespaces.windows(2).all(|pair| {
                view.namespace_order(&pair[0]).expect("left order")
                    < view.namespace_order(&pair[1]).expect("right order")
            }));
        });
    }

    #[test]
    fn mutation_invalidates_attribute_and_namespace_identities() {
        let mut document =
            XmlDocument::parse("<root xmlns:p=\"urn:test\" p:value=\"1\"><child/></root>")
                .expect("fixture must parse");
        let (root, attribute, namespace) = document.with_view(|view| {
            let root = view.root_element();
            let attribute = view
                .attribute_identity(root, Some("urn:test"), "value")
                .expect("attribute must exist");
            let namespace = view
                .namespace_identities(root)
                .expect("namespace axis must exist")
                .into_iter()
                .find(|namespace| namespace.prefix() == "p")
                .expect("p namespace must exist");
            (root, attribute, namespace)
        });

        document
            .append_child(root, "<p:next/>")
            .expect("mutation must succeed");
        document.with_view(|view| {
            assert!(matches!(
                view.attribute_order(&attribute),
                Err(XmlDocumentError::StaleIdentity { .. })
            ));
            assert!(matches!(
                view.namespace_order(&namespace),
                Err(XmlDocumentError::StaleIdentity { .. })
            ));
        });
    }

    #[test]
    fn content_replacement_cannot_escape_its_target_element() {
        let mut document = XmlDocument::parse("<outer><target><old/></target></outer>")
            .expect("fixture must parse");
        let target = document.with_view(|view| {
            view.node_identity(
                view.document()
                    .descendants()
                    .find(|node| node.has_tag_name("target"))
                    .expect("target must exist"),
            )
        });
        let before = document.as_xml().to_owned();

        assert!(
            document
                .replace_content(target, "</target><attacker/><target>")
                .is_err()
        );
        assert_eq!(document.as_xml(), before);
        assert_eq!(document.generation(), 0);
    }
}
