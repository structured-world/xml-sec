//! Owned XML documents with stable semantic identities.
//!
//! [`XmlDocument`] owns both the serialized XML and its parsed view. Read-only
//! operations reuse that view. Structural mutation replaces the parsed
//! generation atomically, so identities from an older generation cannot be
//! confused with nodes in the new tree.

use std::borrow::Cow;
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
use std::cell::Cell;
use std::collections::{HashMap, HashSet, hash_map::Entry};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::xml::dom::storage::names::{NameStorage, Names};
use crate::xml::dom::storage::{
    Native as NativeXmlStorage, Storage as XmlStorage, Values as XmlValues,
};
use crate::xml::dom::{Document, Node, NodeId, ParseError, ParsingOptions, XmlBackend};
use crate::xml_input as xml_sec_xml_input;
use self_cell::self_cell;

use crate::IdAttributeRegistration;
use crate::xml::dom::{SemanticDocument, SemanticNodeId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DocumentMetrics {
    node_count: usize,
    max_depth: usize,
}

static NEXT_DOCUMENT_ID: AtomicU64 = AtomicU64::new(1);
const VALIDATION_WRAPPER_NS: &str = "urn:xml-sec:owned-document-validation";
const VALIDATION_WRAPPER_OPEN: &str = "<xmlsec_owned_document:wrapper xmlns:xmlsec_owned_document=\"urn:xml-sec:owned-document-validation\">";
const VALIDATION_WRAPPER_CLOSE: &str = "</xmlsec_owned_document:wrapper>";
// Validation adds one wrapper element and can prevent text-node merging at
// both replacement boundaries. The committed candidate uses the real ceiling.
const VALIDATION_WRAPPER_NODE_OVERHEAD: u32 = 3;

#[cfg(all(test, any(feature = "xmldsig", feature = "xmlenc")))]
pub(crate) fn selected_parser_passes() -> usize {
    3
}

/// Process-local provenance of one owned XML document.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DocumentIdentity(u64);

/// Identity of one tree node in one immutable document generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NodeIdentity {
    document: DocumentIdentity,
    generation: u64,
    semantic_id: SemanticNodeId,
}

#[cfg(feature = "xmldsig")]
impl structured_asn1::memory::HashWork for NodeIdentity {
    fn hash_work(&self) -> Result<u64, structured_asn1::memory::MemoryError> {
        let Self {
            document: _,
            generation: _,
            semantic_id: _,
        } = self;
        // Derived Hash/Eq traverse two u64 fields and one u32 field, never
        // padding or source XML. Admit their bytes and one operation per field.
        // Exhaustive destructuring and the counting-Hasher test guard growth.
        Ok((2 * core::mem::size_of::<u64>() + core::mem::size_of::<u32>() + 3) as u64)
    }
}

/// Identity of one `XPath` attribute node and its owning element.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AttributeIdentity {
    owner: NodeIdentity,
    namespace: Option<String>,
    local_name: String,
}

/// Identity of one `XPath` namespace node and its owning element.
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
    /// Return the element that owns this `XPath` attribute node.
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
    /// Return the element that owns this `XPath` namespace node.
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
    pub(crate) backend: XmlBackend,
    pub(crate) allow_dtd: bool,
    pub(crate) nodes_limit: u32,
    pub(crate) depth_limit: usize,
    pub(crate) namespace_bindings_limit: usize,
    pub(crate) max_bytes: usize,
}

impl Default for DocumentParseSettings {
    fn default() -> Self {
        Self {
            backend: XmlBackend::build_default(),
            allow_dtd: false,
            nodes_limit: crate::hard_limits::XML_DOCUMENT_NODE_CEILING,
            depth_limit: crate::hard_limits::XML_DOCUMENT_DEPTH_CEILING,
            namespace_bindings_limit: crate::hard_limits::XML_NAMESPACE_BINDING_CEILING,
            max_bytes: crate::hard_limits::XML_DOCUMENT_BYTE_CEILING,
        }
    }
}

impl DocumentParseSettings {
    pub(crate) const fn with_backend(mut self, backend: XmlBackend) -> Self {
        self.backend = backend;
        self
    }
}

#[cfg(any(feature = "xmldsig", feature = "xmlenc", test))]
impl DocumentParseSettings {
    #[cfg(test)]
    pub(crate) const fn new(allow_dtd: bool, nodes_limit: u32, max_bytes: usize) -> Self {
        Self::new_with_depth(
            allow_dtd,
            nodes_limit,
            crate::hard_limits::XML_DOCUMENT_DEPTH_CEILING,
            max_bytes,
        )
    }

    #[cfg(test)]
    pub(crate) const fn new_with_depth(
        allow_dtd: bool,
        nodes_limit: u32,
        depth_limit: usize,
        max_bytes: usize,
    ) -> Self {
        Self {
            backend: XmlBackend::build_default(),
            allow_dtd,
            nodes_limit,
            depth_limit,
            namespace_bindings_limit: crate::hard_limits::XML_NAMESPACE_BINDING_CEILING,
            max_bytes,
        }
    }

    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    pub(crate) fn from_policy(
        xml: crate::policy::XmlInputPolicy,
        resources: &crate::policy::ResourcePolicy,
    ) -> Self {
        Self {
            allow_dtd: xml.allow_internal_dtd,
            nodes_limit: resources.effective_xml_nodes(),
            depth_limit: resources.max_xml_depth,
            namespace_bindings_limit: resources.max_xml_namespace_bindings,
            max_bytes: resources.max_xml_document_bytes,
            ..Self::default()
        }
    }

    #[cfg(feature = "xmldsig")]
    pub(crate) fn for_transform_output(resources: &crate::policy::ResourcePolicy) -> Self {
        Self {
            allow_dtd: false,
            nodes_limit: resources.effective_xml_nodes(),
            depth_limit: resources.max_xml_depth,
            namespace_bindings_limit: resources.max_xml_namespace_bindings,
            max_bytes: resources.max_xml_document_bytes,
            ..Self::default()
        }
    }
}

/// Monotonic parser-work allowance shared by one XML Security operation.
///
/// Encoded input decoding and every byte handed to the XML parser are charged before work, including
/// structural-validation candidates, staged copies, retries, and committed
/// document generations. Failed work remains charged so nested helpers cannot
/// reset or reuse the allowance.
pub(crate) struct XmlParseWorkBudget {
    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    remaining: Cell<usize>,
    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    maximum: usize,
    /// Only XML Security operations own a budget; DOM and C14N graphs have none.
    #[cfg(not(any(feature = "xmldsig", feature = "xmlenc")))]
    uninhabited: core::convert::Infallible,
}

impl XmlParseWorkBudget {
    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    pub(crate) fn from_resources(resources: &crate::policy::ResourcePolicy) -> Self {
        Self {
            remaining: Cell::new(resources.max_xml_parse_work_bytes),
            maximum: resources.max_xml_parse_work_bytes,
        }
    }

    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    pub(crate) fn charge_policy(&self, bytes: usize) -> Result<(), crate::policy::PolicyViolation> {
        let consumed = self.maximum.saturating_sub(self.remaining.get());
        let Some(remaining) = self.remaining.get().checked_sub(bytes) else {
            self.remaining.set(0);
            return Err(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_PARSE_WORK_BYTES,
                maximum: self.maximum,
                actual: consumed.saturating_add(bytes),
            });
        };
        self.remaining.set(remaining);
        Ok(())
    }

    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    pub(crate) fn charge(&self, bytes: usize) -> Result<(), XmlDocumentError> {
        self.charge_policy(bytes).map_err(Into::into)
    }

    #[cfg(not(any(feature = "xmldsig", feature = "xmlenc")))]
    fn charge(&self, _bytes: usize) -> Result<(), XmlDocumentError> {
        match self.uninhabited {}
    }

    /// Parser work still admissible, for a parser that meters its own passes.
    #[cfg(feature = "xslt")]
    pub(crate) fn remaining(&self) -> usize {
        self.remaining.get()
    }

    #[cfg(all(test, any(feature = "xmldsig", feature = "xmlenc")))]
    fn with_limit(maximum: usize) -> Self {
        Self {
            remaining: Cell::new(maximum),
            maximum,
        }
    }

    #[cfg(all(test, any(feature = "xmldsig", feature = "xmlenc")))]
    pub(crate) fn consumed(&self) -> usize {
        self.maximum.saturating_sub(self.remaining.get())
    }
}

fn charge_parse_work(
    budget: Option<&XmlParseWorkBudget>,
    bytes: usize,
) -> Result<(), XmlDocumentError> {
    if let Some(budget) = budget {
        budget.charge(bytes)?;
    }
    Ok(())
}

fn charge_semantic_parser_work(
    budget: Option<&XmlParseWorkBudget>,
    bytes: usize,
) -> Result<(), XmlDocumentError> {
    // The lexical sidecar and one semantic parser allowance are caller work.
    // Differential mode checks each implementation against that same allowance
    // instead of charging its diagnostic duplicate to the caller twice.
    for _ in 0..2 {
        charge_parse_work(budget, bytes)?;
    }
    Ok(())
}

struct ContentReplacementEdit<'a> {
    range: std::ops::Range<usize>,
    replacement: &'a str,
    self_closing: Option<SelfClosingContentEdit>,
}

struct SelfClosingContentEdit {
    prefix_end: usize,
    qualified_name: String,
}

#[cfg(feature = "xmldsig")]
fn is_unescaped_base64_text(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
}

#[cfg(feature = "xmldsig")]
fn validate_base64_replacements(
    replacements: &[(NodeIdentity, String)],
) -> Result<(), XmlDocumentError> {
    if replacements
        .iter()
        .any(|(_, value)| !is_unescaped_base64_text(value))
    {
        return Err(XmlDocumentError::InvalidReplacement(
            "generated base64 replacement contains XML markup".into(),
        ));
    }
    Ok(())
}

impl ContentReplacementEdit<'_> {
    fn output_len(&self) -> Option<usize> {
        let Some(expansion) = &self.self_closing else {
            return Some(self.replacement.len());
        };
        expansion
            .prefix_end
            .checked_add(1)
            .and_then(|length| length.checked_add(self.replacement.len()))
            .and_then(|length| length.checked_add(2))
            .and_then(|length| length.checked_add(expansion.qualified_name.len()))
            .and_then(|length| length.checked_add(1))
    }

    fn validation_output_len(&self) -> Option<usize> {
        self.output_len()?
            .checked_add(VALIDATION_WRAPPER_OPEN.len())?
            .checked_add(VALIDATION_WRAPPER_CLOSE.len())
    }

    fn write_output(&self, source: &str, output: &mut String) {
        if let Some(expansion) = &self.self_closing {
            output.push_str(&source[self.range.start..self.range.start + expansion.prefix_end]);
            output.push('>');
        }
        output.push_str(self.replacement);
        if let Some(expansion) = &self.self_closing {
            output.push_str("</");
            output.push_str(&expansion.qualified_name);
            output.push('>');
        }
    }

    fn write_validation_output(&self, source: &str, output: &mut String) -> std::ops::Range<usize> {
        if let Some(expansion) = &self.self_closing {
            output.push_str(&source[self.range.start..self.range.start + expansion.prefix_end]);
            output.push('>');
        }
        let wrapper_start = output.len();
        output.push_str(VALIDATION_WRAPPER_OPEN);
        output.push_str(self.replacement);
        output.push_str(VALIDATION_WRAPPER_CLOSE);
        let wrapper_range = wrapper_start..output.len();
        if let Some(expansion) = &self.self_closing {
            output.push_str("</");
            output.push_str(&expansion.qualified_name);
            output.push('>');
        }
        wrapper_range
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
    node_count: usize,
    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    max_depth: usize,
    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    peak_namespace_bindings: usize,
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
    /// External XML bytes could not be decoded under the XML encoding contract.
    #[error("XML encoding error: {0}")]
    Encoding(#[from] xml_sec_xml_input::Error),
    /// The input exceeds the active XML element nesting limit.
    #[error("XML document exceeds the maximum element depth of {maximum}: {actual}")]
    DocumentTooDeep {
        /// Maximum accepted element nesting depth.
        maximum: usize,
        /// First observed element nesting depth beyond the limit.
        actual: usize,
    },
    /// The XML parser rejected the document.
    #[error("XML parsing error: {0}")]
    Parse(#[from] ParseError),
    /// Scoped parser rejection whose diagnostic retains its paid storage.
    #[cfg(feature = "xmldsig")]
    #[error("XML parsing error: {0}")]
    AccountedParse(#[source] crate::xml::dom::AccountedParseError),
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
    /// A semantic node was synthesized from a shared entity-reference token.
    #[error(
        "XML mutation target originates from an entity expansion and has no unique source range"
    )]
    EntityExpandedMutationTarget,
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

#[cfg(feature = "xmldsig")]
impl From<crate::xml::dom::AccountedParseError> for XmlDocumentError {
    fn from(error: crate::xml::dom::AccountedParseError) -> Self {
        use crate::xml::dom::AccountedParseError;
        match error {
            AccountedParseError::Semantic(error) => Self::Parse(error),
            #[cfg(feature = "xml-backend-xmloxide")]
            AccountedParseError::Xmloxide(crate::parser_xmloxide::error::ParseError::Resource(
                error,
            )) => Self::Parse(error),
            AccountedParseError::Lexical(crate::xml_input::lexical::Error::Resource(error)) => {
                Self::Parse(ParseError::SharedExecution(error))
            }
            #[cfg(feature = "xml-backend-roxmltree")]
            AccountedParseError::Roxmltree(crate::parser_roxmltree::Error::SharedExecution(
                error,
            )) => Self::Parse(ParseError::SharedExecution(error)),
            #[cfg(feature = "xml-backend-roxmltree")]
            AccountedParseError::Roxmltree(crate::parser_roxmltree::Error::AllocationFailed) => {
                Self::Parse(ParseError::AllocationFailed)
            }
            #[cfg(feature = "xml-backend-roxmltree")]
            AccountedParseError::Roxmltree(crate::parser_roxmltree::Error::DtdDetected) => {
                Self::Parse(ParseError::DtdDetected)
            }
            #[cfg(feature = "xml-backend-roxmltree")]
            AccountedParseError::Roxmltree(crate::parser_roxmltree::Error::NodesLimitReached) => {
                Self::Parse(ParseError::NodesLimitReached)
            }
            error => Self::AccountedParse(error),
        }
    }
}

#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
impl XmlDocumentError {
    pub(crate) fn into_policy_violation(
        self,
        settings: DocumentParseSettings,
    ) -> Result<crate::policy::PolicyViolation, Self> {
        let violation = match self {
            Self::Policy(error) => error,
            Self::DocumentTooLarge { maximum, actual } => {
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_DOCUMENT,
                    maximum,
                    actual,
                }
            }
            Self::DocumentTooDeep { maximum, actual } => {
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_DEPTH,
                    maximum,
                    actual,
                }
            }
            Self::Parse(ParseError::NodesLimitReached) => {
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_NODES,
                    maximum: settings.nodes_limit as usize,
                    actual: settings.nodes_limit as usize + 1,
                }
            }
            Self::Parse(ParseError::NamespaceBindingLimitReached { maximum, actual }) => {
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_NAMESPACE_BINDINGS,
                    maximum,
                    actual,
                }
            }
            error => return Err(error),
        };
        Ok(violation)
    }
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

#[cfg(feature = "xmlenc")]
pub(crate) struct PreparedDocumentMutation {
    identity: DocumentIdentity,
    generation: u64,
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
    /// Return the parser backend retained for reparsing and mutation.
    #[must_use]
    pub fn xml_backend(&self) -> XmlBackend {
        self.settings.backend
    }

    /// Parse and own an XML document using conservative XML input defaults.
    /// Borrowed input is size-checked before it is copied into owned storage.
    ///
    /// # Errors
    /// Returns parsing or byte/node/depth/namespace ceiling failures.
    pub fn parse(xml: impl AsRef<str> + Into<String>) -> Result<Self, XmlDocumentError> {
        let settings = DocumentParseSettings::default();
        let xml = own_bounded_xml(xml, settings.max_bytes)?;
        Self::parse_with_settings(xml, settings)
    }

    /// Decode, parse, and own XML bytes using conservative input defaults.
    ///
    /// BOMs and XML declarations select the source encoding. Decoding is
    /// strict and bounded before the normalized UTF-8 document is retained.
    ///
    /// # Errors
    /// Returns encoding errors or the parsing/ceiling failures of [`Self::parse`].
    pub fn parse_bytes(bytes: &[u8]) -> Result<Self, XmlDocumentError> {
        let settings = DocumentParseSettings::default();
        Self::parse_with_settings(decode_owned_xml(bytes, settings.max_bytes, None)?, settings)
    }

    /// Decode and parse XML bytes with an explicitly selected semantic backend.
    ///
    /// # Errors
    /// Returns encoding, backend selection/divergence, parsing or input-limit failures.
    pub fn parse_bytes_with_backend(
        bytes: &[u8],
        backend: XmlBackend,
    ) -> Result<Self, XmlDocumentError> {
        let settings = DocumentParseSettings::default().with_backend(backend);
        Self::parse_with_settings(decode_owned_xml(bytes, settings.max_bytes, None)?, settings)
    }

    /// Parse and own XML with an explicitly selected compiled parser backend.
    ///
    /// # Errors
    /// Returns backend selection/divergence, parsing or input-limit failures.
    pub fn parse_with_backend(
        xml: impl AsRef<str> + Into<String>,
        backend: XmlBackend,
    ) -> Result<Self, XmlDocumentError> {
        let settings = DocumentParseSettings::default().with_backend(backend);
        let xml = own_bounded_xml(xml, settings.max_bytes)?;
        Self::parse_with_settings(xml, settings)
    }

    /// Parse and own XML under the same immutable policy used by an operation.
    /// The policy's byte ceiling is checked before borrowed input is copied.
    ///
    /// # Errors
    /// Returns invalid-policy, input-limit, decoding, or parsing errors.
    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    pub fn parse_with_policy(
        xml: impl AsRef<str> + Into<String>,
        policy: &impl XmlDocumentPolicy,
    ) -> Result<Self, XmlDocumentError> {
        let resources = policy.resource_policy();
        resources.validate()?;
        let budget = XmlParseWorkBudget::from_resources(resources);
        let xml = own_bounded_xml(xml, resources.max_xml_document_bytes)?;
        Self::parse_with_settings_and_optional_budget(
            xml,
            DocumentParseSettings::from_policy(*policy.xml_input_policy(), resources),
            Some(&budget),
        )
    }

    /// Decode and parse XML bytes under the operation's immutable policy.
    ///
    /// # Errors
    /// Returns invalid-policy, byte/work-limit, decoding, or parsing errors.
    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    pub fn parse_bytes_with_policy(
        bytes: &[u8],
        policy: &impl XmlDocumentPolicy,
    ) -> Result<Self, XmlDocumentError> {
        let resources = policy.resource_policy();
        resources.validate()?;
        let budget = XmlParseWorkBudget::from_resources(resources);
        let xml = decode_owned_xml(bytes, resources.max_xml_document_bytes, Some(&budget))?;
        Self::parse_with_settings_and_optional_budget(
            xml,
            DocumentParseSettings::from_policy(*policy.xml_input_policy(), resources),
            Some(&budget),
        )
    }

    /// Parse and own XML under an operation policy and explicit parser backend.
    ///
    /// # Errors
    /// Returns invalid-policy, input-limit, backend-selection/divergence, or parsing errors.
    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    pub fn parse_with_policy_and_backend(
        xml: impl AsRef<str> + Into<String>,
        policy: &impl XmlDocumentPolicy,
        backend: XmlBackend,
    ) -> Result<Self, XmlDocumentError> {
        let resources = policy.resource_policy();
        resources.validate()?;
        let budget = XmlParseWorkBudget::from_resources(resources);
        let xml = own_bounded_xml(xml, resources.max_xml_document_bytes)?;
        Self::parse_with_settings_and_optional_budget(
            xml,
            DocumentParseSettings::from_policy(*policy.xml_input_policy(), resources)
                .with_backend(backend),
            Some(&budget),
        )
    }

    /// Decode and parse XML bytes under policy with an explicit semantic backend.
    ///
    /// # Errors
    /// Returns invalid-policy, decoding, input-limit, backend-selection/divergence, or parsing errors.
    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    pub fn parse_bytes_with_policy_and_backend(
        bytes: &[u8],
        policy: &impl XmlDocumentPolicy,
        backend: XmlBackend,
    ) -> Result<Self, XmlDocumentError> {
        let resources = policy.resource_policy();
        resources.validate()?;
        let budget = XmlParseWorkBudget::from_resources(resources);
        let xml = decode_owned_xml(bytes, resources.max_xml_document_bytes, Some(&budget))?;
        Self::parse_with_settings_and_optional_budget(
            xml,
            DocumentParseSettings::from_policy(*policy.xml_input_policy(), resources)
                .with_backend(backend),
            Some(&budget),
        )
    }

    pub(crate) fn parse_with_settings(
        xml: String,
        settings: DocumentParseSettings,
    ) -> Result<Self, XmlDocumentError> {
        Self::parse_with_settings_and_optional_budget(xml, settings, None)
    }

    fn parse_with_settings_and_optional_budget(
        xml: String,
        settings: DocumentParseSettings,
        budget: Option<&XmlParseWorkBudget>,
    ) -> Result<Self, XmlDocumentError> {
        if xml.len() > settings.max_bytes {
            return Err(XmlDocumentError::DocumentTooLarge {
                maximum: settings.max_bytes,
                actual: xml.len(),
            });
        }
        let peak_namespace_bindings = preflight_document_limits(&xml, settings, budget)?;
        #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
        let requires_internal_dtd = document_requires_internal_dtd(&xml, settings, budget)?;
        let cell = build_cell_after_preflight(xml, settings, budget, peak_namespace_bindings)?;
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

    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    pub(crate) fn parse_with_settings_and_budget(
        xml: String,
        settings: DocumentParseSettings,
        budget: &XmlParseWorkBudget,
    ) -> Result<Self, XmlDocumentError> {
        Self::parse_with_settings_and_optional_budget(xml, settings, Some(budget))
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

    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    pub(crate) fn validate_operation_policy(
        &self,
        xml: crate::policy::XmlInputPolicy,
        resources: &crate::policy::ResourcePolicy,
    ) -> Result<(), crate::policy::PolicyViolation> {
        resources.validate()?;
        self.validate_xml_input_policy(xml.allow_internal_dtd)?;
        resources.validate_xml_document_len(self.as_xml().len())?;
        self.with_view(|view| {
            // Retain lexical preflight metrics per generation, including entity expansion and
            // DTD defaults. A later stricter operation policy must not trust parse-time limits.
            let actual = view.parsed.peak_namespace_bindings;
            if actual > resources.max_xml_namespace_bindings {
                return Err(crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_NAMESPACE_BINDINGS,
                    maximum: resources.max_xml_namespace_bindings,
                    actual,
                });
            }
            let node_count = view.node_count();
            if node_count > resources.effective_xml_nodes() as usize {
                return Err(crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_NODES,
                    maximum: resources.effective_xml_nodes() as usize,
                    actual: node_count,
                });
            }
            let max_depth = view.max_depth();
            if max_depth > resources.max_xml_depth {
                return Err(crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_DEPTH,
                    maximum: resources.max_xml_depth,
                    actual: max_depth,
                });
            }
            Ok(())
        })
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
    pub(crate) fn staged_copy_with_budget(
        &self,
        settings: DocumentParseSettings,
        budget: &XmlParseWorkBudget,
    ) -> Result<Self, XmlDocumentError> {
        Self::parse_with_settings_and_budget(self.as_xml().to_owned(), settings, budget)
    }

    #[cfg(feature = "xmldsig")]
    pub(crate) fn commit_staged(&mut self, staged: Self) -> Result<(), XmlDocumentError> {
        // Signing mutates and validates every staged generation under the active
        // policy. Moving that retained cell preserves atomicity without parsing
        // the complete signed document once more merely to commit it.
        self.commit_cell(staged.cell)
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
    ///
    /// # Errors
    /// Rejects foreign, stale, missing or entity-expanded identities, non-element
    /// targets, invalid fragments and input-limit failures. Failed replacement
    /// leaves the retained document and generation unchanged.
    pub fn replace_element(
        &mut self,
        target: NodeIdentity,
        replacement: &str,
    ) -> Result<(), XmlDocumentError> {
        let next = self.build_node_replacement(
            target,
            replacement,
            ReplacementShape::SingleElement,
            self.settings,
            None,
        )?;
        self.commit_cell(next)
    }

    #[cfg(feature = "xmlenc")]
    pub(crate) fn replace_element_with_budget(
        &mut self,
        target: NodeIdentity,
        replacement: &str,
        settings: DocumentParseSettings,
        budget: &XmlParseWorkBudget,
    ) -> Result<(), XmlDocumentError> {
        let next = self.build_node_replacement(
            target,
            replacement,
            ReplacementShape::SingleElement,
            settings,
            Some(budget),
        )?;
        self.commit_cell(next)
    }

    #[cfg(feature = "xmlenc")]
    pub(crate) fn prepare_element_replacement_with_budget(
        &self,
        target: NodeIdentity,
        replacement: &str,
        settings: DocumentParseSettings,
        budget: &XmlParseWorkBudget,
    ) -> Result<PreparedDocumentMutation, XmlDocumentError> {
        Ok(PreparedDocumentMutation {
            identity: self.identity,
            generation: self.generation,
            cell: self.build_node_replacement(
                target,
                replacement,
                ReplacementShape::SingleElement,
                settings,
                Some(budget),
            )?,
        })
    }

    /// Replace one complete node with an XML fragment valid in its parent context.
    ///
    /// This operation is intended for `XMLEnc` Content replacement, where one
    /// `EncryptedData` element can expand into multiple sibling nodes.
    ///
    /// # Errors
    /// Rejects invalid/stale mutation identities, invalid parent-context
    /// fragments and input-limit failures without committing a generation.
    pub fn replace_node_with_fragment(
        &mut self,
        target: NodeIdentity,
        replacement: &str,
    ) -> Result<(), XmlDocumentError> {
        let next = self.build_node_replacement(
            target,
            replacement,
            ReplacementShape::Fragment,
            self.settings,
            None,
        )?;
        self.commit_cell(next)
    }

    #[cfg(feature = "xmlenc")]
    pub(crate) fn prepare_node_fragment_replacement_with_budget(
        &self,
        target: NodeIdentity,
        replacement: &str,
        settings: DocumentParseSettings,
        budget: &XmlParseWorkBudget,
    ) -> Result<PreparedDocumentMutation, XmlDocumentError> {
        Ok(PreparedDocumentMutation {
            identity: self.identity,
            generation: self.generation,
            cell: self.build_node_replacement(
                target,
                replacement,
                ReplacementShape::Fragment,
                settings,
                Some(budget),
            )?,
        })
    }

    /// Parse the generation that replaces `target` with `replacement`, then
    /// check on that parse that the replacement stayed inside the target's
    /// slot. Budgeted operations report the node ceiling as a projected limit.
    fn build_node_replacement(
        &self,
        target: NodeIdentity,
        replacement: &str,
        shape: ReplacementShape,
        settings: DocumentParseSettings,
        budget: Option<&XmlParseWorkBudget>,
    ) -> Result<DocumentCell, XmlDocumentError> {
        let (range, parent, folded) = self.with_view(|view| {
            let node = view.resolve_mutation_node(target)?;
            if shape == ReplacementShape::SingleElement && !node.is_element() {
                return Err(XmlDocumentError::TargetNotElement);
            }
            // Decoded lengths of the neighbouring text that replacement text
            // folds into; the candidate keeps these values unchanged.
            let text_len = |sibling: Option<Node<'_, '_>>| {
                sibling
                    .filter(Node::is_text)
                    .and_then(Node::text)
                    .map_or(0, str::len)
            };
            let folded = FoldedText {
                before: text_len(node.prev_sibling()),
                after: text_len(node.next_sibling()),
            };
            Ok((node.range(), node.parent_element().map(Node::range), folded))
        })?;
        let output = self.replaced_range(range.clone(), replacement, settings.max_bytes)?;
        let next = build_cell(output, settings, budget).map_err(|error| match error {
            XmlDocumentError::Parse(ParseError::NodesLimitReached) if budget.is_some() => {
                XmlDocumentError::ProjectedNodeLimit {
                    maximum: settings.nodes_limit as usize,
                }
            }
            error => error,
        })?;
        // The parent encloses the target, and the projected document fits the
        // byte ceiling, so neither bound can wrap.
        let slot = range.start..range.start + replacement.len();
        let parent =
            parent.map(|parent| parent.start..parent.end - range.len() + replacement.len());
        let checked = next.with_dependent(|xml, parsed| {
            // The slot check reads source ranges. Nodes expanded from an internal DTD
            // entity may carry a range inside the declaration instead of at their
            // reference (roxmltree), so such documents parse the replacement inside
            // a validation wrapper, which counts expansions where they occur. Without
            // a DTD only predefined and character references expand, and their
            // nodes keep the reference's own range.
            if settings.allow_dtd
                && !parsed
                    .document
                    .descendants()
                    .all(Node::has_actionable_range)
            {
                return Ok(false);
            }
            validate_replacement_slot(xml, &parsed.document, slot, parent, folded, shape)
                .map(|()| true)
        })?;
        if !checked {
            self.validate_in_wrapper(target, replacement, shape, settings, budget)?;
        }
        Ok(next)
    }

    /// Parse `replacement` inside a validation wrapper at the position of `target`,
    /// then check its shape on the wrapper's children.
    fn validate_in_wrapper(
        &self,
        target: NodeIdentity,
        replacement: &str,
        shape: ReplacementShape,
        settings: DocumentParseSettings,
        budget: Option<&XmlParseWorkBudget>,
    ) -> Result<(), XmlDocumentError> {
        let range =
            self.with_view(|view| Ok::<_, XmlDocumentError>(view.resolve_node(target)?.range()))?;
        let maximum = budget.map(|_| settings.nodes_limit as usize);
        let (parsed, wrapper_range) =
            self.parse_wrapped_range(range, replacement, maximum, settings, budget)?;
        if shape == ReplacementShape::Fragment {
            return Ok(());
        }
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

    /// Replace all children of one element with a well-formed XML fragment.
    ///
    /// # Errors
    /// Rejects invalid/stale or non-element targets, invalid contextual fragments
    /// and input-limit failures; the document remains unchanged on failure.
    pub fn replace_content(
        &mut self,
        target: NodeIdentity,
        replacement: &str,
    ) -> Result<(), XmlDocumentError> {
        self.replace_content_inner(target, replacement, None, self.settings, None)
    }

    #[cfg(feature = "xmlenc")]
    pub(crate) fn replace_content_with_budget(
        &mut self,
        target: NodeIdentity,
        replacement: &str,
        settings: DocumentParseSettings,
        budget: &XmlParseWorkBudget,
    ) -> Result<(), XmlDocumentError> {
        self.replace_content_inner(
            target,
            replacement,
            Some(settings.nodes_limit as usize),
            settings,
            Some(budget),
        )
    }

    fn replace_content_inner(
        &mut self,
        target: NodeIdentity,
        replacement: &str,
        maximum: Option<usize>,
        settings: DocumentParseSettings,
        budget: Option<&XmlParseWorkBudget>,
    ) -> Result<(), XmlDocumentError> {
        let (range, self_closing_expansion, serialized_len) = self.with_view(|view| {
            let node = view.resolve_mutation_node(target)?;
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
                let serialized_len = slash
                    .checked_add(replacement.len())
                    .and_then(|length| length.checked_add(qualified_name.len()))
                    .and_then(|length| length.checked_add(4))
                    .ok_or(XmlDocumentError::DocumentTooLarge {
                        maximum: settings.max_bytes,
                        actual: usize::MAX,
                    })?;
                return Ok((range, Some((slash, qualified_name)), serialized_len));
            }
            let range = (range.start + content.start)..(range.start + content.end);
            Ok((range, None, replacement.len()))
        })?;
        self.ensure_replacement_fits(&range, serialized_len, settings.max_bytes)?;
        let serialized_replacement = if let Some((slash, qualified_name)) = self_closing_expansion {
            let source = &self.as_xml()[range.clone()];
            format!("{}>{replacement}</{qualified_name}>", &source[..slash])
        } else {
            replacement.to_owned()
        };
        self.validate_content_in_element_context(target, replacement, maximum, settings, budget)?;
        if let Some(maximum) = maximum {
            debug_assert_eq!(maximum, settings.nodes_limit as usize);
            self.replace_range_with_settings(range, &serialized_replacement, settings, budget)
        } else {
            self.replace_range(range, &serialized_replacement, budget)
        }
    }

    /// Replace the children of several non-overlapping elements atomically.
    ///
    /// All identities must belong to the current generation. Every boundary is
    /// checked in one validation candidate, then the final candidate is parsed
    /// and either commits as one new generation or leaves the document unchanged.
    ///
    /// # Errors
    /// Rejects invalid/stale, overlapping or non-element targets, invalid
    /// fragments, and input-limit failures without committing any replacement.
    pub fn replace_contents(
        &mut self,
        replacements: &[(NodeIdentity, String)],
    ) -> Result<(), XmlDocumentError> {
        self.replace_contents_inner(replacements, self.settings, false, true, None)
    }

    #[cfg(all(feature = "xmldsig", test))]
    pub(crate) fn replace_contents_with_budget(
        &mut self,
        replacements: &[(NodeIdentity, String)],
        settings: DocumentParseSettings,
        budget: &XmlParseWorkBudget,
    ) -> Result<(), XmlDocumentError> {
        self.replace_contents_inner(replacements, settings, true, true, Some(budget))
    }

    #[cfg(feature = "xmldsig")]
    pub(crate) fn replace_base64_contents_with_budget(
        &mut self,
        replacements: &[(NodeIdentity, String)],
        settings: DocumentParseSettings,
        budget: &XmlParseWorkBudget,
    ) -> Result<(), XmlDocumentError> {
        validate_base64_replacements(replacements)?;
        // Base64 cannot alter XML structure, so the committed candidate parse
        // is also the boundary validation. Generic caller fragments retain the
        // separate contextual validation path above.
        self.replace_contents_inner(replacements, settings, true, false, Some(budget))
    }

    #[cfg(feature = "xmldsig")]
    pub(crate) fn project_base64_contents(
        &self,
        replacements: &[(NodeIdentity, String)],
        maximum_bytes: usize,
    ) -> Result<String, XmlDocumentError> {
        validate_base64_replacements(replacements)?;
        let (edits, projected) =
            self.prepare_content_replacement_edits(replacements, maximum_bytes)?;
        Ok(self.render_content_replacement_edits(&edits, projected))
    }

    /// Serialize the generation that committing these base64 replacements under
    /// `settings` would produce, without parsing it. Base64 character data cannot
    /// change element structure, so the commit parse would only recheck the
    /// projected size and node count, which are checked here instead.
    #[cfg(feature = "xmldsig")]
    pub(crate) fn project_base64_commit(
        &self,
        replacements: &[(NodeIdentity, String)],
        settings: DocumentParseSettings,
    ) -> Result<String, XmlDocumentError> {
        validate_base64_replacements(replacements)?;
        let (edits, projected) =
            self.prepare_content_replacement_edits(replacements, settings.max_bytes)?;
        let projected_nodes = self.with_view(|view| {
            replacements
                .iter()
                .try_fold(view.node_count(), |count, (target, replacement)| {
                    // The content becomes exactly one text node, or none when empty. The
                    // target's descendants (itself included) are part of `count`.
                    let replaced = view.resolve_mutation_node(*target)?.descendants().count() - 1;
                    Ok::<_, XmlDocumentError>(
                        count - replaced + usize::from(!replacement.is_empty()),
                    )
                })
        })?;
        if projected_nodes > settings.nodes_limit as usize {
            return Err(XmlDocumentError::ProjectedNodeLimit {
                maximum: settings.nodes_limit as usize,
            });
        }
        Ok(self.render_content_replacement_edits(&edits, projected))
    }

    fn replace_contents_inner(
        &mut self,
        replacements: &[(NodeIdentity, String)],
        settings: DocumentParseSettings,
        policy_bounded: bool,
        validate_fragments: bool,
        budget: Option<&XmlParseWorkBudget>,
    ) -> Result<(), XmlDocumentError> {
        if replacements.is_empty() {
            return Ok(());
        }
        let (edits, projected) =
            self.prepare_content_replacement_edits(replacements, settings.max_bytes)?;

        if validate_fragments {
            self.validate_content_edits(&edits, settings, policy_bounded, budget)?;
        }

        let output = self.render_content_replacement_edits(&edits, projected);
        if policy_bounded {
            self.replace_serialized_with_settings(output, settings, budget)
        } else {
            self.replace_serialized(output, budget)
        }
    }

    fn prepare_content_replacement_edits<'a>(
        &self,
        replacements: &'a [(NodeIdentity, String)],
        maximum_bytes: usize,
    ) -> Result<(Vec<ContentReplacementEdit<'a>>, usize), XmlDocumentError> {
        let mut targets = HashSet::with_capacity(replacements.len());
        if replacements
            .iter()
            .any(|(target, _)| !targets.insert(*target))
        {
            return Err(XmlDocumentError::InvalidReplacement(
                "replacement targets must be unique".into(),
            ));
        }
        let mut edits = self.with_view(|view| {
            replacements
                .iter()
                .map(|(target, replacement)| {
                    let node = view.resolve_mutation_node(*target)?;
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
                        Ok(ContentReplacementEdit {
                            range,
                            replacement,
                            self_closing: Some(SelfClosingContentEdit {
                                prefix_end: slash,
                                qualified_name,
                            }),
                        })
                    } else {
                        Ok(ContentReplacementEdit {
                            range: (range.start + content.start)..(range.start + content.end),
                            replacement,
                            self_closing: None,
                        })
                    }
                })
                .collect::<Result<Vec<_>, XmlDocumentError>>()
        })?;
        edits.sort_by_key(|edit| edit.range.start);
        if edits
            .windows(2)
            .any(|pair| pair[0].range.end > pair[1].range.start)
        {
            return Err(XmlDocumentError::InvalidReplacement(
                "replacement targets overlap".into(),
            ));
        }
        let projected = edits.iter().try_fold(self.as_xml().len(), |length, edit| {
            length
                .checked_sub(edit.range.len())
                .and_then(|length| length.checked_add(edit.output_len()?))
                .ok_or(XmlDocumentError::DocumentTooLarge {
                    maximum: maximum_bytes,
                    actual: usize::MAX,
                })
        })?;
        if projected > maximum_bytes {
            return Err(XmlDocumentError::DocumentTooLarge {
                maximum: maximum_bytes,
                actual: projected,
            });
        }
        Ok((edits, projected))
    }

    fn render_content_replacement_edits(
        &self,
        edits: &[ContentReplacementEdit<'_>],
        projected: usize,
    ) -> String {
        let mut output = String::with_capacity(projected);
        let mut cursor = 0;
        for edit in edits {
            output.push_str(&self.as_xml()[cursor..edit.range.start]);
            edit.write_output(self.as_xml(), &mut output);
            cursor = edit.range.end;
        }
        output.push_str(&self.as_xml()[cursor..]);
        debug_assert_eq!(output.len(), projected);
        output
    }

    fn validate_content_edits(
        &self,
        edits: &[ContentReplacementEdit<'_>],
        settings: DocumentParseSettings,
        policy_bounded: bool,
        budget: Option<&XmlParseWorkBudget>,
    ) -> Result<(), XmlDocumentError> {
        let projected = edits.iter().try_fold(self.as_xml().len(), |length, edit| {
            length
                .checked_sub(edit.range.len())
                .and_then(|length| length.checked_add(edit.validation_output_len()?))
                .ok_or_else(|| {
                    XmlDocumentError::InvalidReplacement("validation length overflow".into())
                })
        })?;
        let mut candidate = String::with_capacity(projected);
        let mut wrapper_ranges = Vec::with_capacity(edits.len());
        let mut cursor = 0;
        for edit in edits {
            candidate.push_str(&self.as_xml()[cursor..edit.range.start]);
            wrapper_ranges.push(edit.write_validation_output(self.as_xml(), &mut candidate));
            cursor = edit.range.end;
        }
        candidate.push_str(&self.as_xml()[cursor..]);
        debug_assert_eq!(candidate.len(), projected);

        let active_nodes_limit = settings.nodes_limit as usize;
        let wrapper_allowance = edits.len();
        let validation_nodes_limit = active_nodes_limit
            .checked_add(wrapper_allowance)
            .and_then(|maximum| u32::try_from(maximum).ok())
            .unwrap_or(u32::MAX);
        let parsed = build_cell(
            candidate,
            DocumentParseSettings {
                nodes_limit: validation_nodes_limit,
                depth_limit: settings.depth_limit.saturating_add(1),
                // Nonoverlapping wrappers contribute at most one simultaneously active binding.
                // The committed candidate is still checked against the caller's unmodified limit.
                namespace_bindings_limit: settings.namespace_bindings_limit.saturating_add(1),
                max_bytes: projected,
                ..settings
            },
            budget,
        )
        .map_err(|error| match (policy_bounded, error) {
            (true, XmlDocumentError::Parse(ParseError::NodesLimitReached)) => {
                XmlDocumentError::ProjectedNodeLimit {
                    maximum: active_nodes_limit,
                }
            }
            (_, XmlDocumentError::DocumentTooDeep { actual, .. }) => {
                XmlDocumentError::DocumentTooDeep {
                    maximum: settings.depth_limit,
                    actual: actual.saturating_sub(1),
                }
            }
            (_, error) => strip_validation_wrapper_namespace_binding(error, settings),
        })?;
        parsed.with_dependent(|_, document| validate_wrappers(document, &wrapper_ranges))
    }

    /// Append a well-formed XML fragment as the last child of an element.
    ///
    /// # Errors
    /// Rejects invalid/stale or non-element targets, invalid fragments and
    /// input-limit failures without committing a generation.
    pub fn append_child(
        &mut self,
        target: NodeIdentity,
        child: &str,
    ) -> Result<(), XmlDocumentError> {
        self.append_child_inner(target, child, None, self.settings, true, None)
    }

    #[cfg(all(feature = "xmldsig", test))]
    pub(crate) fn append_child_with_budget(
        &mut self,
        target: NodeIdentity,
        child: &str,
        settings: DocumentParseSettings,
        budget: &XmlParseWorkBudget,
    ) -> Result<(), XmlDocumentError> {
        self.append_child_inner(
            target,
            child,
            Some(settings.nodes_limit as usize),
            settings,
            true,
            Some(budget),
        )
    }

    #[cfg(feature = "xmldsig")]
    pub(crate) fn append_generated_child_with_budget(
        &mut self,
        target: NodeIdentity,
        child: &str,
        settings: DocumentParseSettings,
        budget: &XmlParseWorkBudget,
    ) -> Result<(), XmlDocumentError> {
        // SignatureBuilder emits this fragment through the shared lexical writer.
        // Parsing the final candidate once validates both the generated child and its
        // document context without a redundant wrapper-document pass.
        self.append_child_inner(
            target,
            child,
            Some(settings.nodes_limit as usize),
            settings,
            false,
            Some(budget),
        )
    }

    fn append_child_inner(
        &mut self,
        target: NodeIdentity,
        child: &str,
        maximum: Option<usize>,
        settings: DocumentParseSettings,
        validate_context: bool,
        budget: Option<&XmlParseWorkBudget>,
    ) -> Result<(), XmlDocumentError> {
        let projected = self.projected_child_append_len(target, child.len())?;
        if projected > settings.max_bytes {
            return Err(XmlDocumentError::DocumentTooLarge {
                maximum: settings.max_bytes,
                actual: projected,
            });
        }
        let (range, replacement) = self.with_view(|view| {
            let node = view.resolve_mutation_node(target)?;
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
        self.ensure_replacement_fits(&range, replacement.len(), settings.max_bytes)?;
        if validate_context {
            self.validate_content_in_element_context(target, child, maximum, settings, budget)?;
        }
        if let Some(maximum) = maximum {
            debug_assert_eq!(maximum, settings.nodes_limit as usize);
            self.replace_range_with_settings(range, &replacement, settings, budget)
        } else {
            self.replace_range(range, &replacement, budget)
        }
    }

    pub(crate) fn replace_serialized(
        &mut self,
        xml: String,
        budget: Option<&XmlParseWorkBudget>,
    ) -> Result<(), XmlDocumentError> {
        let next = build_cell(xml, self.settings, budget)?;
        self.commit_cell(next)
    }

    pub(crate) fn replace_serialized_with_settings(
        &mut self,
        xml: String,
        settings: DocumentParseSettings,
        budget: Option<&XmlParseWorkBudget>,
    ) -> Result<(), XmlDocumentError> {
        let next = build_cell(xml, settings, budget).map_err(|error| match error {
            XmlDocumentError::Parse(ParseError::NodesLimitReached) => {
                XmlDocumentError::ProjectedNodeLimit {
                    maximum: settings.nodes_limit as usize,
                }
            }
            error => error,
        })?;
        self.commit_cell(next)
    }

    fn commit_cell(&mut self, next: DocumentCell) -> Result<(), XmlDocumentError> {
        let next_generation = self.generation.checked_add(1).ok_or_else(|| {
            XmlDocumentError::InvalidReplacement("document generation overflow".into())
        })?;
        self.cell = next;
        self.generation = next_generation;
        Ok(())
    }

    #[cfg(feature = "xmldsig")]
    pub(crate) fn projected_content_replacement_len(
        &self,
        target: NodeIdentity,
        replacement_len: usize,
    ) -> Result<usize, XmlDocumentError> {
        self.with_view(|view| {
            let node = view.resolve_mutation_node(target)?;
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

    pub(crate) fn projected_child_append_len(
        &self,
        target: NodeIdentity,
        child_len: usize,
    ) -> Result<usize, XmlDocumentError> {
        self.with_view(|view| {
            let node = view.resolve_mutation_node(target)?;
            if !node.is_element() {
                return Err(XmlDocumentError::TargetNotElement);
            }
            let range = node.range();
            let source = &view.xml()[range.clone()];
            let (_, qualified_name, self_closing) = element_content_range(source)?;
            let (removed, added) = if self_closing {
                let slash = source.rfind("/>").ok_or_else(|| {
                    XmlDocumentError::InvalidReplacement(
                        "self-closing element has no terminator".into(),
                    )
                })?;
                let expanded = slash
                    .checked_add(1)
                    .and_then(|length| length.checked_add(child_len))
                    .and_then(|length| length.checked_add(2))
                    .and_then(|length| length.checked_add(qualified_name.len()))
                    .and_then(|length| length.checked_add(1))
                    .ok_or_else(|| {
                        XmlDocumentError::InvalidReplacement("child append length overflow".into())
                    })?;
                (range.len(), expanded)
            } else {
                (0, child_len)
            };
            view.xml()
                .len()
                .checked_sub(removed)
                .and_then(|length| length.checked_add(added))
                .ok_or_else(|| {
                    XmlDocumentError::InvalidReplacement("child append length overflow".into())
                })
        })
    }

    fn replace_range(
        &mut self,
        range: std::ops::Range<usize>,
        replacement: &str,
        budget: Option<&XmlParseWorkBudget>,
    ) -> Result<(), XmlDocumentError> {
        let output = self.replaced_range(range, replacement, self.settings.max_bytes)?;
        self.replace_serialized(output, budget)
    }

    fn replace_range_with_settings(
        &mut self,
        range: std::ops::Range<usize>,
        replacement: &str,
        settings: DocumentParseSettings,
        budget: Option<&XmlParseWorkBudget>,
    ) -> Result<(), XmlDocumentError> {
        let output = self.replaced_range(range, replacement, settings.max_bytes)?;
        self.replace_serialized_with_settings(output, settings, budget)
    }

    #[cfg(feature = "xmlenc")]
    pub(crate) fn commit_prepared(
        &mut self,
        prepared: PreparedDocumentMutation,
    ) -> Result<(), XmlDocumentError> {
        if self.identity != prepared.identity {
            return Err(XmlDocumentError::ForeignIdentity);
        }
        if self.generation != prepared.generation {
            return Err(XmlDocumentError::StaleIdentity {
                identity: prepared.generation,
                current: self.generation,
            });
        }
        self.commit_cell(prepared.cell)
    }

    fn replaced_range(
        &self,
        range: std::ops::Range<usize>,
        replacement: &str,
        maximum_bytes: usize,
    ) -> Result<String, XmlDocumentError> {
        let projected = self.ensure_replacement_fits(&range, replacement.len(), maximum_bytes)?;
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
        maximum_bytes: usize,
    ) -> Result<usize, XmlDocumentError> {
        let projected = self
            .as_xml()
            .len()
            .checked_sub(range.len())
            .and_then(|length| length.checked_add(replacement_len))
            .ok_or(XmlDocumentError::DocumentTooLarge {
                maximum: maximum_bytes,
                actual: usize::MAX,
            })?;
        if projected > maximum_bytes {
            return Err(XmlDocumentError::DocumentTooLarge {
                maximum: maximum_bytes,
                actual: projected,
            });
        }
        Ok(projected)
    }

    fn validate_content_in_element_context(
        &self,
        target: NodeIdentity,
        replacement: &str,
        maximum: Option<usize>,
        settings: DocumentParseSettings,
        budget: Option<&XmlParseWorkBudget>,
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
                .parse_wrapped_range(content_range, replacement, maximum, settings, budget)
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
            maximum,
            settings,
            budget,
        )
        .map(|_| ())
    }

    fn parse_wrapped_range(
        &self,
        range: std::ops::Range<usize>,
        replacement: &str,
        maximum: Option<usize>,
        settings: DocumentParseSettings,
        budget: Option<&XmlParseWorkBudget>,
    ) -> Result<(DocumentCell, std::ops::Range<usize>), XmlDocumentError> {
        let wrapped = wrapped_fragment(replacement);
        let wrapper_range = range.start..(range.start + wrapped.len());
        self.parse_wrapped_edit(range, &wrapped, wrapper_range, maximum, settings, budget)
    }

    fn parse_wrapped_edit(
        &self,
        range: std::ops::Range<usize>,
        replacement: &str,
        wrapper_range: std::ops::Range<usize>,
        maximum: Option<usize>,
        settings: DocumentParseSettings,
        budget: Option<&XmlParseWorkBudget>,
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
        let active_nodes_limit = maximum
            .map(|maximum| maximum.min(settings.nodes_limit as usize))
            .map_or(settings.nodes_limit, |maximum| {
                u32::try_from(maximum).unwrap_or(u32::MAX)
            });
        let parsed = build_cell(
            candidate,
            DocumentParseSettings {
                nodes_limit: active_nodes_limit.saturating_add(VALIDATION_WRAPPER_NODE_OVERHEAD),
                // Wrapper markup is validation scaffolding, not document input.
                // The committed candidate is checked against the real ceiling.
                depth_limit: settings.depth_limit.saturating_add(1),
                namespace_bindings_limit: settings.namespace_bindings_limit.saturating_add(1),
                max_bytes: projected,
                ..settings
            },
            budget,
        )
        .map_err(|error| match (maximum, error) {
            (Some(_), XmlDocumentError::Parse(ParseError::NodesLimitReached)) => {
                XmlDocumentError::ProjectedNodeLimit {
                    maximum: active_nodes_limit as usize,
                }
            }
            (_, XmlDocumentError::DocumentTooDeep { actual, .. }) => {
                XmlDocumentError::DocumentTooDeep {
                    maximum: settings.depth_limit,
                    actual: actual.saturating_sub(1),
                }
            }
            (_, error) => strip_validation_wrapper_namespace_binding(error, settings),
        })?;
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
        self.parsed.node_count
    }

    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    pub(crate) fn max_depth(self) -> usize {
        self.parsed.max_depth
    }

    /// Resolve an ID using standard spellings plus caller registrations.
    #[must_use]
    pub fn node_for_id(
        self,
        value: &str,
        registrations: &[IdAttributeRegistration],
    ) -> Option<NodeIdentity> {
        let mut matched = match self.parsed.indexes.default_ids.get(value) {
            Some(Some(node)) => Some(*node),
            Some(None) => return None,
            None => None,
        };
        for registration in registrations {
            let key = (
                registration.attribute_local_name().to_owned(),
                value.to_owned(),
            );
            if let Some(nodes) = self.parsed.indexes.attributes_by_value.get(&key) {
                for node_id in nodes {
                    let recognized = self.parsed.document.get_node(*node_id).is_some_and(|node| {
                        node.attributes().any(|attribute| {
                            attribute.value() == value && registration.matches(node, attribute)
                        })
                    });
                    if !recognized {
                        continue;
                    }
                    if matched.is_some_and(|previous| previous != *node_id) {
                        return None;
                    }
                    matched = Some(*node_id);
                }
            }
        }
        matched.map(|node| self.node_identity_by_id(node))
    }

    #[cfg(feature = "xmldsig")]
    pub(crate) fn id_index(
        self,
        registrations: &[IdAttributeRegistration],
    ) -> HashMap<String, NodeId> {
        // The same classification and ambiguity rules govern borrowed and
        // retained resolvers; retain only the final value-to-node mapping.
        crate::xml::XmlIdIndex::with_registrations(self.document(), registrations).into_node_ids()
    }

    /// Return deterministic document order for a current tree-node identity.
    ///
    /// # Errors
    /// Rejects foreign/stale identities or nodes absent from this generation.
    pub fn document_order(self, identity: NodeIdentity) -> Result<usize, XmlDocumentError> {
        self.validate_identity(identity)?;
        self.parsed
            .indexes
            .order
            .get(&self.resolve_node(identity)?.id())
            .copied()
            .ok_or(XmlDocumentError::MissingNode)
    }

    /// Return a total order key for a current tree node.
    ///
    /// # Errors
    /// Returns identity-resolution failures as in [`Self::document_order`].
    pub fn node_order(self, identity: NodeIdentity) -> Result<SemanticOrder, XmlDocumentError> {
        Ok(SemanticOrder {
            node: self.document_order(identity)?,
            phase: 0,
            position: 0,
        })
    }

    /// Return a total order key for a current attribute node.
    ///
    /// # Errors
    /// Rejects foreign/stale owners and missing attributes on that owner.
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
    ///
    /// # Errors
    /// Rejects foreign/stale owners and namespace bindings absent from that owner.
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
        NodeIdentity {
            document: self.identity,
            generation: self.generation,
            semantic_id: SemanticDocument::node_id(&self.parsed.document, node),
        }
    }

    pub(crate) fn node_identity_by_id(self, backend: NodeId) -> NodeIdentity {
        let node = self
            .parsed
            .document
            .get_node(backend)
            .expect("indexed backend node must remain in the retained document");
        self.node_identity(node)
    }

    pub(crate) fn resolve_node(
        self,
        identity: NodeIdentity,
    ) -> Result<Node<'a, 'a>, XmlDocumentError> {
        self.validate_identity(identity)?;
        SemanticDocument::node(&self.parsed.document, identity.semantic_id)
            .ok_or(XmlDocumentError::MissingNode)
    }

    fn resolve_mutation_node(
        self,
        identity: NodeIdentity,
    ) -> Result<Node<'a, 'a>, XmlDocumentError> {
        let node = self.resolve_node(identity)?;
        if !node.has_actionable_range() {
            return Err(XmlDocumentError::EntityExpandedMutationTarget);
        }
        Ok(node)
    }

    /// Identify an attribute by expanded name on a current owner element.
    ///
    /// # Errors
    /// Rejects foreign/stale or non-element owners and absent expanded names.
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

    /// Return the in-scope `XPath` namespace nodes owned by one current element.
    ///
    /// # Errors
    /// Rejects foreign/stale, missing or non-element owners.
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
    budget: Option<&XmlParseWorkBudget>,
) -> Result<DocumentCell, XmlDocumentError> {
    let peak_namespace_bindings = preflight_document_limits(&xml, settings, budget)?;
    build_cell_after_preflight(xml, settings, budget, peak_namespace_bindings)
}

fn build_cell_after_preflight(
    xml: String,
    settings: DocumentParseSettings,
    budget: Option<&XmlParseWorkBudget>,
    peak_namespace_bindings: usize,
) -> Result<DocumentCell, XmlDocumentError> {
    charge_semantic_parser_work(budget, xml.len())?;
    build_semantic_cell(xml, settings, peak_namespace_bindings)
}

fn build_semantic_cell(
    xml: String,
    settings: DocumentParseSettings,
    peak_namespace_bindings: usize,
) -> Result<DocumentCell, XmlDocumentError> {
    #[cfg(not(any(feature = "xmldsig", feature = "xmlenc")))]
    let _ = peak_namespace_bindings;
    DocumentCell::try_new(xml, |source| {
        let (document, metrics) = parse_semantic_document(source, settings)?;
        let indexes = DocumentIndexes::build(&document);
        Ok::<_, XmlDocumentError>(ParsedDocument {
            document,
            indexes,
            node_count: metrics.node_count,
            #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
            max_depth: metrics.max_depth,
            #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
            peak_namespace_bindings,
        })
    })
}

pub(crate) fn parse_borrowed_with_settings_and_budget<'a>(
    xml: &'a str,
    settings: DocumentParseSettings,
    budget: Option<&XmlParseWorkBudget>,
) -> Result<Document<'a>, XmlDocumentError> {
    preflight_document_limits(xml, settings, budget)?;
    charge_semantic_parser_work(budget, xml.len())?;
    let (document, _) = parse_semantic_document(xml, settings)?;
    Ok(document)
}

#[cfg(feature = "xmldsig")]
pub(crate) fn parse_borrowed_in<'input, 'w, W: structured_asn1::memory::Work>(
    xml: &'input str,
    settings: DocumentParseSettings,
    budget: Option<&XmlParseWorkBudget>,
    storage: crate::xml::dom::storage::Accounted<'w, W>,
) -> Result<Document<'input, crate::xml::dom::storage::Accounted<'w, W>>, XmlDocumentError> {
    preflight_document_limits_in(xml, settings, budget, storage)?;
    charge_semantic_parser_work(budget, xml.len())?;
    let document = Document::parse_after_limit_preflight_in(
        xml,
        ParsingOptions {
            allow_dtd: settings.allow_dtd,
            nodes_limit: settings.nodes_limit,
        },
        settings.backend,
        storage,
    )?;
    validate_document_metrics_in(&document, settings.depth_limit, storage)?;
    Ok(document)
}

fn preflight_document_limits(
    xml: &str,
    settings: DocumentParseSettings,
    budget: Option<&XmlParseWorkBudget>,
) -> Result<usize, XmlDocumentError> {
    preflight_document_limits_in(xml, settings, budget, NativeXmlStorage)
}

/// Enforce every policy limit on `xml` in one charged lexical pass, for a
/// parser outside this crate's DOM that does not enforce them itself.
#[cfg(feature = "xslt")]
pub(crate) fn preflight_xml_limits<S: NameStorage>(
    xml: &str,
    settings: DocumentParseSettings,
    budget: &XmlParseWorkBudget,
    storage: S,
) -> Result<(), XmlDocumentError> {
    preflight_document_limits_in(xml, settings, Some(budget), storage).map(drop)
}

fn preflight_document_limits_in<S: NameStorage>(
    xml: &str,
    settings: DocumentParseSettings,
    budget: Option<&XmlParseWorkBudget>,
    storage: S,
) -> Result<usize, XmlDocumentError> {
    // This bounded lexical pass is the first parser stage for every entry
    // point, before either backend is allowed to construct a DOM.
    if xml.len() > settings.max_bytes {
        return Err(XmlDocumentError::DocumentTooLarge {
            maximum: settings.max_bytes,
            actual: xml.len(),
        });
    }
    charge_parse_work(budget, xml.len())?;
    let mut dtd = InternalDtd::new(storage);
    let mut expansion_stack = storage.names();
    let mut state = DocumentPreflightState::new(storage)?;
    preflight_xml_fragment(
        xml,
        settings,
        &mut dtd,
        &mut expansion_stack,
        &mut state,
        budget,
        true,
    )?;
    Ok(state.peak_namespace_bindings)
}

struct DocumentPreflightState<S: NameStorage = NativeXmlStorage> {
    depth: usize,
    nodes: u32,
    in_character_data: bool,
    entity_expansions: u32,
    entity_expansion_work: usize,
    active_namespace_bindings: S::Names<S::Text, ()>,
    peak_namespace_bindings: usize,
    namespace_scopes: S::Values<S::Values<(S::Text, bool)>>,
    storage: S,
}

impl<S: NameStorage> DocumentPreflightState<S> {
    fn new(storage: S) -> Result<Self, ParseError> {
        Ok(Self {
            depth: 0,
            nodes: 0,
            in_character_data: false,
            entity_expansions: 0,
            entity_expansion_work: 0,
            active_namespace_bindings: storage.names(),
            peak_namespace_bindings: 0,
            namespace_scopes: storage.values(0)?,
            storage,
        })
    }
}

impl Default for DocumentPreflightState {
    fn default() -> Self {
        Self::new(NativeXmlStorage).expect("empty XML preflight does not allocate")
    }
}

struct InternalDtd<S: NameStorage = NativeXmlStorage> {
    entities: S::Names<S::Text, S::Text>,
    attribute_defaults: S::Names<S::Text, S::Values<InternalAttributeDefault<S>>>,
    storage: S,
}

impl<S: NameStorage> InternalDtd<S> {
    fn new(storage: S) -> Self {
        Self {
            entities: storage.names(),
            attribute_defaults: storage.names(),
            storage,
        }
    }
}

impl Default for InternalDtd {
    fn default() -> Self {
        Self::new(NativeXmlStorage)
    }
}

struct InternalAttributeDefault<S: NameStorage = NativeXmlStorage> {
    attribute_name: S::Text,
    value: S::Text,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FragmentContext {
    Content,
    Attribute,
}

enum PreflightEvent<S: NameStorage = NativeXmlStorage> {
    DocType(Option<S::Text>),
    GeneralRef {
        name: Option<S::Text>,
        is_character_reference: bool,
    },
    CharacterData {
        xml_whitespace: bool,
    },
    Start {
        attribute_source: S::Values<u8>,
        namespace_declarations: S::Values<NamespaceDeclaration<S>>,
    },
    Empty {
        attribute_source: S::Values<u8>,
        namespace_declarations: S::Values<NamespaceDeclaration<S>>,
    },
    End,
    Node,
    Markup,
    Done,
}

enum FragmentSource<S: NameStorage> {
    Document,
    Entity(S::Text),
}

struct FragmentFrame<S: NameStorage> {
    source: FragmentSource<S>,
    offset: usize,
    collect_doctype: bool,
    context: FragmentContext,
    pending_attribute_source: S::Values<u8>,
    pending_attribute_offset: usize,
}

impl<S: NameStorage> FragmentFrame<S> {
    fn next_event(
        &mut self,
        xml: &str,
        dtd: &InternalDtd<S>,
        state: &mut DocumentPreflightState<S>,
        budget: Option<&XmlParseWorkBudget>,
    ) -> Result<(PreflightEvent<S>, bool, FragmentContext), XmlDocumentError> {
        let storage = state.storage;
        let mut pending =
            general_references(&self.pending_attribute_source[self.pending_attribute_offset..]);
        if let Some(name) = pending.next() {
            self.pending_attribute_offset = self
                .pending_attribute_offset
                .saturating_add(pending.consumed());
            // XML 1.0 4.6: this iterator excludes character and predefined
            // references, including their normative redeclarations.
            // https://www.w3.org/TR/xml/#sec-predefined-ent
            return Ok((
                PreflightEvent::GeneralRef {
                    name: Some(storage.text(name)?),
                    is_character_reference: false,
                },
                false,
                FragmentContext::Attribute,
            ));
        }
        self.pending_attribute_source.clear();
        self.pending_attribute_offset = 0;
        let source = match &self.source {
            FragmentSource::Document => xml,
            FragmentSource::Entity(name) => dtd
                .entities
                .get(name, storage)?
                .expect("active entity replacement remains registered")
                .as_ref(),
        };
        let (event, consumed) =
            scan_preflight_event(&source[self.offset..], self.context, dtd, state, budget)?;
        self.offset = self.offset.saturating_add(consumed);
        Ok((event, self.collect_doctype, self.context))
    }
}

fn enter_preflight_entity<S: NameStorage>(
    name: S::Text,
    context: FragmentContext,
    dtd: &InternalDtd<S>,
    expansion_stack: &mut S::Names<S::Text, ()>,
    fragments: &mut S::Values<FragmentFrame<S>>,
    state: &mut DocumentPreflightState<S>,
    budget: Option<&XmlParseWorkBudget>,
) -> Result<(), XmlDocumentError> {
    let storage = state.storage;
    if expansion_stack.get(&name, storage)?.is_none() {
        expansion_stack.insert(storage.text(&name)?, ())?;
        if let Some(replacement) = dtd.entities.get(&name, storage)? {
            state.entity_expansions = state.entity_expansions.saturating_add(1);
            let maximum = crate::hard_limits::XML_ENTITY_EXPANSION_CEILING;
            if state.entity_expansions > maximum {
                return Err(XmlDocumentError::Parse(
                    ParseError::EntityExpansionLimitReached {
                        maximum,
                        actual: state.entity_expansions,
                    },
                ));
            }
            charge_entity_expansion_work(state, budget, replacement.len())?;
            storage.charge(replacement.len())?;
            storage.charge(replacement.len())?;
            storage.charge(replacement.len())?;
            fragments.push(FragmentFrame {
                source: FragmentSource::Entity(name),
                offset: 0,
                collect_doctype: false,
                context,
                pending_attribute_source: storage.values(0)?,
                pending_attribute_offset: 0,
            })?;
        } else {
            expansion_stack.remove(&name, storage)?;
        }
    }
    Ok(())
}

fn preflight_xml_fragment<S: NameStorage>(
    xml: &str,
    settings: DocumentParseSettings,
    dtd: &mut InternalDtd<S>,
    expansion_stack: &mut S::Names<S::Text, ()>,
    state: &mut DocumentPreflightState<S>,
    budget: Option<&XmlParseWorkBudget>,
    collect_doctype: bool,
) -> Result<(), XmlDocumentError> {
    if state.nodes == 0 {
        // roxmltree exposes its document root as the first semantic node.
        state.nodes = 1;
    }
    let storage = state.storage;
    // Disjoint lexical event windows make these source-sized passes linear;
    // dictionary probes, expansion revisits and copies are admitted separately.
    storage.charge(xml.len())?;
    storage.charge(xml.len())?;
    storage.charge(xml.len())?;
    let mut fragments: S::Values<FragmentFrame<S>> = storage.values(1)?;
    fragments.push(FragmentFrame {
        source: FragmentSource::Document,
        offset: 0,
        collect_doctype,
        context: FragmentContext::Content,
        pending_attribute_source: storage.values(0)?,
        pending_attribute_offset: 0,
    })?;
    // Syntax diagnostics and exact parser precedence belong to the selected
    // DOM pipeline; this pass stops at malformed syntax after bounding its prefix.
    while !fragments.is_empty() {
        storage.charge(1)?;
        let (event, collect_doctype, context) = {
            let frame = fragments.last_mut().expect("fragment stack is not empty");
            frame.next_event(xml, dtd, state, budget)?
        };

        match event {
            PreflightEvent::DocType(doctype) => {
                if collect_doctype
                    && settings.allow_dtd
                    && let Some(doctype) = doctype
                {
                    collect_internal_dtd(&doctype, dtd)?;
                }
                state.in_character_data = false;
                continue;
            }
            PreflightEvent::GeneralRef {
                name,
                is_character_reference,
            } => {
                let Some(name) = name else {
                    continue;
                };
                if is_character_reference {
                    if context == FragmentContext::Content {
                        observe_preflight_node(state, settings, true)?;
                    }
                    continue;
                }
                enter_preflight_entity(
                    name,
                    context,
                    dtd,
                    expansion_stack,
                    &mut fragments,
                    state,
                    budget,
                )?;
                continue;
            }
            PreflightEvent::Done => {
                let frame = fragments.pop().expect("fragment stack is not empty");
                if let FragmentSource::Entity(name) = frame.source {
                    expansion_stack.remove(&name, storage)?;
                }
                continue;
            }
            PreflightEvent::CharacterData { xml_whitespace } => {
                if context == FragmentContext::Attribute {
                    continue;
                }
                if state.depth == 0 && xml_whitespace {
                    state.in_character_data = false;
                    continue;
                }
                let starts_semantic_node = !state.in_character_data;
                state.in_character_data = true;
                if starts_semantic_node {
                    observe_preflight_node(state, settings, false)?;
                }
                continue;
            }
            PreflightEvent::Node => {
                state.in_character_data = false;
                observe_preflight_node(state, settings, false)?;
                continue;
            }
            PreflightEvent::Markup => {
                state.in_character_data = false;
                continue;
            }
            PreflightEvent::Start { .. } | PreflightEvent::Empty { .. } | PreflightEvent::End => {}
        }

        if context == FragmentContext::Attribute {
            continue;
        }
        state.in_character_data = false;
        observe_preflight_markup(event, settings, &mut fragments, state)?;
    }
    Ok(())
}

fn observe_preflight_markup<S: NameStorage>(
    event: PreflightEvent<S>,
    settings: DocumentParseSettings,
    fragments: &mut S::Values<FragmentFrame<S>>,
    state: &mut DocumentPreflightState<S>,
) -> Result<(), XmlDocumentError> {
    let storage = state.storage;
    match event {
        PreflightEvent::Start {
            attribute_source,
            namespace_declarations,
        } => {
            let frame = fragments
                .last_mut()
                .expect("active element frame remains registered");
            frame.pending_attribute_source = attribute_source;
            frame.pending_attribute_offset = 0;
            let changes = apply_preflight_namespace_declarations(
                state,
                namespace_declarations,
                settings.namespace_bindings_limit,
            )?;
            state.namespace_scopes.push(changes)?;
            observe_preflight_node(state, settings, false)?;
            state.depth = state.depth.saturating_add(1);
            if state.depth > settings.depth_limit {
                return Err(XmlDocumentError::DocumentTooDeep {
                    maximum: settings.depth_limit,
                    actual: state.depth,
                });
            }
        }
        PreflightEvent::Empty {
            attribute_source,
            namespace_declarations,
        } => {
            let frame = fragments
                .last_mut()
                .expect("active element frame remains registered");
            frame.pending_attribute_source = attribute_source;
            frame.pending_attribute_offset = 0;
            let changes = apply_preflight_namespace_declarations(
                state,
                namespace_declarations,
                settings.namespace_bindings_limit,
            )?;
            observe_preflight_node(state, settings, false)?;
            let actual = state.depth.saturating_add(1);
            if actual > settings.depth_limit {
                return Err(XmlDocumentError::DocumentTooDeep {
                    maximum: settings.depth_limit,
                    actual,
                });
            }
            restore_preflight_namespace_bindings(
                &mut state.active_namespace_bindings,
                changes,
                storage,
            )?;
        }
        PreflightEvent::End => {
            state.depth = state.depth.saturating_sub(1);
            if let Some(changes) = state.namespace_scopes.pop() {
                restore_preflight_namespace_bindings(
                    &mut state.active_namespace_bindings,
                    changes,
                    storage,
                )?;
            }
        }
        _ => unreachable!("non-structural events continue above"),
    }
    Ok(())
}

fn preflight_pi_event<S: NameStorage>(remaining: &str) -> (PreflightEvent<S>, usize) {
    find_bytes(&remaining.as_bytes()[2..], b"?>").map_or(
        (PreflightEvent::Done, remaining.len()),
        |end| {
            let event = if remaining
                .get(2..5)
                .is_some_and(|target| target.eq_ignore_ascii_case("xml"))
                && remaining
                    .as_bytes()
                    .get(5)
                    .is_some_and(u8::is_ascii_whitespace)
            {
                PreflightEvent::Markup
            } else {
                PreflightEvent::Node
            };
            (event, 2 + end + 2)
        },
    )
}

fn scan_preflight_event<S: NameStorage>(
    remaining: &str,
    context: FragmentContext,
    dtd: &InternalDtd<S>,
    state: &mut DocumentPreflightState<S>,
    budget: Option<&XmlParseWorkBudget>,
) -> Result<(PreflightEvent<S>, usize), XmlDocumentError> {
    let storage = state.storage;
    if remaining.is_empty() {
        return Ok((PreflightEvent::Done, 0));
    }
    if context == FragmentContext::Attribute {
        let mut references = general_references(remaining.as_bytes());
        if let Some(name) = references.next() {
            return Ok((
                PreflightEvent::GeneralRef {
                    is_character_reference: is_character_reference(name),
                    name: Some(storage.text(name)?),
                },
                references.consumed(),
            ));
        }
        return Ok((PreflightEvent::Done, remaining.len()));
    }
    if remaining.starts_with("<!--") {
        return Ok(find_bytes(&remaining.as_bytes()[4..], b"-->")
            .map_or((PreflightEvent::Done, remaining.len()), |end| {
                (PreflightEvent::Node, 4 + end + 3)
            }));
    }
    if remaining.starts_with("<![CDATA[") {
        return Ok(find_bytes(&remaining.as_bytes()[9..], b"]]>").map_or(
            (PreflightEvent::Done, remaining.len()),
            |end| {
                (
                    PreflightEvent::CharacterData {
                        xml_whitespace: false,
                    },
                    9 + end + 3,
                )
            },
        ));
    }
    if remaining.starts_with("<?") {
        return Ok(preflight_pi_event(remaining));
    }
    if remaining.starts_with("<!DOCTYPE") {
        if let Some(end) = find_doctype_end(remaining) {
            return Ok((
                PreflightEvent::DocType(Some(storage.text(&remaining[..end])?)),
                end,
            ));
        }
        return Ok((PreflightEvent::Done, remaining.len()));
    }
    if remaining.starts_with("</") {
        return Ok(find_unquoted_byte(remaining.as_bytes(), b'>', 2)
            .map_or((PreflightEvent::Done, remaining.len()), |end| {
                (PreflightEvent::End, end + 1)
            }));
    }
    if remaining.starts_with('<') {
        return scan_preflight_opening(remaining, dtd, state, budget);
    }
    if let Some(reference) = remaining.strip_prefix('&') {
        // XML 1.0 sections 4.4.2 and 4.5 require replacement markup to be
        // processed after character-reference normalization. This conservative
        // resource scan must not swallow markup after a malformed reference;
        // the semantic parser remains responsible for well-formedness.
        // https://www.w3.org/TR/REC-xml/#intern-replacement
        if let Some(end) = reference.find([';', '<', '&'])
            && reference.as_bytes()[end] == b';'
        {
            let name = &reference[..end];
            return Ok((
                PreflightEvent::GeneralRef {
                    name: Some(storage.text(name)?),
                    is_character_reference: is_character_reference(name),
                },
                end + 2,
            ));
        }
        return Ok((
            PreflightEvent::CharacterData {
                xml_whitespace: false,
            },
            1,
        ));
    }
    let end = remaining.find(['<', '&']).unwrap_or(remaining.len());
    let text = &remaining[..end];
    Ok((
        PreflightEvent::CharacterData {
            xml_whitespace: text
                .chars()
                .all(|character| matches!(character, ' ' | '\t' | '\r' | '\n')),
        },
        end,
    ))
}

fn scan_preflight_opening<S: NameStorage>(
    remaining: &str,
    dtd: &InternalDtd<S>,
    state: &mut DocumentPreflightState<S>,
    budget: Option<&XmlParseWorkBudget>,
) -> Result<(PreflightEvent<S>, usize), XmlDocumentError> {
    let storage = state.storage;
    let Some(end) = find_unquoted_byte(remaining.as_bytes(), b'>', 1) else {
        return Ok((PreflightEvent::Done, remaining.len()));
    };
    let opening = &remaining[..=end];
    let (element_name, attributes) = opening_tag_attributes(opening, storage)?;
    let attribute_source =
        element_attribute_reference_source(opening, element_name, &attributes, dtd)?;
    // The frame later revisits this attribute/reference window.
    storage.charge(attribute_source.len())?;
    let namespace_declarations =
        namespace_declarations(element_name, &attributes, dtd, state, budget)?;
    let event = if opening[..opening.len() - 1].trim_end().ends_with('/') {
        PreflightEvent::Empty {
            attribute_source,
            namespace_declarations,
        }
    } else {
        PreflightEvent::Start {
            attribute_source,
            namespace_declarations,
        }
    };
    Ok((event, end + 1))
}

fn is_character_reference(name: &str) -> bool {
    name.starts_with('#') || matches!(name, "amp" | "apos" | "gt" | "lt" | "quot")
}

fn find_doctype_end(doctype: &str) -> Option<usize> {
    let mut quote = None;
    let mut subset_depth = 0usize;
    let bytes = doctype.as_bytes();
    let mut offset = 0;
    while offset < bytes.len() {
        if quote.is_none() && bytes[offset..].starts_with(b"<!--") {
            let end = bytes[offset + 4..]
                .windows(3)
                .position(|window| window == b"-->")?;
            offset += 4 + end + 3;
            continue;
        }
        if quote.is_none() && bytes[offset..].starts_with(b"<?") {
            let end = bytes[offset + 2..]
                .windows(2)
                .position(|window| window == b"?>")?;
            offset += 2 + end + 2;
            continue;
        }
        let byte = bytes[offset];
        match (quote, byte) {
            (None, b'\'' | b'"') => quote = Some(byte),
            (Some(delimiter), current) if delimiter == current => quote = None,
            (None, b'[') => subset_depth = subset_depth.saturating_add(1),
            (None, b']') => subset_depth = subset_depth.saturating_sub(1),
            (None, b'>') if subset_depth == 0 => return Some(offset + 1),
            _ => {}
        }
        offset += 1;
    }
    None
}

struct NamespaceDeclaration<S: NameStorage = NativeXmlStorage> {
    prefix: S::Text,
    is_undeclaration: bool,
}

fn namespace_declarations<S: NameStorage>(
    element_name: &str,
    attributes: &[(&str, &str)],
    dtd: &InternalDtd<S>,
    state: &mut DocumentPreflightState<S>,
    budget: Option<&XmlParseWorkBudget>,
) -> Result<S::Values<NamespaceDeclaration<S>>, XmlDocumentError> {
    let storage = state.storage;
    let mut declarations = storage.values(0)?;
    for &(name, value) in attributes {
        storage.charge(name.len())?;
        let prefix = if name == "xmlns" {
            ""
        } else {
            let Some(prefix) = name.strip_prefix("xmlns:") else {
                continue;
            };
            prefix
        };
        declarations.push(NamespaceDeclaration {
            prefix: storage.text(prefix)?,
            is_undeclaration: namespace_value_expands_to_empty(value, dtd, state, budget)?,
        })?;
    }
    if let Some(defaults) = dtd.attribute_defaults.get(element_name, storage)? {
        for default in &**defaults {
            let mut present = false;
            for &(name, _) in attributes {
                storage.charge(
                    name.len()
                        .min(default.attribute_name.len())
                        .saturating_add(1),
                )?;
                if name == default.attribute_name.as_ref() {
                    present = true;
                    break;
                }
            }
            if present {
                continue;
            }
            storage.charge(default.attribute_name.len())?;
            let prefix = if default.attribute_name.as_ref() == "xmlns" {
                ""
            } else if let Some(prefix) = default.attribute_name.strip_prefix("xmlns:") {
                prefix
            } else {
                continue;
            };
            declarations.push(NamespaceDeclaration {
                prefix: storage.text(prefix)?,
                is_undeclaration: namespace_value_expands_to_empty(
                    &default.value,
                    dtd,
                    state,
                    budget,
                )?,
            })?;
        }
    }
    Ok(declarations)
}

fn namespace_value_expands_to_empty<'a, S: NameStorage>(
    value: &'a str,
    dtd: &'a InternalDtd<S>,
    state: &mut DocumentPreflightState<S>,
    budget: Option<&XmlParseWorkBudget>,
) -> Result<bool, XmlDocumentError> {
    // Namespace declaration values are normalized attributes, so entity replacement precedes the
    // empty default-namespace test: XML 1.0 section 3.3.3 and Namespaces 1.0 section 6.2.
    // https://www.w3.org/TR/xml/#AVNormalize
    // https://www.w3.org/TR/REC-xml-names/#defaulting
    if value.is_empty() {
        return Ok(true);
    }
    if !value.starts_with('&') {
        return Ok(false);
    }
    let storage = state.storage;
    storage.charge(value.len())?;
    let mut pending = storage.values(1)?;
    pending.push(value)?;
    let mut expansions = 0u32;
    while let Some(remaining) = pending.pop() {
        storage.charge(1)?;
        if remaining.is_empty() {
            continue;
        }
        let Some(reference) = remaining.strip_prefix('&') else {
            return Ok(false);
        };
        let Some(end) = reference.find(';') else {
            return Ok(false);
        };
        let name = &reference[..end];
        // XML 1.0 sections 4.1 and 4.6: these references denote a character,
        // never an empty replacement or a caller-defined namespace undeclaration.
        // https://www.w3.org/TR/REC-xml/#sec-predefined-ent
        if name.starts_with('#') || matches!(name, "amp" | "lt" | "gt" | "apos" | "quot") {
            return Ok(false);
        }
        let Some(replacement) = dtd.entities.get(name, storage)? else {
            return Ok(false);
        };
        expansions = expansions.saturating_add(1);
        if expansions > crate::hard_limits::XML_ENTITY_EXPANSION_CEILING {
            return Ok(false);
        }
        charge_entity_expansion_work(state, budget, replacement.len())?;
        storage.charge(replacement.len())?;
        pending.push(&reference[end + 1..])?;
        pending.push(replacement.as_ref())?;
    }
    Ok(true)
}

fn apply_preflight_namespace_declarations<S: NameStorage>(
    state: &mut DocumentPreflightState<S>,
    declarations: S::Values<NamespaceDeclaration<S>>,
    maximum: usize,
) -> Result<S::Values<(S::Text, bool)>, XmlDocumentError> {
    let storage = state.storage;
    let mut changes = storage.values(declarations.len())?;
    for declaration in declarations {
        storage.charge(1)?;
        let was_active = if declaration.is_undeclaration {
            state
                .active_namespace_bindings
                .remove(&declaration.prefix, storage)?
                .is_some()
        } else if state
            .active_namespace_bindings
            .get(&declaration.prefix, storage)?
            .is_some()
        {
            true
        } else {
            state
                .active_namespace_bindings
                .insert(storage.text(&declaration.prefix)?, ())?;
            false
        };
        changes.push((declaration.prefix, was_active))?;
    }
    let actual = state.active_namespace_bindings.len();
    state.peak_namespace_bindings = state.peak_namespace_bindings.max(actual);
    if actual > maximum {
        return Err(XmlDocumentError::Parse(
            ParseError::NamespaceBindingLimitReached { maximum, actual },
        ));
    }
    Ok(changes)
}

fn restore_preflight_namespace_bindings<S: NameStorage>(
    active: &mut S::Names<S::Text, ()>,
    mut changes: S::Values<(S::Text, bool)>,
    storage: S,
) -> Result<(), XmlDocumentError> {
    while let Some((prefix, was_active)) = changes.pop() {
        storage.charge(1)?;
        if was_active {
            if active.get(&prefix, storage)?.is_none() {
                active.insert(prefix, ())?;
            }
        } else {
            active.remove(&prefix, storage)?;
        }
    }
    Ok(())
}

fn element_attribute_reference_source<S: NameStorage>(
    opening: &str,
    element_name: &str,
    attributes: &[(&str, &str)],
    dtd: &InternalDtd<S>,
) -> Result<S::Values<u8>, XmlDocumentError> {
    let storage = dtd.storage;
    storage.charge(opening.len())?;
    let mut source = storage.values(0)?;
    if opening.contains('&') {
        source.extend_copy(opening.as_bytes())?;
    }
    if dtd.attribute_defaults.len() == 0 {
        return Ok(source);
    }

    if let Some(defaults) = dtd.attribute_defaults.get(element_name, storage)? {
        let mut present_attributes = storage.names();
        for &(name, _) in attributes {
            present_attributes.insert(name, ())?;
        }
        for default in &**defaults {
            if present_attributes
                .get(&default.attribute_name, storage)?
                .is_none()
            {
                present_attributes.insert(default.attribute_name.as_ref(), ())?;
                storage.charge(default.value.len())?;
                if default.value.contains('&') {
                    source.push(b' ')?;
                    source.extend_copy(default.value.as_bytes())?;
                }
            }
        }
    }
    Ok(source)
}

type OpeningAttributes<'a, S> = (&'a str, <S as XmlStorage>::Values<(&'a str, &'a str)>);

fn opening_tag_attributes<S: XmlStorage>(
    opening: &str,
    storage: S,
) -> Result<OpeningAttributes<'_, S>, ParseError> {
    let bytes = opening.as_bytes();
    let mut offset = 1usize;
    let name_start = offset;
    while bytes
        .get(offset)
        .is_some_and(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | b'/' | b'>'))
    {
        offset += 1;
    }
    let element_name = &opening[name_start..offset];
    let mut attributes = storage.values(0)?;
    while offset < bytes.len() {
        while bytes
            .get(offset)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        {
            offset += 1;
        }
        if bytes
            .get(offset)
            .is_none_or(|byte| matches!(byte, b'/' | b'>'))
        {
            break;
        }
        let start = offset;
        while bytes
            .get(offset)
            .is_some_and(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | b'='))
        {
            offset += 1;
        }
        if start == offset {
            break;
        }
        let name = &opening[start..offset];
        while bytes
            .get(offset)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        {
            offset += 1;
        }
        if bytes.get(offset) != Some(&b'=') {
            break;
        }
        offset += 1;
        while bytes
            .get(offset)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        {
            offset += 1;
        }
        let Some(delimiter @ (b'\'' | b'"')) = bytes.get(offset).copied() else {
            break;
        };
        offset += 1;
        let value_start = offset;
        while bytes.get(offset).is_some_and(|byte| *byte != delimiter) {
            offset += 1;
        }
        let value = &opening[value_start..offset];
        attributes.push((name, value))?;
        offset = offset.saturating_add(1);
    }
    Ok((element_name, attributes))
}

struct GeneralReferences<'a> {
    value: &'a [u8],
    offset: usize,
}

impl GeneralReferences<'_> {
    fn consumed(&self) -> usize {
        self.offset
    }
}

impl<'a> Iterator for GeneralReferences<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let relative_start = self.value[self.offset..]
                .iter()
                .position(|byte| *byte == b'&')?;
            let start = self.offset + relative_start + 1;
            let Some(relative_end) = self.value[start..].iter().position(|byte| *byte == b';')
            else {
                self.offset = self.value.len();
                return None;
            };
            let end = start + relative_end;
            self.offset = end + 1;
            let name = &self.value[start..end];
            if !name.starts_with(b"#")
                && !matches!(name, b"amp" | b"apos" | b"gt" | b"lt" | b"quot")
                && let Ok(name) = std::str::from_utf8(name)
            {
                return Some(name);
            }
        }
    }
}

fn general_references(value: &[u8]) -> GeneralReferences<'_> {
    GeneralReferences { value, offset: 0 }
}

fn charge_entity_expansion_work<S: NameStorage>(
    state: &mut DocumentPreflightState<S>,
    budget: Option<&XmlParseWorkBudget>,
    bytes: usize,
) -> Result<(), XmlDocumentError> {
    charge_parse_work(budget, bytes)?;
    if budget.is_none() {
        let actual = state.entity_expansion_work.saturating_add(bytes);
        let maximum = crate::hard_limits::XML_ENTITY_EXPANSION_WORK_BYTE_CEILING;
        if actual > maximum {
            return Err(XmlDocumentError::Parse(
                ParseError::EntityExpansionWorkLimitReached { maximum, actual },
            ));
        }
        state.entity_expansion_work = actual;
    }
    Ok(())
}

pub(crate) fn preflight_dom_limits(
    xml: &str,
    options: ParsingOptions,
) -> Result<ParsingOptions, ParseError> {
    let effective = ParsingOptions {
        allow_dtd: options.allow_dtd,
        nodes_limit: options
            .nodes_limit
            .min(crate::hard_limits::XML_DOCUMENT_NODE_CEILING),
    };
    let settings = DocumentParseSettings {
        backend: XmlBackend::default(),
        allow_dtd: effective.allow_dtd,
        nodes_limit: effective.nodes_limit,
        depth_limit: crate::hard_limits::XML_DOCUMENT_DEPTH_CEILING,
        namespace_bindings_limit: crate::hard_limits::XML_NAMESPACE_BINDING_CEILING,
        max_bytes: crate::hard_limits::XML_DOCUMENT_BYTE_CEILING,
    };
    match preflight_document_limits(xml, settings, None) {
        Ok(_) => Ok(effective),
        Err(XmlDocumentError::Parse(error)) => Err(error),
        Err(XmlDocumentError::DocumentTooDeep { maximum, actual }) => {
            Err(ParseError::DepthLimitReached { maximum, actual })
        }
        Err(XmlDocumentError::DocumentTooLarge { maximum, actual }) => {
            Err(ParseError::ByteLimitReached { maximum, actual })
        }
        Err(error) => Err(ParseError::Backend {
            backend: "xml-limit-preflight",
            message: error.to_string(),
        }),
    }
}

fn observe_preflight_node<S: NameStorage>(
    state: &mut DocumentPreflightState<S>,
    settings: DocumentParseSettings,
    character_data: bool,
) -> Result<(), XmlDocumentError> {
    if character_data {
        if state.in_character_data {
            return Ok(());
        }
        state.in_character_data = true;
    }
    state.nodes = state.nodes.saturating_add(1);
    if state.nodes > settings.nodes_limit {
        return Err(XmlDocumentError::Parse(ParseError::NodesLimitReached));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DtdAttributeType {
    Cdata,
    Id,
    Tokenized,
}

fn collect_internal_dtd<S: NameStorage>(
    doctype: &str,
    dtd: &mut InternalDtd<S>,
) -> Result<(), XmlDocumentError> {
    let storage = dtd.storage;
    storage.charge(doctype.len())?;
    storage.charge(doctype.len())?;
    storage.charge(doctype.len())?;
    let mut failure = None;
    visit_internal_dtd(doctype, |declaration| {
        if failure.is_some() {
            return;
        }
        let result = (|| -> Result<(), ParseError> {
            if let Some(declaration) = dtd_declaration_body(declaration, "ENTITY") {
                if let Some((name, value)) = parse_internal_general_entity(declaration)
                    && dtd.entities.get(name, storage)?.is_none()
                {
                    dtd.entities.insert(
                        storage.text(name)?,
                        normalize_internal_entity_value(value, storage)?,
                    )?;
                }
            } else if let Some(declaration) = dtd_declaration_body(declaration, "ATTLIST") {
                let mut attribute_failure = None;
                visit_attribute_declarations(declaration, |element, attribute, _, value| {
                    if attribute_failure.is_some() {
                        return;
                    }
                    let result = (|| -> Result<(), ParseError> {
                        if let Some(value) = value {
                            let default = InternalAttributeDefault {
                                attribute_name: storage.text(attribute)?,
                                value: storage.text(value)?,
                            };
                            if let Some(defaults) =
                                dtd.attribute_defaults.get_mut(element, storage)?
                            {
                                defaults.push(default)?;
                            } else {
                                let mut defaults = storage.values(1)?;
                                defaults.push(default)?;
                                dtd.attribute_defaults
                                    .insert(storage.text(element)?, defaults)?;
                            }
                        }
                        Ok(())
                    })();
                    if let Err(error) = result {
                        attribute_failure = Some(error);
                    }
                });
                if let Some(error) = attribute_failure {
                    return Err(error);
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            failure = Some(error);
        }
    });
    match failure {
        Some(error) => Err(error.into()),
        None => Ok(()),
    }
}

/// Visit actual internal-subset attribute declarations, not declaration-like
/// strings inside comments, PIs, or quoted entity replacement text.
pub(crate) fn visit_dtd_attributes<'a>(
    doctype: &'a str,
    mut visitor: impl FnMut(&'a str, &'a str, DtdAttributeType),
) {
    visit_internal_dtd(doctype, |declaration| {
        if let Some(declaration) = dtd_declaration_body(declaration, "ATTLIST") {
            visit_attribute_declarations(declaration, |element, attribute, kind, _| {
                visitor(element, attribute, kind);
            });
        }
    });
}

fn dtd_declaration_body<'a>(declaration: &'a str, keyword: &str) -> Option<&'a str> {
    // XML 1.0 sections 3.3 [52] and 4.2 [70] require S after the keyword.
    // https://www.w3.org/TR/2008/REC-xml-20081126/#attdecls
    // https://www.w3.org/TR/2008/REC-xml-20081126/#sec-entity-decl
    declaration
        .strip_prefix(keyword)
        .filter(|body| matches!(body.as_bytes().first(), Some(b' ' | b'\t' | b'\r' | b'\n')))
}

fn visit_internal_dtd<'a>(doctype: &'a str, mut visitor: impl FnMut(&'a str)) {
    let Some(subset_start) = find_unquoted_byte(doctype.as_bytes(), b'[', 0) else {
        return;
    };
    let Some(subset_end) = doctype.rfind(']') else {
        return;
    };
    let subset = &doctype[subset_start + 1..subset_end];
    let mut offset = 0;
    let bytes = subset.as_bytes();
    while offset < bytes.len() {
        if bytes[offset..].starts_with(b"<!--") {
            let Some(end) = find_bytes(&bytes[offset + 4..], b"-->") else {
                break;
            };
            offset += 4 + end + 3;
        } else if bytes[offset..].starts_with(b"<?") {
            let Some(end) = find_bytes(&bytes[offset + 2..], b"?>") else {
                break;
            };
            offset += 2 + end + 2;
        } else if bytes[offset..].starts_with(b"<!") {
            let Some(declaration_end) = find_unquoted_byte(bytes, b'>', offset + 2) else {
                break;
            };
            visitor(&subset[offset + 2..declaration_end]);
            offset = declaration_end + 1;
        } else {
            offset += 1;
        }
    }
}

fn visit_attribute_declarations<'a>(
    declaration: &'a str,
    mut visitor: impl FnMut(&'a str, &'a str, DtdAttributeType, Option<&'a str>),
) {
    let bytes = declaration.as_bytes();
    let mut offset = 0;
    skip_dtd_whitespace(bytes, &mut offset);
    let Some(element_name) = consume_dtd_token(declaration, &mut offset) else {
        return;
    };
    loop {
        skip_dtd_whitespace(bytes, &mut offset);
        if offset == bytes.len() {
            break;
        }
        let Some(attribute_name) = consume_dtd_token(declaration, &mut offset) else {
            break;
        };
        skip_dtd_whitespace(bytes, &mut offset);
        let type_start = offset;
        if !consume_attribute_type(declaration, &mut offset) {
            break;
        }
        let kind = match &declaration[type_start..offset] {
            "CDATA" => DtdAttributeType::Cdata,
            "ID" => DtdAttributeType::Id,
            _ => DtdAttributeType::Tokenized,
        };
        skip_dtd_whitespace(bytes, &mut offset);

        if consume_dtd_keyword(declaration, &mut offset, "#REQUIRED")
            || consume_dtd_keyword(declaration, &mut offset, "#IMPLIED")
        {
            visitor(element_name, attribute_name, kind, None);
            continue;
        }
        if consume_dtd_keyword(declaration, &mut offset, "#FIXED") {
            skip_dtd_whitespace(bytes, &mut offset);
        }
        let Some(value) = consume_dtd_quoted_value(declaration, &mut offset) else {
            break;
        };
        visitor(element_name, attribute_name, kind, Some(value));
    }
}

fn skip_dtd_whitespace(bytes: &[u8], offset: &mut usize) {
    while bytes
        .get(*offset)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
    {
        *offset += 1;
    }
}

fn consume_dtd_token<'a>(input: &'a str, offset: &mut usize) -> Option<&'a str> {
    let bytes = input.as_bytes();
    let start = *offset;
    while bytes.get(*offset).is_some_and(|byte| {
        !matches!(
            byte,
            b' ' | b'\t' | b'\r' | b'\n' | b'(' | b')' | b'\'' | b'"'
        )
    }) {
        *offset += 1;
    }
    (start != *offset).then(|| &input[start..*offset])
}

fn consume_attribute_type(input: &str, offset: &mut usize) -> bool {
    let bytes = input.as_bytes();
    if consume_dtd_keyword(input, offset, "NOTATION") {
        skip_dtd_whitespace(bytes, offset);
        return consume_parenthesized_dtd_group(bytes, offset);
    }
    if bytes.get(*offset) == Some(&b'(') {
        return consume_parenthesized_dtd_group(bytes, offset);
    }
    consume_dtd_token(input, offset).is_some()
}

fn consume_parenthesized_dtd_group(bytes: &[u8], offset: &mut usize) -> bool {
    if bytes.get(*offset) != Some(&b'(') {
        return false;
    }
    let mut depth = 0usize;
    while let Some(byte) = bytes.get(*offset).copied() {
        *offset += 1;
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn consume_dtd_keyword(input: &str, offset: &mut usize, keyword: &str) -> bool {
    let remaining = &input[*offset..];
    if !remaining.starts_with(keyword) {
        return false;
    }
    let end = *offset + keyword.len();
    if input
        .as_bytes()
        .get(end)
        .is_some_and(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | b'(' | b'\'' | b'"'))
    {
        return false;
    }
    *offset = end;
    true
}

fn consume_dtd_quoted_value<'a>(input: &'a str, offset: &mut usize) -> Option<&'a str> {
    let bytes = input.as_bytes();
    let quote = *bytes.get(*offset)?;
    if !matches!(quote, b'\'' | b'"') {
        return None;
    }
    let start = *offset + 1;
    let relative_end = bytes[start..].iter().position(|byte| *byte == quote)?;
    let end = start + relative_end;
    *offset = end + 1;
    Some(&input[start..end])
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn parse_internal_general_entity(declaration: &str) -> Option<(&str, &str)> {
    let bytes = declaration.as_bytes();
    let mut offset = 0usize;
    skip_dtd_whitespace(bytes, &mut offset);
    if bytes.get(offset) == Some(&b'%') {
        return None;
    }
    // XML 1.0 section 2.10 production S contains only SP, TAB, CR, and LF. Unicode whitespace
    // remains part of a legal Name and must not split the declaration.
    // https://www.w3.org/TR/xml/#sec-white-space
    let name = consume_dtd_token(declaration, &mut offset)?;
    let separator = offset;
    skip_dtd_whitespace(bytes, &mut offset);
    if offset == separator {
        return None;
    }
    let definition = &declaration[offset..];
    let quote = definition.as_bytes().first().copied()?;
    if !matches!(quote, b'\'' | b'"') {
        // External entities have no replacement text without an explicit
        // resolver, which this crate never installs.
        return None;
    }
    let value_end = definition.as_bytes()[1..]
        .iter()
        .position(|byte| *byte == quote)?
        + 1;
    Some((name, &definition[1..value_end]))
}

fn normalize_internal_entity_value<S: XmlStorage>(
    value: &str,
    storage: S,
) -> Result<S::Text, ParseError> {
    // XML 1.0 §4.4 expands numeric character references while reading the
    // entity declaration. General and predefined entity references remain
    // lexical input for the later replacement-text pass.
    storage.charge(value.len())?;
    storage.charge(value.len())?;
    storage.charge(value.len())?;
    let mut normalized = storage.values(value.len())?;
    let mut offset = 0;
    while let Some(relative_start) = value[offset..].find("&#") {
        let start = offset + relative_start;
        normalized.extend_copy(&value.as_bytes()[offset..start])?;
        let Some(relative_end) = value[start + 2..].find(';') else {
            normalized.extend_copy(&value.as_bytes()[start..])?;
            return storage.finish_bytes(normalized);
        };
        let end = start + 2 + relative_end;
        let digits = &value[start + 2..end];
        let (radix, digits) = digits
            .strip_prefix('x')
            .map_or((10, digits), |digits| (16, digits));
        let replacement = u32::from_str_radix(digits, radix)
            .ok()
            .filter(|codepoint| is_xml_character(*codepoint))
            .and_then(char::from_u32);
        if let Some(replacement) = replacement {
            normalized.extend_copy(replacement.encode_utf8(&mut [0; 4]).as_bytes())?;
        } else {
            normalized.extend_copy(&value.as_bytes()[start..=end])?;
        }
        offset = end + 1;
    }
    normalized.extend_copy(&value.as_bytes()[offset..])?;
    storage.finish_bytes(normalized)
}

const fn is_xml_character(codepoint: u32) -> bool {
    matches!(
        codepoint,
        0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x1_0000..=0x10_FFFF
    )
}

fn find_unquoted_byte(bytes: &[u8], needle: u8, start: usize) -> Option<usize> {
    let mut quote = None;
    for (index, byte) in bytes.iter().copied().enumerate().skip(start) {
        match byte {
            b'\'' | b'"' => match quote {
                Some(active) if active == byte => quote = None,
                None => quote = Some(byte),
                Some(_) => {}
            },
            _ if quote.is_none() && byte == needle => return Some(index),
            _ => {}
        }
    }
    None
}

fn parse_semantic_document(
    source: &str,
    settings: DocumentParseSettings,
) -> Result<(Document<'_>, DocumentMetrics), XmlDocumentError> {
    let document = Document::parse_after_limit_preflight_with_backend(
        source,
        ParsingOptions {
            allow_dtd: settings.allow_dtd,
            nodes_limit: settings.nodes_limit,
        },
        settings.backend,
    )
    .map_err(XmlDocumentError::Parse)?;
    let metrics = validate_document_metrics(&document, settings.depth_limit)?;
    Ok((document, metrics))
}

fn validate_document_metrics(
    document: &Document<'_>,
    maximum: usize,
) -> Result<DocumentMetrics, XmlDocumentError> {
    validate_document_metrics_in(document, maximum, NativeXmlStorage)
}

fn validate_document_metrics_in<D: XmlStorage, S: XmlStorage>(
    document: &Document<'_, D>,
    maximum: usize,
    storage: S,
) -> Result<DocumentMetrics, XmlDocumentError> {
    // Node IDs follow document order, so each parent's depth has already been
    // recorded. This keeps the compatibility path linear instead of walking
    // every ancestor chain independently.
    let mut depths = storage.values(document.descendants().len())?;
    let mut node_count = 0;
    let mut max_depth = 0;
    for node in document.descendants() {
        storage.charge(1)?;
        node_count += 1;
        let parent_depth = node
            .parent()
            .and_then(|parent| depths.get(parent.id().get_usize()))
            .copied()
            .unwrap_or(0);
        let depth = parent_depth + usize::from(node.is_element());
        let node_index = node.id().get_usize();
        debug_assert_eq!(depths.len(), node_index);
        depths.push(depth)?;
        max_depth = max_depth.max(depth);
        if depth > maximum {
            return Err(XmlDocumentError::DocumentTooDeep {
                maximum,
                actual: depth,
            });
        }
    }
    Ok(DocumentMetrics {
        node_count,
        max_depth,
    })
}

fn own_bounded_xml(
    xml: impl AsRef<str> + Into<String>,
    maximum: usize,
) -> Result<String, XmlDocumentError> {
    let actual = xml.as_ref().len();
    if actual > maximum {
        return Err(XmlDocumentError::DocumentTooLarge { maximum, actual });
    }
    Ok(xml.into())
}

fn decode_owned_xml(
    bytes: &[u8],
    maximum: usize,
    budget: Option<&XmlParseWorkBudget>,
) -> Result<String, XmlDocumentError> {
    decode_xml_with_budget(bytes, maximum, budget).map(Cow::into_owned)
}

pub(crate) fn decode_xml_with_budget<'a>(
    bytes: &'a [u8],
    maximum: usize,
    budget: Option<&XmlParseWorkBudget>,
) -> Result<Cow<'a, str>, XmlDocumentError> {
    if bytes.len() > maximum {
        return Err(XmlDocumentError::DocumentTooLarge {
            maximum,
            actual: bytes.len(),
        });
    }
    // Decoding is an input-sized pass, not free preparation for XML parsing.
    // Charge it before encoding detection/transcoding and retain that charge
    // in the same sticky budget used by preflight and semantic construction.
    charge_parse_work(budget, bytes.len())?;
    xml_sec_xml_input::decode_xml_bounded(bytes, None, maximum).map_err(|error| match error {
        xml_sec_xml_input::Error::DecodedLimit { actual, .. } => {
            XmlDocumentError::DocumentTooLarge { maximum, actual }
        }
        error => XmlDocumentError::Encoding(error),
    })
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
fn document_requires_internal_dtd(
    xml: &str,
    settings: DocumentParseSettings,
    budget: Option<&XmlParseWorkBudget>,
) -> Result<bool, XmlDocumentError> {
    // Parse provenance records what the source actually requires, not merely
    // whether its creator used a permissive policy. This lets a later strict
    // operation accept ordinary XML while rejecting DTD-dependent documents.
    if !settings.allow_dtd {
        return Ok(false);
    }
    charge_semantic_parser_work(budget, xml.len())?;
    Ok(Document::parse_after_limit_preflight_with_backend(
        xml,
        ParsingOptions {
            allow_dtd: false,
            nodes_limit: settings.nodes_limit,
        },
        settings.backend,
    )
    .is_err())
}

/// What a node replacement must leave in its parent.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ReplacementShape {
    /// Exactly one element, beside whitespace, comments and processing instructions.
    SingleElement,
    /// Any content that is well-formed in the parent context.
    Fragment,
}

/// Decoded byte lengths of the text siblings around a replaced node.
#[derive(Clone, Copy)]
struct FoldedText {
    before: usize,
    after: usize,
}

/// Check on a parsed candidate that the bytes at `slot` are complete children
/// of the parent (`None`: the document node) that held the replaced node.
///
/// The prefix before `slot` is unchanged, so its tokens still end at
/// `slot.start`. A parent that spans exactly its projected range keeps every
/// end tag of the replacement inside itself. A child that crosses the slot
/// boundary can only be text folded with a neighbour; its part inside the slot
/// must end on a token boundary, otherwise markup opened by the replacement
/// (CDATA, a reference) would be closed by the neighbour.
fn validate_replacement_slot(
    xml: &str,
    document: &Document<'_>,
    slot: std::ops::Range<usize>,
    parent: Option<std::ops::Range<usize>>,
    folded: FoldedText,
    shape: ReplacementShape,
) -> Result<(), XmlDocumentError> {
    let escaped = || {
        XmlDocumentError::InvalidReplacement(
            "replacement escaped its structural validation boundary".into(),
        )
    };
    let not_single_element = || {
        XmlDocumentError::InvalidReplacement(
            "element replacement must contain exactly one element".into(),
        )
    };
    let mut container = document.root();
    if let Some(parent) = parent {
        while !(container.is_element() && container.range() == parent) {
            container = container
                .children()
                .find(|child| {
                    let range = child.range();
                    child.is_element() && range.start <= parent.start && parent.end <= range.end
                })
                .ok_or_else(escaped)?;
        }
    }
    let mut elements = 0_usize;
    let mut covered = slot.start;
    for child in container.children() {
        let range = child.range();
        if range.end <= slot.start {
            continue;
        }
        if range.start >= slot.end {
            break;
        }
        let part = range.start.max(slot.start)..range.end.min(slot.end);
        // Nodes expanded from one entity reference share its range.
        if !leaves_no_node(&xml[covered..part.start.max(covered)]) {
            return Err(escaped());
        }
        covered = covered.max(part.end);
        if part != range {
            if !child.is_text() || !text_tokens_complete(&xml[part]) {
                return Err(escaped());
            }
            if shape == ReplacementShape::SingleElement {
                // With every token complete, the folded neighbours keep their
                // decoded values, so the replacement's text is what remains
                // between them.
                let value = child.text().unwrap_or_default();
                let start = if range.start < slot.start {
                    folded.before
                } else {
                    0
                };
                let end = if range.end > slot.end {
                    value.len().checked_sub(folded.after)
                } else {
                    Some(value.len())
                };
                let own = end
                    .and_then(|end| value.get(start..end))
                    .ok_or_else(escaped)?;
                if !own.trim().is_empty() {
                    return Err(not_single_element());
                }
            }
        } else if child.is_element() {
            elements += 1;
        } else if child.is_text() {
            if shape == ReplacementShape::SingleElement
                && !child.text().is_none_or(|text| text.trim().is_empty())
            {
                return Err(not_single_element());
            }
        } else if !child.is_comment() && !child.is_pi() {
            return Err(escaped());
        }
    }
    if !leaves_no_node(&xml[covered..slot.end]) {
        return Err(escaped());
    }
    if shape == ReplacementShape::SingleElement && elements != 1 {
        return Err(not_single_element());
    }
    Ok(())
}

/// Whether character data starting on a token boundary also ends on one: every
/// CDATA section and reference it opens is closed inside it.
fn text_tokens_complete(text: &str) -> bool {
    scan_text_tokens(text, |_| true)
}

/// Whether source bytes no node covers are markup that leaves no node: whitespace
/// the parser drops at document level, or complete references to an empty entity
/// (XML 1.0 section 2.3 [9] permits an empty entity value).
fn leaves_no_node(source: &str) -> bool {
    scan_text_tokens(source, |literal| literal.trim().is_empty())
}

/// Walk character data token by token: every CDATA section and reference must
/// close inside `text`, and `literal` must accept each run of plain characters.
fn scan_text_tokens(text: &str, literal: impl Fn(&str) -> bool) -> bool {
    let mut rest = text;
    while let Some(start) = rest.find(['&', '<']) {
        if !literal(&rest[..start]) {
            return false;
        }
        rest = &rest[start..];
        let close = if rest.starts_with("<![CDATA[") {
            "]]>"
        } else if rest.starts_with('&') {
            ";"
        } else {
            return false;
        };
        let Some(end) = rest.find(close) else {
            return false;
        };
        rest = &rest[end + close.len()..];
    }
    literal(rest)
}

fn wrapped_fragment(replacement: &str) -> String {
    format!("{VALIDATION_WRAPPER_OPEN}{replacement}{VALIDATION_WRAPPER_CLOSE}")
}

fn strip_validation_wrapper_namespace_binding(
    error: XmlDocumentError,
    settings: DocumentParseSettings,
) -> XmlDocumentError {
    match error {
        XmlDocumentError::Parse(ParseError::NamespaceBindingLimitReached { actual, .. }) => {
            // The temporary wrapper contributes one binding that the committed document lacks.
            XmlDocumentError::Parse(ParseError::NamespaceBindingLimitReached {
                maximum: settings.namespace_bindings_limit,
                actual: actual.saturating_sub(1),
            })
        }
        error => error,
    }
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

fn validate_wrappers(
    parsed: &ParsedDocument<'_>,
    expected_ranges: &[std::ops::Range<usize>],
) -> Result<(), XmlDocumentError> {
    let mut remaining = expected_ranges
        .iter()
        .map(|range| (range.start, range.end))
        .collect::<HashSet<_>>();
    for node in parsed
        .document
        .descendants()
        .filter(|node| node.has_tag_name((VALIDATION_WRAPPER_NS, "wrapper")))
    {
        let range = node.range();
        remaining.remove(&(range.start, range.end));
    }
    if remaining.is_empty() {
        Ok(())
    } else {
        Err(XmlDocumentError::InvalidReplacement(
            "replacement escaped its structural validation boundary".into(),
        ))
    }
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
                if !crate::xml::is_id_attribute(node, attribute, &[])
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
mod replacement_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    // `with_view` requires a late-bound view lifetime; an inherent method item
    // fixes the impl lifetime too early to satisfy that higher-ranked contract.
    fn retained_root(view: DocumentView<'_>) -> NodeIdentity {
        view.root_element()
    }

    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    fn retained_node_count(view: DocumentView<'_>) -> usize {
        view.node_count()
    }

    #[cfg(feature = "xmldsig")]
    #[test]
    fn current_query_parser_preserves_semantics_and_refuses_unfunded_dom() {
        // All actual backend passes and their semantic projection must retain
        // current Work/capacity, including the borrowed UTF-8 input path.
        use crate::xml::dom::storage::Accounted;
        use structured_asn1::{
            Encoding, Limits, Parser,
            memory::{Memory, MemoryAccount, MemoryError},
        };
        fn describe<S: XmlStorage>(
            node: crate::xml::dom::Node<'_, '_, S>,
        ) -> (
            crate::xml::dom::NodeType,
            String,
            Option<String>,
            Option<String>,
        ) {
            (
                node.node_type(),
                node.tag_name().name().to_string(),
                node.tag_name().namespace().map(str::to_string),
                node.text().map(str::to_string),
            )
        }
        for backend in XmlBackend::available() {
            for depth in [126, 127, 128, 129, 130] {
                let source = format!(
                    "{}<p:leaf xmlns:p='urn:p' xml:id='target' p:a='value'>text</p:leaf>{}",
                    "<r>".repeat(depth),
                    "</r>".repeat(depth)
                );
                let settings = DocumentParseSettings::default().with_backend(backend);
                let native = parse_borrowed_with_settings_and_budget(&source, settings, None)
                    .expect("native boundary XML parses");
                let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(1 << 24, 1 << 28)));
                let parser = Parser::der(memory.clone());
                let reader = parser.read(&[], 0).expect("empty execution cursor");
                let execution = reader.execution();
                let paid = parse_borrowed_in(&source, settings, None, Accounted(&execution))
                    .expect("funded boundary XML parses");
                let actual: Vec<_> = paid.descendants().map(describe).collect();
                let expected: Vec<_> = native.descendants().map(describe).collect();
                assert_eq!(actual, expected, "{backend:?} at depth {depth}");
                let leaf = paid
                    .descendants()
                    .find(|node| node.has_tag_name(("urn:p", "leaf")))
                    .expect("expanded leaf retained");
                assert_eq!(leaf.attribute(("urn:p", "a")), Some("value"));
                assert!(
                    leaf.attributes()
                        .find(|attribute| attribute.name() == "id")
                        .expect("xml:id retained")
                        .is_id()
                );
                assert!(memory.used() > source.len());
                drop(paid);
                assert_eq!(memory.used(), 0);
            }

            let source = format!("<root>{}</root>", "x".repeat(64 * 1024));
            for (capacity, local, aggregate, expected) in [
                (4096, 1 << 28, 1 << 28, MemoryError::LimitExceeded),
                (1 << 24, 0, 1 << 28, MemoryError::WorkExceeded),
                (1 << 24, 1 << 28, 0, MemoryError::WorkExceeded),
            ] {
                let memory =
                    Memory::new(std::sync::Arc::new(MemoryAccount::new(capacity, aggregate)));
                let parser = Parser::new(
                    Encoding::Der,
                    Limits {
                        max_work: local,
                        ..Default::default()
                    },
                    memory.clone(),
                );
                let reader = parser.read(&[], 0).expect("empty execution cursor");
                let execution = reader.execution();
                let result = parse_borrowed_in(
                    &source,
                    DocumentParseSettings::default().with_backend(backend),
                    None,
                    Accounted(&execution),
                );
                assert!(
                    matches!(result, Err(XmlDocumentError::Parse(ParseError::SharedExecution(error))) if error == expected),
                    "{backend:?}: {result:?}"
                );
                assert_eq!(memory.used(), 0);
            }
        }
    }

    #[cfg(feature = "xmldsig")]
    #[test]
    fn current_query_parser_boundary_rejections_do_not_change_with_depth() {
        // Depth must not select different namespace/well-formedness rules or
        // turn a construction refusal into an ordinary XML rejection.
        use crate::xml::dom::storage::Accounted;
        use structured_asn1::{
            Parser,
            memory::{Memory, MemoryAccount},
        };
        for backend in XmlBackend::available() {
            for depth in [126, 127, 128, 129, 130] {
                for (body, tail) in [
                    ("<p:leaf/>", ""),
                    (
                        "<leaf xmlns:p='urn:x' xmlns:q='urn:x' p:a='1' q:a='2'/>",
                        "",
                    ),
                    ("<leaf xmlns:xml='urn:wrong'/>", ""),
                    ("<leaf xmlns:p='http://www.w3.org/2000/xmlns/'/>", ""),
                    ("<leaf xmlns:p=''/>", ""),
                    ("<leaf>&undeclared;</leaf>", ""),
                    ("<leaf/>", "<second/>"),
                ] {
                    let source = format!(
                        "{}{body}{}{tail}",
                        "<r>".repeat(depth),
                        "</r>".repeat(depth)
                    );
                    let settings = DocumentParseSettings::default().with_backend(backend);
                    assert!(
                        parse_borrowed_with_settings_and_budget(&source, settings, None).is_err(),
                        "{backend:?}, depth {depth}, {body}, trailing {tail}"
                    );
                    let memory =
                        Memory::new(std::sync::Arc::new(MemoryAccount::new(1 << 24, 1 << 28)));
                    let parser = Parser::der(memory.clone());
                    let cursor = parser.read(&[], 0).expect("empty current cursor");
                    let execution = cursor.execution();
                    let result = parse_borrowed_in(&source, settings, None, Accounted(&execution));
                    assert!(result.is_err(), "{backend:?}, depth {depth}, {body}");
                    assert!(
                        !matches!(
                            &result,
                            Err(XmlDocumentError::Parse(
                                ParseError::SharedExecution(_) | ParseError::AllocationFailed
                            ))
                        ),
                        "funded malformed input must not exhaust construction: {result:?}"
                    );
                    drop(result);
                    assert_eq!(memory.used(), 0);
                }
            }
        }
    }

    #[cfg(feature = "xmldsig")]
    #[test]
    fn current_query_limit_preflight_has_exact_work_and_capacity_admission() {
        // Namespace undo, entity/default expansion and temporary name queries
        // must all spend this query's Work, not its roomy aggregate account.
        use crate::xml::dom::storage::Accounted;
        use structured_asn1::{
            Encoding, Limits, Parser,
            memory::{Memory, MemoryAccount, MemoryError},
        };

        fn run(
            source: &str,
            max_work: u64,
            capacity: usize,
        ) -> (Result<usize, XmlDocumentError>, Memory) {
            let memory = Memory::new(std::sync::Arc::new(MemoryAccount::new(capacity, 1 << 28)));
            let parser = Parser::new(
                Encoding::Der,
                Limits {
                    max_work,
                    ..Default::default()
                },
                memory.clone(),
            );
            let reader = parser.read(&[], 0).expect("empty execution cursor");
            let work = reader.execution();
            let result = preflight_document_limits_in(
                source,
                DocumentParseSettings::new(true, 1024, source.len()),
                None,
                Accounted(&work),
            );
            (result, memory)
        }

        // No lookup below misses against a non-empty dictionary: such a miss
        // compares keys only on a randomly seeded tag collision, so two runs'
        // exact work would differ.
        for source in [
            "<r xmlns:p='urn:outer'><c xmlns:p='urn:inner'/><c/></r>",
            "<!DOCTYPE c [<!ENTITY x 'value'><!ATTLIST c a CDATA '&x;'>]><c><c/><c a='literal'/></c>",
            "<!DOCTYPE r [<!ENTITY x '<c xmlns:p=\"urn:p\"/>'>]><r>&x;</r>",
        ] {
            let expected = preflight_document_limits(
                source,
                DocumentParseSettings::new(true, 1024, source.len()),
                None,
            )
            .expect("native preflight accepts fixed XML");
            let (result, measured) = run(source, 1 << 28, 1 << 20);
            assert_eq!(result.expect("ample current work"), expected);
            assert_eq!(measured.used(), 0);
            let needed = measured.work_used() as u64;
            assert!(needed > 0);

            let (result, exact) = run(source, needed, 1 << 20);
            assert_eq!(result.expect("exact current work"), expected);
            assert_eq!(exact.used(), 0);
            assert_eq!(exact.work_used() as u64, needed);

            for maximum in [0, needed - 1] {
                let (result, denied) = run(source, maximum, 1 << 20);
                assert!(matches!(
                    result,
                    Err(XmlDocumentError::Parse(ParseError::SharedExecution(
                        MemoryError::WorkExceeded
                    )))
                ));
                assert_eq!(denied.used(), 0);
            }
            let (result, denied) = run(source, 1 << 28, 0);
            assert!(matches!(
                result,
                Err(XmlDocumentError::Parse(ParseError::SharedExecution(
                    MemoryError::LimitExceeded
                )))
            ));
            assert_eq!(denied.used(), 0);
        }
    }

    #[test]
    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    fn namespace_preflight_error_is_a_policy_violation() {
        // Initial parsing and retained-document validation must report the same typed limit.
        let settings = DocumentParseSettings {
            namespace_bindings_limit: 1,
            ..Default::default()
        };
        let error =
            preflight_document_limits(r#"<root xmlns:a="urn:a" xmlns:b="urn:b"/>"#, settings, None)
                .expect_err("namespace ceiling must be enforced");
        assert!(matches!(
            error.into_policy_violation(settings),
            Ok(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_NAMESPACE_BINDINGS,
                maximum: 1,
                actual: 2,
            })
        ));
    }

    #[test]
    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    fn review_owned_document_enforces_namespace_policy() {
        // A retained parse cannot grant authority beyond the current operation policy.
        let document = XmlDocument::parse(r#"<root xmlns:a="urn:a" xmlns:b="urn:b"/>"#)
            .expect("permissive parse accepts both namespace bindings");
        let resources = crate::policy::ResourcePolicy {
            max_xml_namespace_bindings: 1,
            ..Default::default()
        };
        assert!(matches!(
            document
                .validate_operation_policy(crate::policy::XmlInputPolicy::default(), &resources),
            Err(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_NAMESPACE_BINDINGS,
                actual: 2,
                maximum: 1
            })
        ));
    }

    #[test]
    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    fn namespace_policy_tracks_peak_scope_and_mutations() {
        // Disjoint sibling scopes are not cumulative; replacing a node must refresh the
        // retained peak, so a previously accepted document cannot bypass stricter policy.
        let mut document = XmlDocument::parse(
            r#"<root><a xmlns:p="urn:p" ID="target"/><b xmlns:q="urn:q"/></root>"#,
        )
        .expect("disjoint namespace scopes parse");
        let resources = crate::policy::ResourcePolicy {
            max_xml_namespace_bindings: 1,
            ..Default::default()
        };
        let policy = crate::policy::XmlInputPolicy::default();
        document
            .validate_operation_policy(policy, &resources)
            .expect("sibling scopes fit a one-binding limit");
        let target =
            document.with_view(|view| view.node_for_id("target", &[]).expect("target is indexed"));
        document
            .replace_element(
                target,
                r#"<a xmlns:p="urn:p" xmlns:q="urn:q" ID="target"/>"#,
            )
            .expect("replacement fits the original parse settings");
        assert!(matches!(
            document.validate_operation_policy(policy, &resources),
            Err(crate::policy::PolicyViolation::ResourceLimit { actual: 2, .. })
        ));
        let target = document.with_view(|view| {
            view.node_for_id("target", &[])
                .expect("replacement target is indexed")
        });
        document
            .replace_element(target, "<a/>")
            .expect("bindings can be removed");
        document
            .validate_operation_policy(policy, &resources)
            .expect("removed namespace bindings do not remain in the peak metric");
    }

    #[test]
    fn byte_input_decoding_is_identical_for_every_semantic_backend() {
        // Encoding is resolved before backend selection, so parser choice cannot
        // change which external XML byte sequences are accepted or interpreted.
        let latin1 = b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><root>caf\xe9</root>";
        for backend in XmlBackend::available() {
            let document = XmlDocument::parse_bytes_with_backend(latin1, backend)
                .expect("declared Latin-1 XML must parse with every backend");
            assert!(document.as_xml().contains("encoding=\"UTF-8\""));
            document.with_view(|view| {
                assert_eq!(view.document().root_element().text(), Some("café"));
            });
        }
    }

    #[test]
    fn every_semantic_backend_rejects_the_same_encoding_conflict() {
        // Encoding validation happens before backend dispatch, so a parser
        // implementation cannot reinterpret contradictory external bytes.
        let mut bytes = vec![0xff, 0xfe];
        bytes.extend(
            "<?xml version=\"1.0\" encoding=\"UTF-16BE\"?><root/>"
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        );
        for backend in XmlBackend::available() {
            assert!(matches!(
                XmlDocument::parse_bytes_with_backend(&bytes, backend),
                Err(XmlDocumentError::Encoding(
                    xml_sec_xml_input::Error::ConflictingEncoding(_)
                ))
            ));
        }
    }

    #[cfg(feature = "xmldsig")]
    #[test]
    fn byte_decoding_work_is_rejected_before_encoding_validation() {
        // An exhausted operation must reject before even invalid UTF-16 is
        // decoded, for both default and explicitly selected backends.
        let bytes = [0xff, 0xfe, 0];
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.resources.max_xml_parse_work_bytes = 0;
        let assert_work_error = |result: Result<XmlDocument, XmlDocumentError>| {
            assert!(matches!(
                result,
                Err(XmlDocumentError::Policy(
                    crate::policy::PolicyViolation::ResourceLimit {
                        resource: crate::policy::resource_name::XML_PARSE_WORK_BYTES,
                        maximum: 0,
                        actual: 3,
                    }
                ))
            ));
        };
        assert_work_error(XmlDocument::parse_bytes_with_policy(&bytes, &policy));
        for backend in XmlBackend::available() {
            assert_work_error(XmlDocument::parse_bytes_with_policy_and_backend(
                &bytes, &policy, backend,
            ));
        }
    }

    #[cfg(feature = "xmldsig")]
    #[test]
    fn byte_decoding_and_parsing_share_one_work_allowance() {
        // UTF-16 decoding consumes its source bytes; preflight and the two
        // parser/projection passes then consume normalized UTF-8 bytes.
        let xml = "<r/>";
        let mut bytes = vec![0xff, 0xfe];
        bytes.extend(xml.encode_utf16().flat_map(u16::to_le_bytes));
        let required = bytes.len() + 3 * xml.len();
        for backend in XmlBackend::available() {
            let mut policy = crate::policy::VerificationPolicy::default();
            policy.resources.max_xml_parse_work_bytes = required - 1;
            assert!(matches!(
                XmlDocument::parse_bytes_with_policy_and_backend(&bytes, &policy, backend),
                Err(XmlDocumentError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_PARSE_WORK_BYTES,
                    maximum, actual,
                })) if maximum == required - 1 && actual == required
            ));
            policy.resources.max_xml_parse_work_bytes = required;
            assert_eq!(
                XmlDocument::parse_bytes_with_policy_and_backend(&bytes, &policy, backend)
                    .expect("exact aggregate work must suffice")
                    .as_xml(),
                xml
            );
        }
    }

    #[test]
    fn selected_backend_builds_the_retained_semantic_projection() {
        let settings = DocumentParseSettings::default();
        let xml =
            r#"<root xmlns:p="urn:test"><p:item ID="target"><![CDATA[value]]></p:item></root>"#;
        let retained = build_semantic_cell(xml.to_owned(), settings, 1)
            .expect("selected backend semantic projection must parse");
        retained.with_dependent(|_, parsed| {
            assert!(parsed.indexes.default_ids.contains_key("target"));
            assert_eq!(
                parsed
                    .document
                    .root_element()
                    .first_element_child()
                    .expect("fixture must contain the indexed child element")
                    .text(),
                Some("value")
            );
        });
    }

    #[cfg(feature = "xml-backend-xmloxide")]
    #[test]
    fn xmloxide_attribute_capacity_is_independent_of_retained_node_limit() {
        // Retained nodes and per-element attributes are different resources.
        // A tight node limit must not make the selected backend reject an
        // otherwise bounded element that the semantic projection accepts.
        let xml = r#"<root a="1" b="2" c="3"/>"#;
        let settings = DocumentParseSettings::new(false, 2, xml.len());
        build_cell(xml.to_owned(), settings, None)
            .expect("attributes must not consume the retained node allowance");
    }

    #[test]
    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    fn node_preflight_rejects_wide_input_before_any_dom_pass() {
        // The allowance covers only the streaming preflight. Reaching either
        // DOM would exhaust parser work before it could report the node bound.
        let xml = "<root><first/><second/></root>";
        let resources = crate::policy::ResourcePolicy {
            max_xml_parse_work_bytes: xml.len(),
            ..crate::policy::ResourcePolicy::default()
        };
        let budget = XmlParseWorkBudget::from_resources(&resources);
        let settings = DocumentParseSettings::new(false, 3, xml.len());

        assert!(matches!(
            build_cell(xml.to_owned(), settings, Some(&budget)),
            Err(XmlDocumentError::Parse(ParseError::NodesLimitReached))
        ));
    }

    #[test]
    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    fn namespace_predefined_references_do_not_expand_dtd_declarations() {
        // Predefined/numeric references always yield a character, never an undeclaration.
        // Even a declared predefined entity must not consume DTD expansion work here.
        let mut dtd = InternalDtd::default();
        Names::insert(&mut dtd.entities, "amp".to_owned(), "&#38;#38;".to_owned())
            .expect("fixed entity declaration fits native storage");
        for value in [
            "&amp;", "&#38;", "&#x26;", "&lt;", "&gt;", "&quot;", "&apos;",
        ] {
            let mut state = DocumentPreflightState::default();
            let budget = XmlParseWorkBudget::with_limit(0);
            assert!(
                !namespace_value_expands_to_empty(value, &dtd, &mut state, Some(&budget))
                    .expect("character references require no DTD expansion")
            );
            assert_eq!(state.entity_expansion_work, 0);
        }
    }

    #[test]
    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    fn namespace_entity_chain_consumes_parse_work_budget() {
        // Namespace normalization expands general entities before testing an undeclaration.
        // That preflight path must share the same sticky parser-work budget as content expansion.
        let xml = r#"<!DOCTYPE root [<!ENTITY first "&second;"><!ENTITY second "">]><root xmlns="&first;"/>"#;
        let resources = crate::policy::ResourcePolicy {
            max_xml_parse_work_bytes: xml.len() + "&second;".len() - 1,
            ..crate::policy::ResourcePolicy::default()
        };
        let budget = XmlParseWorkBudget::from_resources(&resources);
        let settings = DocumentParseSettings::new(true, 8, xml.len());

        assert!(matches!(
            preflight_document_limits(xml, settings, Some(&budget)),
            Err(XmlDocumentError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_PARSE_WORK_BYTES,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn internal_entity_names_use_xml_whitespace_delimiters_only() {
        // XML 1.0 sections 2.3 and 2.10 make U+1680 a Name character, not production S.
        // https://www.w3.org/TR/xml/#NT-Name
        // https://www.w3.org/TR/xml/#sec-white-space
        assert_eq!(
            parse_internal_general_entity(" \u{1680} 'value'"),
            Some(("\u{1680}", "value"))
        );
    }

    #[test]
    fn node_preflight_counts_contiguous_character_data_once() {
        // Entity references and CDATA split the lexical event stream, but
        // roxmltree retains the contiguous character data as one text node.
        let xml = "<root>a&amp;<![CDATA[b]]>&#99;</root>";
        let exact_settings = DocumentParseSettings::new(false, 3, xml.len());

        build_cell(xml.to_owned(), exact_settings, None)
            .expect("the exact retained semantic node count must be accepted");
        assert!(matches!(
            build_cell(
                xml.to_owned(),
                DocumentParseSettings::new(false, 2, xml.len()),
                None,
            ),
            Err(XmlDocumentError::Parse(ParseError::NodesLimitReached))
        ));
    }

    #[test]
    fn node_preflight_excludes_document_boundary_whitespace() {
        // XML Misc whitespace outside the document element is not retained as
        // a roxmltree text node and must not consume semantic-node policy.
        let xml = " \n<root/>\n ";
        let settings = DocumentParseSettings::new(false, 2, xml.len());

        preflight_document_limits(xml, settings, None)
            .expect("document plus root element must fit the exact node ceiling");
    }

    #[test]
    fn node_preflight_continues_after_explicit_end_tags() {
        // The lexical reader is recreated at each event boundary. A closing tag
        // must still be observed so later siblings cannot bypass node policy.
        let xml = "<root><first></first><second/></root>";
        let settings = DocumentParseSettings::new(false, 3, xml.len());

        assert!(matches!(
            preflight_document_limits(xml, settings, None),
            Err(XmlDocumentError::Parse(ParseError::NodesLimitReached))
        ));
    }

    #[test]
    fn depth_preflight_expands_nested_internal_entity_markup() {
        // Entity replacement markup contributes real retained element depth.
        // The streaming guard must reject it before either DOM parser allocates
        // the expanded tree, including references nested inside replacements.
        let xml = r#"<!DOCTYPE root [
            <!ENTITY inner "<b><c/></b>">
            <!ENTITY deep "<a>&inner;</a>">
        ]><root>&deep;</root>"#;
        let settings = DocumentParseSettings::new_with_depth(true, 32, 3, xml.len());

        assert!(matches!(
            preflight_document_limits(xml, settings, None),
            Err(XmlDocumentError::DocumentTooDeep {
                maximum: 3,
                actual: 4,
            })
        ));

        let exact_settings = DocumentParseSettings::new_with_depth(true, 32, 4, xml.len());
        preflight_document_limits(xml, exact_settings, None)
            .expect("expanded markup at the exact depth boundary must be accepted");
    }

    #[test]
    fn namespace_preflight_counts_bindings_inside_entity_replacements() {
        // Entity replacement text becomes part of the document's namespace context, so it must
        // consume the same active-binding ceiling as literal markup before a DOM is allocated.
        let maximum = crate::hard_limits::XML_NAMESPACE_BINDING_CEILING;
        let mut declarations = String::new();
        for index in 0..=maximum {
            write!(declarations, r#" xmlns:p{index}="urn:{index}""#)
                .expect("namespace declaration");
        }
        let xml = format!(
            "<!DOCTYPE root [<!ENTITY expanded '<child{declarations}/>'>]><root>&expanded;</root>"
        );
        let settings = DocumentParseSettings::new_with_depth(true, 16, 4, xml.len());

        assert!(matches!(
            preflight_document_limits(&xml, settings, None),
            Err(XmlDocumentError::Parse(ParseError::NamespaceBindingLimitReached {
                maximum: observed_maximum,
                actual,
            })) if observed_maximum == maximum && actual == maximum + 1
        ));
    }

    #[test]
    fn namespace_preflight_accepts_entity_replacement_at_exact_ceiling() {
        let maximum = crate::hard_limits::XML_NAMESPACE_BINDING_CEILING;
        let mut declarations = String::new();
        for index in 0..maximum {
            write!(declarations, r#" xmlns:p{index}="urn:{index}""#)
                .expect("namespace declaration");
        }
        let xml = format!(
            "<!DOCTYPE root [<!ENTITY expanded '<child{declarations}/>'>]><root>&expanded;</root>"
        );
        let settings = DocumentParseSettings::new_with_depth(true, 16, 4, xml.len());

        preflight_document_limits(&xml, settings, None)
            .expect("the exact expanded namespace-binding boundary is accepted");
    }

    #[test]
    fn namespace_preflight_expands_undeclarations_before_counting_bindings() {
        // Namespaces in XML 1.0 section 6.2 applies the normalized attribute value to a default
        // namespace declaration: https://www.w3.org/TR/REC-xml-names/#defaulting
        let maximum = crate::hard_limits::XML_NAMESPACE_BINDING_CEILING;
        let mut declarations = String::new();
        for index in 0..maximum {
            write!(declarations, r#" xmlns:p{index}="urn:{index}""#)
                .expect("namespace declaration");
        }
        let xml = format!(
            r#"<!DOCTYPE root [<!ENTITY empty ''>]><root{declarations}><child xmlns="&empty;"/></root>"#
        );
        let settings = DocumentParseSettings::new_with_depth(true, 16, 4, xml.len());

        preflight_document_limits(&xml, settings, None)
            .expect("an entity-expanded empty default namespace is an undeclaration");
    }

    #[test]
    fn namespace_preflight_counts_literal_active_bindings() {
        let maximum = crate::hard_limits::XML_NAMESPACE_BINDING_CEILING;
        let mut declarations = String::new();
        for index in 0..=maximum {
            write!(declarations, r#" xmlns:p{index}="urn:{index}""#)
                .expect("namespace declaration");
        }
        let xml = format!("<root{declarations}/>");
        let settings = DocumentParseSettings::new(false, 4, xml.len());

        assert!(matches!(
            preflight_document_limits(&xml, settings, None),
            Err(XmlDocumentError::Parse(ParseError::NamespaceBindingLimitReached {
                maximum: observed_maximum,
                actual,
            })) if observed_maximum == maximum && actual == maximum + 1
        ));
    }

    #[test]
    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    fn namespace_preflight_enforces_compiled_resource_policy() {
        let xml = r#"<root xmlns:first="urn:first" xmlns:second="urn:second"/>"#;
        let resources = crate::policy::ResourcePolicy {
            max_xml_namespace_bindings: 1,
            ..crate::policy::ResourcePolicy::default()
        };
        let settings = DocumentParseSettings::from_policy(
            crate::policy::XmlInputPolicy::default(),
            &resources,
        );

        assert!(matches!(
            preflight_document_limits(xml, settings, None),
            Err(XmlDocumentError::Parse(
                ParseError::NamespaceBindingLimitReached {
                    maximum: 1,
                    actual: 2,
                }
            ))
        ));
    }

    #[test]
    fn namespace_shadowing_does_not_inflate_active_binding_count() {
        // Namespaces in XML 1.0 section 6.1 makes the nearest declaration replace the active
        // prefix binding; nested shadowing must not accumulate historical bindings.
        // https://www.w3.org/TR/REC-xml-names/#scoping-defaulting
        let mut xml = String::new();
        for depth in 0..220 {
            xml.push_str("<n");
            for prefix in 0..5 {
                write!(xml, r#" xmlns:p{prefix}="urn:{depth}:{prefix}""#)
                    .expect("shadowed namespace");
            }
            xml.push('>');
        }
        xml.push_str(&"</n>".repeat(220));
        let settings = DocumentParseSettings::new_with_depth(false, 2_000, 256, xml.len());

        preflight_document_limits(&xml, settings, None)
            .expect("five shadowed prefixes remain five active bindings");
    }

    #[test]
    fn namespace_preflight_releases_distinct_empty_sibling_bindings() {
        // Namespace declarations are scoped to their element. Sequential empty siblings must not
        // accumulate bindings that are no longer in scope.
        // https://www.w3.org/TR/REC-xml-names/#scoping-defaulting
        let maximum = crate::hard_limits::XML_NAMESPACE_BINDING_CEILING;
        let mut siblings = String::new();
        for index in 0..=maximum {
            write!(siblings, r#"<child xmlns:p{index}="urn:{index}"/>"#)
                .expect("namespace sibling");
        }
        let xml = format!("<root>{siblings}</root>");
        let settings = DocumentParseSettings::new(false, 2_000, xml.len());

        preflight_document_limits(&xml, settings, None)
            .expect("bindings on completed empty siblings are no longer active");
    }

    #[test]
    fn namespace_preflight_restores_outer_binding_after_shadowing() {
        // Leaving a nested shadowing scope restores the outer prefix binding, so a subsequent
        // declaration is measured against the complete in-scope namespace set.
        // https://www.w3.org/TR/REC-xml-names/#scoping-defaulting
        let maximum = crate::hard_limits::XML_NAMESPACE_BINDING_CEILING;
        let mut declarations = String::new();
        for index in 0..maximum {
            write!(declarations, r#" xmlns:p{index}="urn:outer:{index}""#)
                .expect("outer namespace");
        }
        let xml = format!(
            r#"<root{declarations}><shadow xmlns:p0="urn:inner"/><overflow xmlns:extra="urn:extra"/></root>"#
        );
        let settings = DocumentParseSettings::new(false, 2_000, xml.len());

        assert!(matches!(
            preflight_document_limits(&xml, settings, None),
            Err(XmlDocumentError::Parse(ParseError::NamespaceBindingLimitReached {
                maximum: observed_maximum,
                actual,
            })) if observed_maximum == maximum && actual == maximum + 1
        ));
    }

    #[test]
    fn depth_preflight_observes_markup_generated_by_a_character_reference() {
        // Numeric references are normalized while the entity declaration is
        // read, so `&#60;` becomes markup when the replacement is later parsed.
        let xml = r#"<!DOCTYPE root [
            <!ENTITY generated "&#60;a><b/></a>">
        ]><root>&generated;</root>"#;
        let settings = DocumentParseSettings::new_with_depth(true, 16, 2, xml.len());

        assert!(matches!(
            preflight_document_limits(xml, settings, None),
            Err(XmlDocumentError::DocumentTooDeep {
                maximum: 2,
                actual: 3,
            })
        ));
    }

    #[test]
    fn depth_preflight_does_not_stop_at_generated_ampersands() {
        // An incomplete reference in replacement text must not hide the markup
        // that follows it from the pre-DOM resource checks.
        for replacement in ["&#38;<a><b/></a>", "&#38;<a><b/>&amp;</a>"] {
            let xml = format!(
                "<!DOCTYPE root [<!ENTITY generated \"{replacement}\">]><root>&generated;</root>"
            );
            let settings = DocumentParseSettings::new_with_depth(true, 16, 2, xml.len());
            assert!(matches!(
                preflight_document_limits(&xml, settings, None),
                Err(XmlDocumentError::DocumentTooDeep {
                    maximum: 2,
                    actual: 3
                })
            ));
        }
    }

    #[test]
    fn dtd_attribute_visitor_requires_keyword_boundary() {
        // XML 1.0 [52] requires S after ATTLIST; a declaration-like token
        // must not assign ID type even when a non-validating backend skips it.
        let mut declarations = Vec::new();
        visit_dtd_attributes(
            "<!DOCTYPE root [<!ATTLISTitem Token ID #IMPLIED>]>",
            |element, attribute, kind| declarations.push((element, attribute, kind)),
        );
        assert_eq!(declarations.len(), 0);
    }

    #[test]
    fn entity_preflight_ignores_declarations_inside_dtd_comments() {
        // Comment text is not a declaration. Treating it as one would let a
        // harmless reference acquire attacker-controlled phantom markup.
        let xml = r#"<!DOCTYPE root [
            <!-- <!ENTITY value "<a><b><c/></b></a>"> -->
            <!ENTITY value "ok">
        ]><root>&value;</root>"#;
        let settings = DocumentParseSettings::new_with_depth(true, 8, 1, xml.len());

        preflight_document_limits(xml, settings, None)
            .expect("comment contents must not participate in entity expansion");
        build_cell(xml.to_owned(), settings, None)
            .expect("the real declaration contains only character data");
    }

    #[test]
    fn doctype_protected_regions_cannot_hide_document_nodes_from_preflight() {
        // Brackets inside DTD comments and processing instructions do not
        // change internal-subset depth. Scanning must resume at the root.
        for protected in ["<!-- [ -->", "<?target [ ?>"] {
            let xml = format!("<!DOCTYPE root [{protected}]><root><child/></root>");
            let settings = DocumentParseSettings::new_with_depth(true, 1, 4, xml.len());

            assert!(matches!(
                preflight_document_limits(&xml, settings, None),
                Err(XmlDocumentError::Parse(ParseError::NodesLimitReached))
            ));
        }
    }

    #[test]
    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    fn entity_preflight_charges_nested_replacement_work() {
        // Repeated nested references must exhaust parser work during the
        // streaming pass, before either DOM parser receives the document.
        let xml = r#"<!DOCTYPE root [
            <!ENTITY a "0123456789">
            <!ENTITY b "&a;&a;&a;&a;">
        ]><root>&b;</root>"#;
        let first_replacement = "&a;&a;&a;&a;".len();
        let nested_replacement = "0123456789".len();
        let maximum = xml.len() + first_replacement + nested_replacement - 1;
        let budget = XmlParseWorkBudget::with_limit(maximum);
        let settings = DocumentParseSettings::new_with_depth(true, 32, 4, xml.len());

        assert!(matches!(
            build_cell(xml.to_owned(), settings, Some(&budget)),
            Err(XmlDocumentError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_PARSE_WORK_BYTES,
                maximum: observed_maximum,
                actual,
            })) if observed_maximum == maximum
                && actual == xml.len() + first_replacement + nested_replacement
        ));
    }

    #[test]
    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    fn entity_preflight_charges_a_reference_generated_by_a_character_reference() {
        // Declaration-time `&#38;` normalization exposes a general reference
        // which must recurse through the same aggregate parse-work budget.
        let xml = r#"<!DOCTYPE root [
            <!ENTITY nested "0123456789">
            <!ENTITY generated "&#38;nested;">
        ]><root>&generated;</root>"#;
        let first_replacement = "&nested;".len();
        let nested_replacement = "0123456789".len();
        let maximum = xml.len() + first_replacement + nested_replacement - 1;
        let budget = XmlParseWorkBudget::with_limit(maximum);
        let settings = DocumentParseSettings::new_with_depth(true, 16, 2, xml.len());

        assert!(matches!(
            preflight_document_limits(xml, settings, Some(&budget)),
            Err(XmlDocumentError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_PARSE_WORK_BYTES,
                maximum: observed_maximum,
                actual,
            })) if observed_maximum == maximum
                && actual == xml.len() + first_replacement + nested_replacement
        ));
    }

    #[test]
    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    fn entity_preflight_charges_nested_attribute_replacements() {
        // Attribute values are part of parser expansion work even though their
        // entity references are contained inside one lexical start-tag event.
        let xml = r#"<!DOCTYPE root [
            <!ENTITY a "0123456789">
            <!ENTITY b "&a;&a;&a;&a;">
        ]><root value="&b;"/>"#;
        let first_replacement = "&a;&a;&a;&a;".len();
        let nested_replacement = "0123456789".len();
        let expected_work = xml.len() + first_replacement + 4 * nested_replacement;
        let budget = XmlParseWorkBudget::with_limit(expected_work);
        let settings = DocumentParseSettings::new_with_depth(true, 8, 1, xml.len());

        preflight_document_limits(xml, settings, Some(&budget))
            .expect("the exact repeated attribute expansion budget must be accepted");
        assert_eq!(budget.consumed(), expected_work);

        let maximum = expected_work - 1;
        let budget = XmlParseWorkBudget::with_limit(maximum);

        assert!(matches!(
            preflight_document_limits(xml, settings, Some(&budget)),
            Err(XmlDocumentError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_PARSE_WORK_BYTES,
                maximum: observed_maximum,
                actual,
            })) if observed_maximum == maximum
                && actual == expected_work
        ));
    }

    #[test]
    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    fn attribute_preflight_exempts_normatively_redeclared_predefined_entities() {
        // XML 1.0 section 4.6 permits predefined entities to be redeclared only with their
        // normative replacement text; they remain predefined references, not expansion work.
        // https://www.w3.org/TR/xml/#sec-predefined-ent
        let references = "&amp;".repeat(
            usize::try_from(crate::hard_limits::XML_ENTITY_EXPANSION_CEILING)
                .expect("entity ceiling fits usize")
                + 1,
        );
        let xml =
            format!(r#"<!DOCTYPE root [<!ENTITY amp "&#38;#38;">]><root value="{references}"/>"#);
        let settings = DocumentParseSettings::new_with_depth(true, 8, 1, xml.len());
        let budget = XmlParseWorkBudget::with_limit(xml.len());

        preflight_document_limits(&xml, settings, Some(&budget))
            .expect("predefined attribute references do not consume entity expansion budget");
        assert_eq!(budget.consumed(), xml.len());
    }

    #[test]
    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    fn entity_preflight_streams_dense_attribute_references_in_source_order() {
        // A dense attribute must fail on the first expansion that exhausts the
        // budget. Buffering every reference and popping in reverse both delays
        // enforcement and exposes the transient allocation amplification.
        let repeated = "&first;".repeat(4_096);
        let xml = format!(
            "<!DOCTYPE root [<!ENTITY first \"0123456789\"><!ENTITY last \"01234567890123456789\">]><root value=\"{repeated}&last;\"/>"
        );
        let maximum = xml.len() + 9;
        let budget = XmlParseWorkBudget::with_limit(maximum);
        let settings = DocumentParseSettings::new_with_depth(true, 8, 1, xml.len());

        let mut scanner = general_references(b"&first;&last;");
        assert_eq!(scanner.next(), Some("first"));
        assert_eq!(scanner.next(), Some("last"));
        assert_eq!(scanner.next(), None);

        assert!(matches!(
            preflight_document_limits(&xml, settings, Some(&budget)),
            Err(XmlDocumentError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_PARSE_WORK_BYTES,
                maximum: observed_maximum,
                actual,
            })) if observed_maximum == maximum && actual == xml.len() + 10
        ));
    }

    #[test]
    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    fn entity_preflight_charges_applicable_dtd_attribute_defaults() {
        // Parser-created DTD defaults bypass lexical start-tag attributes when
        // the source element omits that name. Their references must use the same
        // budget as literal values without charging an overridden default.
        let omitted = r#"<!DOCTYPE root [
            <!ENTITY a "0123456789">
            <!ENTITY b "&a;&a;&a;&a;">
            <!ATTLIST root value CDATA "&b;">
        ]><root/>"#;
        let first_replacement = "&a;&a;&a;&a;".len();
        let nested_replacement = "0123456789".len();
        let expected_work = omitted.len() + first_replacement + 4 * nested_replacement;
        let settings = DocumentParseSettings::new_with_depth(true, 8, 1, omitted.len());
        let exact_budget = XmlParseWorkBudget::with_limit(expected_work);

        preflight_document_limits(omitted, settings, Some(&exact_budget))
            .expect("the exact default-attribute expansion budget must be accepted");
        assert_eq!(exact_budget.consumed(), expected_work);

        let maximum = expected_work - 1;
        let short_budget = XmlParseWorkBudget::with_limit(maximum);
        assert!(matches!(
            preflight_document_limits(omitted, settings, Some(&short_budget)),
            Err(XmlDocumentError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_PARSE_WORK_BYTES,
                maximum: observed_maximum,
                actual,
            })) if observed_maximum == maximum && actual == expected_work
        ));

        let overridden = omitted.replace("<root/>", "<root value=\"literal\"/>");
        let source_only_budget = XmlParseWorkBudget::with_limit(overridden.len());
        let overridden_settings =
            DocumentParseSettings::new_with_depth(true, 8, 1, overridden.len());
        preflight_document_limits(&overridden, overridden_settings, Some(&source_only_budget))
            .expect("an explicit source attribute must suppress its DTD default");
        assert_eq!(source_only_budget.consumed(), overridden.len());
    }

    #[test]
    fn entity_preflight_uses_bounded_heap_for_long_acyclic_chains() {
        // Entity indirection is independent of element depth. A legal acyclic
        // chain must not consume one native stack frame per replacement.
        const ENTITY_COUNT: usize = 4_096;
        let mut xml = String::from("<!DOCTYPE root [\n<!ENTITY e0 \"value\">\n");
        for index in 1..ENTITY_COUNT {
            writeln!(xml, "<!ENTITY e{index} \"&e{};\">", index - 1)
                .expect("write entity declaration");
        }
        write!(xml, "]><root>&e{};</root>", ENTITY_COUNT - 1).expect("write root reference");
        let settings = DocumentParseSettings::new_with_depth(true, 16, 1, xml.len());

        preflight_document_limits(&xml, settings, None)
            .expect("long acyclic entity traversal must use bounded native stack");
    }

    #[test]
    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    fn owned_parse_preflights_depth_before_dtd_provenance() {
        // Enabling internal DTD syntax must not move the provenance probe ahead
        // of the allocation-free depth boundary for an ordinary document.
        let xml = "<root><child><leaf/></child></root>";
        let settings = DocumentParseSettings::new_with_depth(true, 16, 2, xml.len());
        let budget = XmlParseWorkBudget::with_limit(xml.len());

        assert!(matches!(
            XmlDocument::parse_with_settings_and_optional_budget(
                xml.to_owned(),
                settings,
                Some(&budget),
            ),
            Err(XmlDocumentError::DocumentTooDeep {
                maximum: 2,
                actual: 3,
            })
        ));
    }

    fn nested_document(depth: usize) -> String {
        let mut xml = "<node>".repeat(depth);
        xml.push_str(&"</node>".repeat(depth));
        xml
    }

    #[test]
    fn selected_backend_enforces_exact_depth_boundary() {
        let settings = DocumentParseSettings::new_with_depth(false, 128, 2, 4_096);
        let accepted = nested_document(2);
        build_semantic_cell(accepted, settings, 0).expect("exact depth must parse");

        let rejected = nested_document(3);
        assert!(matches!(
            build_semantic_cell(rejected, settings, 0),
            Err(XmlDocumentError::DocumentTooDeep {
                maximum: 2,
                actual: 3,
            })
        ));
    }

    #[cfg(feature = "xml-backend-xmloxide")]
    #[test]
    fn xmloxide_backend_enforces_exact_depth_boundary() {
        // The default backend rejects before constructing an oversized tree,
        // while exposing the same backend-neutral document error.
        let settings = DocumentParseSettings::new_with_depth(false, 128, 2, 4_096);
        let accepted = nested_document(2);
        build_cell(accepted, settings, None).expect("exact depth must parse");

        let rejected = nested_document(3);
        assert!(matches!(
            build_cell(rejected, settings, None),
            Err(XmlDocumentError::DocumentTooDeep {
                maximum: 2,
                actual: 3,
            })
        ));
    }

    struct OversizedBorrowedInput<'a>(&'a str);

    impl AsRef<str> for OversizedBorrowedInput<'_> {
        fn as_ref(&self) -> &str {
            self.0
        }
    }

    impl From<OversizedBorrowedInput<'_>> for String {
        fn from(_: OversizedBorrowedInput<'_>) -> Self {
            panic!("oversized borrowed XML must be rejected before ownership conversion")
        }
    }

    #[test]
    fn oversized_borrowed_input_is_rejected_before_ownership_conversion() {
        // Borrowed request bodies can be arbitrarily large. Both constructors
        // must inspect their size before cloning them into the owned document.
        let oversized = "x".repeat(crate::hard_limits::XML_DOCUMENT_BYTE_CEILING + 1);
        assert!(matches!(
            XmlDocument::parse(OversizedBorrowedInput(&oversized)),
            Err(XmlDocumentError::DocumentTooLarge { .. })
        ));

        #[cfg(feature = "xmldsig")]
        {
            let mut policy = crate::policy::SigningPolicy::default();
            policy.resources.max_xml_document_bytes = 8;
            assert!(matches!(
                XmlDocument::parse_with_policy(OversizedBorrowedInput("<root/>xx"), &policy),
                Err(XmlDocumentError::DocumentTooLarge {
                    maximum: 8,
                    actual: 9,
                })
            ));
        }
    }

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
        let root = first.with_view(retained_root);

        let error = second
            .with_view(|view| view.resolve_node(root).map(|_| ()))
            .expect_err("foreign identity must fail closed");
        assert!(matches!(error, XmlDocumentError::ForeignIdentity));
    }

    #[test]
    fn child_append_projection_matches_both_element_forms() {
        // Signing must be able to enforce a tighter operation policy before
        // append_child allocates either form of the replacement document.
        for xml in ["<root></root>", "<root/>"] {
            let document = XmlDocument::parse(xml).expect("fixture must parse");
            let root = document.with_view(retained_root);
            let projected = document
                .projected_child_append_len(root, "<child/>".len())
                .expect("append length must project");

            assert_eq!(projected, "<root><child/></root>".len());
        }
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
        let root = document.with_view(retained_root);
        document
            .replace_content(root, "<p:new/>")
            .expect("in-scope prefix must be accepted");
        assert_eq!(
            document.as_xml(),
            "<p:root xmlns:p=\"urn:test\"><p:new/></p:root>"
        );
    }

    #[cfg(feature = "xml-backend-xmloxide")]
    #[test]
    fn folded_character_data_replacement_splices_its_complete_source_range() {
        // Adjacent text and CDATA tokens form one semantic text node. Mutation
        // must replace every lexical token represented by that node.
        let mut document = XmlDocument::parse("<r>one<![CDATA[+]]>two</r>")
            .expect("mixed character data fixture must parse");
        let target = document.with_view(|view| {
            let text = view
                .document()
                .root_element()
                .first_child()
                .expect("fixture must contain a text node");
            assert_eq!(text.text(), Some("one+two"));
            view.node_identity(text)
        });

        document
            .replace_node_with_fragment(target, "replacement")
            .expect("the complete folded text node must be replaceable");

        assert_eq!(document.as_xml(), "<r>replacement</r>");
    }

    #[test]
    fn validation_wrapper_does_not_consume_document_depth() {
        // The synthetic wrapper exists only while validating the replacement;
        // a result at the real document depth ceiling must remain accepted.
        let mut document = XmlDocument::parse_with_settings(
            "<root><target/></root>".into(),
            DocumentParseSettings::new_with_depth(false, 128, 2, 4_096),
        )
        .expect("fixture must fit the exact depth ceiling");
        let target = document.with_view(|view| {
            view.node_identity(
                view.document()
                    .descendants()
                    .find(|node| node.has_tag_name("target"))
                    .expect("target must exist"),
            )
        });

        document
            .replace_content(target, "text")
            .expect("validation-only wrapper must not consume caller depth");
        assert_eq!(document.as_xml(), "<root><target>text</target></root>");
    }

    #[test]
    fn validation_wrapper_does_not_consume_namespace_allowance() {
        // Scaffolding contributes one active namespace, but committed user markup contributes none.
        for batch in [false, true] {
            let mut document = XmlDocument::parse_with_settings(
                "<root/>".into(),
                DocumentParseSettings {
                    namespace_bindings_limit: 0,
                    ..DocumentParseSettings::default()
                },
            )
            .expect("namespace-free input");
            let root = document.with_view(retained_root);
            if batch {
                document
                    .replace_contents(&[(root, "text".into())])
                    .expect("namespace-free batch");
            } else {
                document
                    .replace_content(root, "text")
                    .expect("namespace-free replacement");
            }
            assert_eq!(document.as_xml(), "<root>text</root>");
            let root = document.with_view(retained_root);
            assert!(
                document
                    .replace_content(root, "<p:e xmlns:p='urn:p'/>")
                    .is_err()
            );
            assert_eq!(document.as_xml(), "<root>text</root>");
        }
    }

    #[test]
    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    fn validation_wrapper_namespace_error_reports_document_limit() {
        // A rejected replacement must report only caller-visible bindings, not the wrapper's.
        let settings = DocumentParseSettings {
            namespace_bindings_limit: 1,
            ..DocumentParseSettings::default()
        };
        for batch in [false, true] {
            let mut document = XmlDocument::parse_with_settings("<root/>".into(), settings)
                .expect("namespace-free input");
            let root = document.with_view(retained_root);
            let replacement = "<child xmlns:a='urn:a' xmlns:b='urn:b'/>";
            let error = if batch {
                document.replace_contents(&[(root, replacement.into())])
            } else {
                document.replace_content(root, replacement)
            }
            .expect_err("two bindings exceed the configured ceiling");
            assert!(matches!(
                error.into_policy_violation(settings),
                Ok(crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_NAMESPACE_BINDINGS,
                    maximum: 1,
                    actual: 2,
                })
            ));
            assert_eq!(document.as_xml(), "<root/>");
            assert_eq!(document.generation(), 0);
        }
    }

    #[test]
    fn validation_wrapper_preserves_real_depth_rejection() {
        // Exempting validation scaffolding must not exempt an inserted element
        // that makes the committed document exceed the configured depth.
        let mut document = XmlDocument::parse_with_settings(
            "<root><target/></root>".into(),
            DocumentParseSettings::new_with_depth(false, 128, 2, 4_096),
        )
        .expect("fixture must fit the exact depth ceiling");
        let target = document.with_view(|view| {
            view.node_identity(
                view.document()
                    .descendants()
                    .find(|node| node.has_tag_name("target"))
                    .expect("target must exist"),
            )
        });
        let before = document.as_xml().to_owned();

        let error = document
            .replace_content(target, "<child/>")
            .expect_err("real replacement depth must remain bounded");
        assert!(
            matches!(
                error,
                XmlDocumentError::DocumentTooDeep {
                    maximum: 2,
                    actual: 3,
                }
            ),
            "unexpected error: {error:?}"
        );
        assert_eq!(document.as_xml(), before);
        assert_eq!(document.generation(), 0);
    }

    #[test]
    fn batched_validation_wrappers_do_not_consume_document_depth() {
        // The combined validator inserts one wrapper per target, but sibling
        // scaffolding must not reduce the active depth available to either edit.
        let mut document = XmlDocument::parse_with_settings(
            "<root><first/><second/></root>".into(),
            DocumentParseSettings::new_with_depth(false, 128, 2, 4_096),
        )
        .expect("fixture must fit the exact depth ceiling");
        let (first, second) = document.with_view(|view| {
            let mut targets = view
                .document()
                .descendants()
                .filter(|node| matches!(node.tag_name().name(), "first" | "second"));
            (
                view.node_identity(targets.next().expect("first target")),
                view.node_identity(targets.next().expect("second target")),
            )
        });

        document
            .replace_contents(&[(first, "a".into()), (second, "b".into())])
            .expect("validation-only wrappers must not consume caller depth");
        assert_eq!(
            document.as_xml(),
            "<root><first>a</first><second>b</second></root>"
        );
    }

    #[test]
    fn mutations_ignore_greater_than_inside_quoted_attributes() {
        // The opening-tag boundary is the unquoted '>', not a character in an
        // attribute value; both content replacement and append use that boundary.
        let mut document =
            XmlDocument::parse("<root marker=\">\"><old/></root>").expect("fixture must parse");
        let root = document.with_view(retained_root);

        document
            .replace_content(root, "<first/>")
            .expect("quoted greater-than must not corrupt content replacement");
        let root = document.with_view(retained_root);
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
        let root = document.with_view(retained_root);

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
        let root = document.with_view(retained_root);
        let before = document.as_xml().to_owned();

        assert!(document.replace_content(root, "<unclosed>").is_err());
        assert_eq!(document.as_xml(), before);
        assert_eq!(document.generation(), 0);
    }

    #[test]
    fn oversized_invalid_fragment_fails_at_the_document_byte_boundary() {
        // Resource rejection must happen before wrapper parsing, so malformed
        // attacker input cannot force allocations beyond the document ceiling.
        // Cover both direct content replacement and self-closing expansion.
        for xml in ["<root><child/></root>", "<root/>"] {
            let mut document = XmlDocument::parse_with_settings(
                xml.into(),
                DocumentParseSettings::new(false, 64, 64),
            )
            .expect("bounded fixture must parse");
            let root = document.with_view(retained_root);
            let replacement = "<".repeat(1_024);

            assert!(matches!(
                document.replace_content(root, &replacement),
                Err(XmlDocumentError::DocumentTooLarge {
                    maximum: 64,
                    actual,
                }) if actual > 64
            ));
            assert_eq!(document.as_xml(), xml);
            assert_eq!(document.generation(), 0);
        }
    }

    #[cfg(feature = "xmlenc")]
    #[test]
    fn bounded_fragment_validation_uses_the_active_node_ceiling() {
        // The validation wrapper must not parse attacker-controlled plaintext
        // under a broader document-creation ceiling before the operation limit.
        let document = XmlDocument::parse_with_settings(
            "<root><target/></root>".into(),
            DocumentParseSettings::new(false, 128, 4_096),
        )
        .expect("fixture must parse");
        let target = document.with_view(|view| {
            let target = view
                .document()
                .descendants()
                .find(|node| node.has_tag_name("target"))
                .expect("target must exist");
            view.node_identity(target)
        });
        let maximum = document.with_view(retained_node_count);
        let before = document.as_xml().to_owned();
        let budget = XmlParseWorkBudget::from_resources(&crate::policy::ResourcePolicy::default());

        let replacement = document.prepare_node_fragment_replacement_with_budget(
            target,
            "<replacement><child/><child/><malformed>",
            DocumentParseSettings::new(
                false,
                u32::try_from(maximum).expect("bounded node count"),
                4_096,
            ),
            &budget,
        );
        assert!(matches!(
            replacement,
            Err(XmlDocumentError::ProjectedNodeLimit { maximum: rejected })
                if rejected == maximum
        ));
        assert_eq!(document.as_xml(), before);
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
    fn batched_content_replacements_obey_the_active_byte_ceiling() {
        // A retained document can have broader parse settings than the current
        // signing operation; the complete batch must use the active ceiling.
        let mut document = XmlDocument::parse_with_settings(
            "<root><first/><second/></root>".into(),
            DocumentParseSettings::new(false, 128, 4_096),
        )
        .expect("fixture must parse");
        let (first, second) = document.with_view(|view| {
            let mut targets = view
                .document()
                .descendants()
                .filter(|node| matches!(node.tag_name().name(), "first" | "second"));
            (
                view.node_identity(targets.next().expect("first target")),
                view.node_identity(targets.next().expect("second target")),
            )
        });
        let before = document.as_xml().to_owned();
        let replacements = [(first, "alpha".into()), (second, "beta".into())];
        let expected = "<root><first>alpha</first><second>beta</second></root>";
        let maximum = expected.len() - 1;
        let budget = XmlParseWorkBudget::from_resources(&crate::policy::ResourcePolicy::default());

        let error = document
            .replace_contents_with_budget(
                &replacements,
                DocumentParseSettings::new(false, 128, maximum),
                &budget,
            )
            .expect_err("the active byte ceiling must reject the complete batch");

        assert!(matches!(
            error,
            XmlDocumentError::DocumentTooLarge {
                maximum: observed_maximum,
                actual,
            } if observed_maximum == maximum && actual == expected.len()
        ));
        assert_eq!(document.as_xml(), before);
        assert_eq!(document.generation(), 0);
    }

    #[test]
    fn batched_content_replacements_validate_one_namespaced_candidate() {
        // The combined validator must preserve each target's parent namespace
        // context across both self-closing expansion and ordinary replacement.
        let mut document = XmlDocument::parse(
            r#"<root xmlns:p="urn:test"><first/><second><old/></second></root>"#,
        )
        .expect("fixture must parse");
        let (first, second) = document.with_view(|view| {
            let mut targets = view
                .document()
                .descendants()
                .filter(|node| matches!(node.tag_name().name(), "first" | "second"));
            (
                view.node_identity(targets.next().expect("first target")),
                view.node_identity(targets.next().expect("second target")),
            )
        });

        document
            .replace_contents(&[
                (first, "<p:alpha/>".into()),
                (second, "text<p:beta/>".into()),
            ])
            .expect("all fragments must validate in one candidate");

        assert_eq!(
            document.as_xml(),
            r#"<root xmlns:p="urn:test"><first><p:alpha/></first><second>text<p:beta/></second></root>"#
        );
        assert_eq!(document.generation(), 1);
    }

    #[cfg(feature = "xmldsig")]
    #[test]
    fn batched_content_replacements_charge_two_combined_parses() {
        // A full 64-reference signing batch must pay for one combined
        // structural-validation candidate and one committed generation, not
        // one full-document parse per independent DigestValue replacement.
        const TARGETS: usize = 64;
        let source = format!("<root>{}</root>", "<item>old</item>".repeat(TARGETS));
        let mut document = XmlDocument::parse(&source).expect("fixture must parse");
        let replacements = document.with_view(|view| {
            view.document()
                .descendants()
                .filter(|node| node.has_tag_name("item"))
                .map(|node| (view.node_identity(node), "x".to_owned()))
                .collect::<Vec<_>>()
        });
        let committed_len = source.len() - TARGETS * "old".len() + TARGETS;
        let validation_len =
            source.len() - TARGETS * "old".len() + TARGETS * wrapped_fragment("x").len();
        let parser_passes = selected_parser_passes();
        let maximum = (validation_len + committed_len) * parser_passes;
        let budget = XmlParseWorkBudget::with_limit(maximum);

        document
            .replace_contents_with_budget(&replacements, DocumentParseSettings::default(), &budget)
            .expect("the batch must fit its two combined parser passes exactly");

        assert_eq!(budget.consumed(), maximum);
        assert_eq!(document.as_xml().matches("<item>x</item>").count(), TARGETS);
        assert_eq!(document.generation(), 1);
    }

    #[test]
    #[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
    fn parser_work_accounting_follows_the_runtime_backend() {
        // Differential mode validates both implementations against the same
        // per-backend allowance; its diagnostic duplicate is not caller work.
        let xml = "<root><value/></root>";
        for backend in [
            XmlBackend::Xmloxide,
            XmlBackend::Roxmltree,
            XmlBackend::Differential,
        ]
        .into_iter()
        .filter(|backend| backend.is_available())
        {
            let expected = xml.len() * 3;
            let budget = XmlParseWorkBudget::with_limit(expected);
            parse_borrowed_with_settings_and_budget(
                xml,
                DocumentParseSettings::default().with_backend(backend),
                Some(&budget),
            )
            .expect("the exact runtime parser-work allowance must fit");
            assert_eq!(budget.consumed(), expected, "{backend:?}");
        }
    }

    #[test]
    fn batched_content_replacements_reject_one_escaped_boundary_atomically() {
        // One fragment escaping its target must reject the whole batch even
        // when every other replacement is structurally valid.
        let mut document = XmlDocument::parse("<root><first></first><second></second></root>")
            .expect("fixture must parse");
        let (first, second) = document.with_view(|view| {
            let mut targets = view
                .document()
                .descendants()
                .filter(|node| matches!(node.tag_name().name(), "first" | "second"));
            (
                view.node_identity(targets.next().expect("first target")),
                view.node_identity(targets.next().expect("second target")),
            )
        });
        let before = document.as_xml().to_owned();

        document
            .replace_contents(&[
                (first, "</first><attacker/><first>".into()),
                (second, "safe".into()),
            ])
            .expect_err("a fragment must not escape its target boundary");

        assert_eq!(document.as_xml(), before);
        assert_eq!(document.generation(), 0);
    }

    #[cfg(feature = "xmldsig")]
    #[test]
    fn retained_mutations_share_one_sticky_parse_work_budget() {
        // Each mutation performs one wrapped validation parse and one committed
        // document parse. A later mutation must inherit the consumed allowance,
        // and a rejected charge must exhaust it rather than permit retries.
        let mut document =
            XmlDocument::parse("<root><first/><second/></root>").expect("fixture must parse");
        let first = document.with_view(|view| {
            view.node_identity(
                view.document()
                    .descendants()
                    .find(|node| node.has_tag_name("first"))
                    .expect("first target"),
            )
        });
        let first_output = "<root><first>a</first><second/></root>";
        let first_validation_len = first_output
            .len()
            .checked_add(VALIDATION_WRAPPER_OPEN.len())
            .and_then(|length| length.checked_add(VALIDATION_WRAPPER_CLOSE.len()))
            .expect("fixture length must fit");
        let parser_passes = selected_parser_passes();
        let maximum = (first_validation_len + first_output.len()) * parser_passes;
        let budget = XmlParseWorkBudget::with_limit(maximum);

        document
            .replace_contents_with_budget(
                &[(first, "a".into())],
                DocumentParseSettings::default(),
                &budget,
            )
            .expect("the first mutation must consume the exact allowance");
        assert_eq!(document.as_xml(), first_output);

        let second = document.with_view(|view| {
            view.node_identity(
                view.document()
                    .descendants()
                    .find(|node| node.has_tag_name("second"))
                    .expect("second target"),
            )
        });
        let before = document.as_xml().to_owned();
        let error = document
            .replace_contents_with_budget(
                &[(second, "b".into())],
                DocumentParseSettings::default(),
                &budget,
            )
            .expect_err("the second mutation must not receive a fresh allowance");

        assert!(matches!(
            error,
            XmlDocumentError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_PARSE_WORK_BYTES,
                maximum: observed_maximum,
                actual,
            }) if observed_maximum == maximum && actual > maximum
        ));
        assert_eq!(document.as_xml(), before);
        assert_eq!(document.generation(), 1);
    }

    #[cfg(feature = "xmlenc")]
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
        let maximum = document.with_view(retained_node_count);
        let before = document.as_xml().to_owned();
        let budget = XmlParseWorkBudget::from_resources(&crate::policy::ResourcePolicy::default());

        assert!(matches!(
            document.replace_content_with_budget(
                target,
                "value",
                DocumentParseSettings::new(false, u32::try_from(maximum).expect("bounded node count"), 1_024),
                &budget,
            ),
            Err(XmlDocumentError::ProjectedNodeLimit { maximum: rejected })
                if rejected == maximum
        ));
        assert_eq!(document.as_xml(), before);
        assert_eq!(document.generation(), 0);
    }

    #[test]
    fn entity_expanded_elements_are_not_mutation_targets() {
        // One entity token may expand to several semantic siblings. Mutating
        // one projected identity must not splice the shared lexical token.
        let source = "<!DOCTYPE root [<!ENTITY pair '<a ID=\"target\"/><b/>'>]><root>&pair;</root>";
        let settings = DocumentParseSettings::new(true, 64, 4_096);
        let mut document = XmlDocument::parse_with_settings(source.into(), settings)
            .expect("entity fixture must parse");
        let target = document
            .with_view(|view| view.node_for_id("target", &[]))
            .expect("expanded element ID must resolve");
        let before = document.as_xml().to_owned();

        let error = document
            .replace_element(target, "<replacement/>")
            .expect_err("entity-expanded identity must not be mutable");

        assert!(error.to_string().contains("entity expansion"), "{error}");
        assert_eq!(document.as_xml(), before);
        assert_eq!(document.generation(), 0);
    }

    #[cfg(feature = "xmldsig")]
    #[test]
    fn bounded_append_accepts_text_merged_with_existing_content() {
        // Wrapper validation temporarily separates adjacent text, but the
        // committed document merges it and therefore stays at the node ceiling.
        let mut document = XmlDocument::parse_with_settings(
            "<root>text</root>".into(),
            DocumentParseSettings::new(false, 3, 1_024),
        )
        .expect("fixture must fit the exact node ceiling");
        let root = document.with_view(retained_root);
        let budget = XmlParseWorkBudget::from_resources(&crate::policy::ResourcePolicy::default());

        document
            .append_child_with_budget(
                root,
                "more",
                DocumentParseSettings::new(false, 3, 1_024),
                &budget,
            )
            .expect("merged text must not consume another committed node");

        assert_eq!(document.as_xml(), "<root>textmore</root>");
        assert_eq!(document.with_view(retained_node_count), 3);
    }

    #[cfg(feature = "xmlenc")]
    #[test]
    fn bounded_fragment_accepts_two_boundary_text_merges() {
        // A wrapper can prevent text merging on both sides of a replacement.
        // The final candidate still contains one text node and fits exactly.
        let mut document =
            XmlDocument::parse("<root>left<target/>right</root>").expect("fixture must parse");
        let target = document.with_view(|view| {
            let target = view
                .document()
                .descendants()
                .find(|node| node.has_tag_name("target"))
                .expect("target must exist");
            view.node_identity(target)
        });
        let budget = XmlParseWorkBudget::from_resources(&crate::policy::ResourcePolicy::default());

        let prepared = document
            .prepare_node_fragment_replacement_with_budget(
                target,
                "middle",
                DocumentParseSettings::new(false, 3, 1_024),
                &budget,
            )
            .expect("both boundary text pairs must fit in the prepared document");
        document
            .commit_prepared(prepared)
            .expect("prepared replacement must commit atomically");

        assert_eq!(document.as_xml(), "<root>leftmiddleright</root>");
        assert_eq!(document.with_view(retained_node_count), 3);
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
        let mut declarations = String::new();
        for index in 0..128 {
            write!(declarations, r#" xmlns:p{index}="urn:namespace:{index}""#)
                .expect("wide namespace");
        }
        let mut children = String::new();
        for index in 0..1_024 {
            write!(children, "<child index=\"{index}\"/>").expect("wide children");
        }
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
