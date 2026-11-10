//! XML Canonicalization (C14N).
//!
//! Implements:
//! - [Canonical XML 1.0](https://www.w3.org/TR/xml-c14n/) (inclusive)
//! - [Canonical XML 1.1](https://www.w3.org/TR/xml-c14n11/) (inclusive; xml:id non-inheritance and xml:base fixup)
//! - [Exclusive XML Canonicalization 1.0](https://www.w3.org/TR/xml-exc-c14n/) (exclusive)
//!
//! # Example
//!
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use xml_sec::c14n::{C14nAlgorithm, C14nMode, canonicalize_xml};
//!
//! let xml = b"<root b=\"2\" a=\"1\"><empty/></root>";
//! let algo = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
//! let canonical = canonicalize_xml(xml, &algo)?;
//! assert_eq!(
//!     String::from_utf8(canonical)?,
//!     "<root a=\"1\" b=\"2\"><empty></empty></root>"
//! );
//! # Ok(())
//! # }
//! ```

mod escape;
pub(crate) mod scratch;
#[cfg(feature = "xmldsig")]
pub(crate) use escape::escape_attr;
mod ns_common;
pub(crate) mod ns_exclusive;
pub(crate) mod ns_inclusive;
pub(crate) mod prefix;
pub(crate) mod serialize;
pub(crate) mod sink;
pub(crate) mod xml_base;

use alloc::{
    collections::BTreeSet,
    format,
    string::{String, ToString},
    vec::Vec,
};

#[cfg(feature = "xmldsig")]
use sink::ByteSink;

use crate::xml::dom::storage::{Native as NativeDom, Storage as DomStorage};
use crate::xml::dom::{Document, Node, NodeId};

use ns_exclusive::ExclusiveNsRenderer;
use ns_inclusive::InclusiveNsRenderer;
#[cfg(feature = "xmldsig")]
use serialize::serialize_canonical_visible_with_positions_bounded;
use serialize::{
    C14nConfig, CanonicalOutputOptions, serialize_canonical_visible_with_position_bounded,
    serialize_canonical_visible_with_position_with_xml_base_budget,
};

/// C14N algorithm mode (without the comments flag).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum C14nMode {
    /// Inclusive C14N 1.0 — all in-scope namespaces rendered.
    Inclusive1_0,
    /// Inclusive C14N 1.1 — like 1.0 with xml:id non-inheritance and xml:base fixup.
    Inclusive1_1,
    /// Exclusive C14N 1.0 — only visibly-utilized namespaces rendered.
    Exclusive1_0,
}

/// Full C14N algorithm identifier.
///
/// Constructed from algorithm URIs found in `<CanonicalizationMethod>` or
/// `<Transform>` elements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct C14nAlgorithm {
    mode: C14nMode,
    with_comments: bool,
    /// For Exclusive C14N: prefixes forced via `InclusiveNamespaces PrefixList`.
    /// `"#default"` is normalized to `""` (empty string) by `with_prefix_list()`.
    inclusive_prefixes: BTreeSet<String>,
}

impl C14nAlgorithm {
    /// The canonicalization mode.
    #[must_use]
    pub fn mode(&self) -> C14nMode {
        self.mode
    }

    /// Whether comment nodes are preserved.
    #[must_use]
    pub fn with_comments(&self) -> bool {
        self.with_comments
    }

    /// Prefixes forced via `InclusiveNamespaces PrefixList` (exclusive C14N).
    #[must_use]
    pub fn inclusive_prefixes(&self) -> &BTreeSet<String> {
        &self.inclusive_prefixes
    }

    /// Create a new algorithm with the given mode and comments flag.
    #[must_use]
    pub fn new(mode: C14nMode, with_comments: bool) -> Self {
        Self {
            mode,
            with_comments,
            inclusive_prefixes: BTreeSet::new(),
        }
    }

    /// Parse from an algorithm URI. Returns `None` for unrecognized URIs.
    #[must_use]
    pub fn from_uri(uri: &str) -> Option<Self> {
        let (mode, with_comments) = match uri {
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" => (C14nMode::Inclusive1_0, false),
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments" => {
                (C14nMode::Inclusive1_0, true)
            }
            "http://www.w3.org/2006/12/xml-c14n11" => (C14nMode::Inclusive1_1, false),
            "http://www.w3.org/2006/12/xml-c14n11#WithComments" => (C14nMode::Inclusive1_1, true),
            "http://www.w3.org/2001/10/xml-exc-c14n#" => (C14nMode::Exclusive1_0, false),
            "http://www.w3.org/2001/10/xml-exc-c14n#WithComments" => (C14nMode::Exclusive1_0, true),
            _ => return None,
        };
        Some(Self {
            mode,
            with_comments,
            inclusive_prefixes: BTreeSet::new(),
        })
    }

    /// Set the `InclusiveNamespaces PrefixList` (exclusive C14N only).
    /// `"#default"` is normalized to empty string `""`.
    ///
    /// Only meaningful for [`C14nMode::Exclusive1_0`]. For inclusive modes,
    /// the prefix list is ignored during canonicalization.
    #[must_use]
    pub fn with_prefix_list(mut self, prefix_list: &str) -> Self {
        self.inclusive_prefixes = prefix::inclusive_tokens(prefix_list)
            .map(|p| {
                if p == "#default" {
                    String::new()
                } else {
                    p.to_string()
                }
            })
            .collect();
        self
    }

    /// Get the algorithm URI for this configuration.
    #[must_use]
    pub fn uri(&self) -> &'static str {
        match (self.mode, self.with_comments) {
            (C14nMode::Inclusive1_0, false) => "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
            (C14nMode::Inclusive1_0, true) => {
                "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
            }
            (C14nMode::Inclusive1_1, false) => "http://www.w3.org/2006/12/xml-c14n11",
            (C14nMode::Inclusive1_1, true) => "http://www.w3.org/2006/12/xml-c14n11#WithComments",
            (C14nMode::Exclusive1_0, false) => "http://www.w3.org/2001/10/xml-exc-c14n#",
            (C14nMode::Exclusive1_0, true) => "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
        }
    }
}

/// Error type for C14N operations.
#[derive(Debug, thiserror::Error)]
pub enum C14nError {
    /// Current scoped execution refused work or scratch storage.
    #[cfg(feature = "xmldsig")]
    #[error("canonicalization shared execution: {0}")]
    SharedExecution(#[from] structured_asn1::memory::MemoryError),
    /// XML parsing error.
    #[error("XML parse error: {0}")]
    Parse(String),
    /// Invalid node reference.
    #[error("invalid node reference")]
    InvalidNode,
    /// A nonempty namespace name is relative, which canonical XML forbids.
    #[error("canonicalization requires absolute namespace URIs")]
    RelativeNamespace,
    /// Algorithm not yet implemented.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// The inherited `xml:base` chain exceeds the configured component limit.
    #[error("XML Base resolution exceeds maximum of {max} inherited components: got {actual}")]
    XmlBaseComponentsTooLarge {
        /// Configured maximum inherited components.
        max: usize,
        /// Number of inherited components encountered.
        actual: usize,
    },
    /// Cumulative `xml:base` resolution work exceeds the configured byte limit.
    #[error("XML Base resolution exceeds maximum of {max_bytes} bytes: got at least {actual}")]
    XmlBaseResolutionTooLarge {
        /// Configured maximum cumulative bytes.
        max_bytes: usize,
        /// Minimum cumulative byte count that exceeded the maximum.
        actual: usize,
    },
    /// Canonical output was refused before exceeding its admitted byte bound.
    #[error("canonical output exceeds maximum of {max_bytes} bytes")]
    OutputLimitExceeded {
        /// Maximum bytes admitted for this serialization, excluding any prefix.
        max_bytes: usize,
    },
    /// The caller's writer failed.
    #[cfg(feature = "std")]
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// An internal byte consumer stopped accepting canonical output; the
    /// operation reports the consumer's own failure instead.
    #[error("canonical output consumer refused bytes")]
    OutputRefused,
}

#[cfg(any(feature = "xmldsig", test))]
pub(crate) fn is_output_limit_error(error: &C14nError) -> bool {
    matches!(error, C14nError::OutputLimitExceeded { .. })
}

/// Visibility contract for canonicalizing a precise `XPath` node-set.
///
/// `XPath` can select attributes and namespace nodes independently from their
/// owner element. The public closure API predates that requirement and treats
/// both categories as visible whenever their owner is visible; `XMLDSig` uses
/// this richer crate-private contract for standards-compliant subsets.
pub(crate) trait NodeVisibility<D: DomStorage = NativeDom> {
    fn contains_node(&self, node: Node<'_, '_, D>) -> Result<bool, C14nError>;

    /// The element whose whole subtree, and nothing else, this set selects.
    fn apex(&self) -> Option<NodeId> {
        None
    }

    fn contains_attribute(
        &self,
        owner: Node<'_, '_, D>,
        namespace: Option<&str>,
        local_name: &str,
    ) -> Result<bool, C14nError>;

    fn contains_namespace(
        &self,
        owner: Node<'_, '_, D>,
        prefix: &str,
        uri: &str,
    ) -> Result<bool, C14nError>;

    fn contains_attribute_at(
        &self,
        owner: Node<'_, '_, D>,
        _ordinal: usize,
        attribute: crate::xml::dom::Attribute<'_, D>,
    ) -> Result<bool, C14nError> {
        self.contains_attribute(owner, attribute.namespace(), attribute.name())
    }
    fn contains_namespace_at(
        &self,
        owner: Node<'_, '_, D>,
        _ordinal: usize,
        namespace: crate::xml::dom::Namespace<'_, D>,
    ) -> Result<bool, C14nError> {
        self.contains_namespace(owner, namespace.name().unwrap_or(""), namespace.uri())
    }
}

struct ClosureVisibility<'a> {
    predicate: &'a dyn Fn(Node<'_, '_>) -> bool,
}

impl NodeVisibility for ClosureVisibility<'_> {
    fn contains_node(&self, node: Node<'_, '_>) -> Result<bool, C14nError> {
        Ok((self.predicate)(node))
    }

    fn contains_attribute(
        &self,
        owner: Node<'_, '_>,
        _namespace: Option<&str>,
        _local_name: &str,
    ) -> Result<bool, C14nError> {
        Ok((self.predicate)(owner))
    }

    fn contains_namespace(
        &self,
        owner: Node<'_, '_>,
        _prefix: &str,
        _uri: &str,
    ) -> Result<bool, C14nError> {
        Ok((self.predicate)(owner))
    }
}

/// One element's whole subtree, with every attribute and namespace node on it.
#[cfg(feature = "xmldsig")]
pub(crate) struct SubtreeVisibility<'a, 'input> {
    pub(crate) apex: Node<'a, 'input>,
}

#[cfg(feature = "xmldsig")]
impl NodeVisibility for SubtreeVisibility<'_, '_> {
    fn contains_node(&self, node: Node<'_, '_>) -> Result<bool, C14nError> {
        Ok(self.apex.subtree_contains_id(node.id()))
    }

    fn apex(&self) -> Option<NodeId> {
        Some(self.apex.id())
    }

    fn contains_attribute(
        &self,
        owner: Node<'_, '_>,
        _namespace: Option<&str>,
        _local_name: &str,
    ) -> Result<bool, C14nError> {
        self.contains_node(owner)
    }

    fn contains_namespace(
        &self,
        owner: Node<'_, '_>,
        _prefix: &str,
        _uri: &str,
    ) -> Result<bool, C14nError> {
        self.contains_node(owner)
    }
}

/// Canonicalize an XML document or document subset.
///
/// - `doc`: parsed backend-neutral semantic document (read-only DOM).
/// - `node_set`: optional predicate controlling which nodes appear in output.
///   `None` means the entire document.
/// - `algo`: algorithm parameters (mode, comments, prefix list).
/// - `output`: byte buffer receiving canonical XML.
///
/// # Errors
/// Returns namespace/URI, inherited-base, output-limit or sink failures.
/// Already emitted bytes remain in `output` on failure.
pub fn canonicalize(
    doc: &Document,
    node_set: Option<&dyn Fn(Node) -> bool>,
    algo: &C14nAlgorithm,
    output: &mut Vec<u8>,
) -> Result<(), C14nError> {
    let visibility = node_set.map(|predicate| ClosureVisibility { predicate });
    canonicalize_with_visibility(
        doc,
        visibility
            .as_ref()
            .map(|visibility| visibility as &dyn NodeVisibility),
        algo,
        output,
    )
}

/// Bounded canonicalization that also reports where each tracked element's
/// start tag begins in `output`.
#[cfg(feature = "xmldsig-sign")]
pub(crate) fn canonicalize_bounded_with_xml_base_budget_and_positions(
    doc: &Document,
    visibility: &dyn NodeVisibility,
    algo: &C14nAlgorithm,
    tracked_elements: &[NodeId],
    max_output_bytes: usize,
    xml_base_resolution: &xml_base::XmlBaseResolutionBudget,
    output: &mut Vec<u8>,
) -> Result<Vec<(NodeId, usize)>, C14nError> {
    canonicalize_with_visibility_and_positions_bounded_with_xml_base_budget(
        doc,
        Some(visibility),
        algo,
        tracked_elements,
        max_output_bytes,
        xml_base_resolution,
        output,
    )
}

/// The nodes of a document a caller selects one by one, as an `XPath` node
/// set over the external tree a document projects does. `None` means the
/// caller cannot judge the node (it has no counterpart in the caller's
/// tree), and canonicalization fails rather than guess.
#[cfg(all(feature = "external-tree", feature = "xmldsig"))]
pub trait SelectedNodes {
    /// Whether a tree node (element, text, comment or processing
    /// instruction) is selected.
    fn node(&self, node: Node<'_, '_>) -> Option<bool>;
    /// Whether the attribute `namespace`:`local_name` of `owner` is selected.
    fn attribute(
        &self,
        owner: Node<'_, '_>,
        namespace: Option<&str>,
        local_name: &str,
    ) -> Option<bool>;
    /// Whether the namespace node `prefix` (empty for the default namespace)
    /// of `owner`, bound to `uri`, is selected.
    fn namespace(&self, owner: Node<'_, '_>, prefix: &str, uri: &str) -> Option<bool>;
}

#[cfg(all(feature = "external-tree", feature = "xmldsig"))]
struct Selected<'a>(&'a dyn SelectedNodes);

#[cfg(all(feature = "external-tree", feature = "xmldsig"))]
impl NodeVisibility for Selected<'_> {
    fn contains_node(&self, node: Node<'_, '_>) -> Result<bool, C14nError> {
        self.0.node(node).ok_or(C14nError::InvalidNode)
    }

    fn contains_attribute(
        &self,
        owner: Node<'_, '_>,
        namespace: Option<&str>,
        local_name: &str,
    ) -> Result<bool, C14nError> {
        self.0
            .attribute(owner, namespace, local_name)
            .ok_or(C14nError::InvalidNode)
    }

    fn contains_namespace(
        &self,
        owner: Node<'_, '_>,
        prefix: &str,
        uri: &str,
    ) -> Result<bool, C14nError> {
        self.0
            .namespace(owner, prefix, uri)
            .ok_or(C14nError::InvalidNode)
    }
}

/// Canonicalize the subset of `view`'s document that `selected` chooses,
/// node by node, with the canonical-output and `xml:base` limits of
/// `resources`. This is the integration surface for crates that keep a node
/// set over an external tree (`DocumentView::external_node_of` maps the
/// document's nodes back to it).
///
/// # Errors
/// [`C14nError::InvalidNode`] for a node the selection cannot judge, an
/// output or `xml:base` limit, or a namespace the canonical form forbids.
#[cfg(all(feature = "external-tree", feature = "xmldsig"))]
pub fn canonicalize_selected(
    view: crate::DocumentView<'_>,
    selected: &dyn SelectedNodes,
    algo: &C14nAlgorithm,
    resources: &crate::policy::ResourcePolicy,
    output: &mut Vec<u8>,
) -> Result<(), C14nError> {
    let budget = xml_base::XmlBaseResolutionBudget::with_limits(
        resources.effective_xml_base_components(),
        resources.effective_xml_base_resolution_bytes(),
    );
    canonicalize_visible_to_writer_bounded(
        view.document(),
        Some(&Selected(selected)),
        algo,
        resources.effective_canonicalized_bytes(),
        &budget,
        output,
        0,
    )
}

/// Same bounded serializer for terminal streams and retained collecting output.
/// The supplied initial offset preserves absolute positions for append callers.
#[cfg(feature = "xmldsig")]
pub(crate) fn canonicalize_visible_to_writer_bounded<W: ByteSink + ?Sized>(
    doc: &Document,
    visibility: Option<&dyn NodeVisibility>,
    algo: &C14nAlgorithm,
    max_output_bytes: usize,
    xml_base_resolution: &xml_base::XmlBaseResolutionBudget,
    output: &mut W,
    initial_offset: usize,
) -> Result<(), C14nError> {
    canonicalize_writer_with_scratch(
        doc,
        visibility,
        algo,
        max_output_bytes,
        xml_base_resolution,
        output,
        initial_offset,
        &scratch::Native,
        None,
        None,
        &mut (),
    )
    .map(|_| ())
}

#[cfg(feature = "xmldsig")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn canonicalize_visible_to_writer_accounted<
    W: ByteSink + ?Sized,
    E: structured_asn1::memory::Work,
    D: DomStorage,
>(
    doc: &Document<'_, D>,
    visibility: Option<&dyn NodeVisibility<D>>,
    algo: &C14nAlgorithm,
    max_output_bytes: usize,
    xml_base_resolution: &xml_base::XmlBaseResolutionBudget,
    output: &mut W,
    work: &E,
    prefix_list: Option<&str>,
) -> Result<(), C14nError> {
    canonicalize_writer_with_scratch(
        doc,
        visibility,
        algo,
        max_output_bytes,
        xml_base_resolution,
        output,
        0,
        &scratch::Accounted(work),
        prefix_list,
        None,
        &mut (),
    )
    .map(|_| ())
}

/// Terminal stream for any scratch and DOM storage; nothing is collected.
#[cfg(feature = "xmldsig")]
pub(crate) fn canonicalize_visible_to_writer_in<
    W: ByteSink + ?Sized,
    S: scratch::Scratch,
    D: DomStorage,
>(
    doc: &Document<'_, D>,
    visibility: &dyn NodeVisibility<D>,
    (algo, prefix_list): (&C14nAlgorithm, Option<&str>),
    max_output_bytes: usize,
    xml_base_resolution: &xml_base::XmlBaseResolutionBudget,
    output: &mut W,
    scratch: &S,
) -> Result<(), C14nError> {
    canonicalize_writer_with_scratch(
        doc,
        Some(visibility),
        algo,
        max_output_bytes,
        xml_base_resolution,
        output,
        0,
        scratch,
        prefix_list,
        None,
        &mut (),
    )
    .map(|_| ())
}

/// [`canonicalize_visible_to_writer_in`] reporting the structure of the
/// canonical form to `observer` as its octets reach `output`.
#[cfg(feature = "xslt")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn canonicalize_visible_observed_in<
    'n,
    W: ByteSink + ?Sized,
    S: scratch::Scratch,
    D: DomStorage,
    O: serialize::CanonicalObserver<'n>,
>(
    doc: &'n Document<'_, D>,
    visibility: &dyn NodeVisibility<D>,
    algo: &C14nAlgorithm,
    max_output_bytes: usize,
    xml_base_resolution: &xml_base::XmlBaseResolutionBudget,
    output: &mut W,
    scratch: &S,
    observer: &mut O,
) -> Result<(), C14nError> {
    canonicalize_writer_with_scratch(
        doc,
        Some(visibility),
        algo,
        max_output_bytes,
        xml_base_resolution,
        output,
        0,
        scratch,
        None,
        None,
        observer,
    )
    .map(|_| ())
}

/// Materialize only when another transform requires bytes, with the same
/// serializer, storage admission and position provenance as terminal output.
#[cfg(feature = "xmldsig")]
pub(crate) fn canonicalize_buffer_in<S: scratch::Scratch, D: DomStorage>(
    doc: &Document<'_, D>,
    visibility: &dyn NodeVisibility<D>,
    (algo, prefix_list): (&C14nAlgorithm, Option<&str>),
    tracked: Option<NodeId>,
    max_output_bytes: usize,
    xml_base_resolution: &xml_base::XmlBaseResolutionBudget,
    scratch: &S,
) -> Result<(S::Bytes, Option<usize>), C14nError> {
    struct Buffer<B>(B);
    impl<B: scratch::Bytes> ByteSink for Buffer<B> {
        fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), C14nError> {
            self.0.append(bytes)
        }
    }
    let mut buffer = Buffer(scratch.bytes());
    let tracked_position = canonicalize_writer_with_scratch(
        doc,
        Some(visibility),
        algo,
        max_output_bytes,
        xml_base_resolution,
        &mut buffer,
        0,
        scratch,
        prefix_list,
        tracked,
        &mut (),
    )?;
    Ok((buffer.0, tracked_position))
}

#[cfg(feature = "xmldsig")]
#[allow(clippy::too_many_arguments)]
fn canonicalize_writer_with_scratch<
    'n,
    W: ByteSink + ?Sized,
    S: scratch::Scratch,
    D: DomStorage,
    O: serialize::CanonicalObserver<'n>,
>(
    doc: &'n Document<'_, D>,
    visibility: Option<&dyn NodeVisibility<D>>,
    algo: &C14nAlgorithm,
    max_output_bytes: usize,
    xml_base_resolution: &xml_base::XmlBaseResolutionBudget,
    output: &mut W,
    initial_offset: usize,
    scratch: &S,
    prefix_list: Option<&str>,
    tracked: Option<NodeId>,
    observer: &mut O,
) -> Result<Option<usize>, C14nError> {
    let inclusive = InclusiveNsRenderer;
    let exclusive = match prefix_list {
        Some(list) => ExclusiveNsRenderer::from_prefix_list(list),
        None => ExclusiveNsRenderer::new(&algo.inclusive_prefixes),
    };
    let renderer: &dyn serialize::NsRenderer<S, D> = match algo.mode {
        C14nMode::Inclusive1_0 | C14nMode::Inclusive1_1 => &inclusive,
        C14nMode::Exclusive1_0 => &exclusive,
    };
    let (position, _) = serialize::serialize_with_scratch(
        doc,
        visibility,
        algo.with_comments,
        renderer,
        C14nConfig::for_mode(algo.mode),
        CanonicalOutputOptions::bounded(tracked, max_output_bytes, xml_base_resolution),
        output,
        initial_offset,
        scratch,
        observer,
    )?;
    Ok(position)
}

pub(crate) fn canonicalize_with_visibility(
    doc: &Document,
    visibility: Option<&dyn NodeVisibility>,
    algo: &C14nAlgorithm,
    output: &mut Vec<u8>,
) -> Result<(), C14nError> {
    canonicalize_with_visibility_and_position(doc, visibility, algo, None, output)?;
    Ok(())
}

pub(crate) fn canonicalize_with_visibility_and_position(
    doc: &Document,
    visibility: Option<&dyn NodeVisibility>,
    algo: &C14nAlgorithm,
    tracked_element: Option<NodeId>,
    output: &mut Vec<u8>,
) -> Result<Option<usize>, C14nError> {
    canonicalize_with_visibility_and_position_impl(
        doc,
        visibility,
        algo,
        tracked_element,
        None,
        None,
        output,
    )
}

#[cfg(test)]
pub(crate) fn canonicalize_with_visibility_and_position_bounded(
    doc: &Document,
    visibility: Option<&dyn NodeVisibility>,
    algo: &C14nAlgorithm,
    tracked_element: Option<NodeId>,
    max_output_bytes: usize,
    output: &mut Vec<u8>,
) -> Result<Option<usize>, C14nError> {
    canonicalize_with_visibility_and_position_impl(
        doc,
        visibility,
        algo,
        tracked_element,
        Some(max_output_bytes),
        None,
        output,
    )
}

#[cfg(feature = "xmldsig")]
pub(crate) fn canonicalize_with_visibility_and_position_bounded_with_xml_base_budget<
    D: DomStorage,
>(
    doc: &Document<'_, D>,
    visibility: Option<&dyn NodeVisibility<D>>,
    algo: &C14nAlgorithm,
    tracked_element: Option<NodeId>,
    max_output_bytes: usize,
    xml_base_resolution: &xml_base::XmlBaseResolutionBudget,
    output: &mut Vec<u8>,
) -> Result<Option<usize>, C14nError> {
    canonicalize_with_visibility_and_position_impl(
        doc,
        visibility,
        algo,
        tracked_element,
        Some(max_output_bytes),
        Some(xml_base_resolution),
        output,
    )
}

#[cfg(feature = "xmldsig")]
pub(crate) fn canonicalize_with_visibility_and_positions_bounded_with_xml_base_budget<
    D: DomStorage,
>(
    doc: &Document<'_, D>,
    visibility: Option<&dyn NodeVisibility<D>>,
    algo: &C14nAlgorithm,
    tracked_elements: &[NodeId],
    max_output_bytes: usize,
    xml_base_resolution: &xml_base::XmlBaseResolutionBudget,
    output: &mut Vec<u8>,
) -> Result<Vec<(NodeId, usize)>, C14nError> {
    let config = C14nConfig::for_mode(algo.mode);
    let inclusive = InclusiveNsRenderer;
    let exclusive = ExclusiveNsRenderer::new(&algo.inclusive_prefixes);
    let renderer: &dyn serialize::NsRenderer<scratch::Native, D> = match algo.mode {
        C14nMode::Inclusive1_0 | C14nMode::Inclusive1_1 => &inclusive,
        C14nMode::Exclusive1_0 => &exclusive,
    };
    serialize_canonical_visible_with_positions_bounded(
        doc,
        visibility,
        algo.with_comments,
        renderer,
        config,
        CanonicalOutputOptions::bounded_many(
            tracked_elements,
            max_output_bytes,
            xml_base_resolution,
        ),
        output,
    )
}

fn canonicalize_with_visibility_and_position_impl<D: DomStorage>(
    doc: &Document<'_, D>,
    visibility: Option<&dyn NodeVisibility<D>>,
    algo: &C14nAlgorithm,
    tracked_element: Option<NodeId>,
    max_output_bytes: Option<usize>,
    xml_base_resolution: Option<&xml_base::XmlBaseResolutionBudget>,
    output: &mut Vec<u8>,
) -> Result<Option<usize>, C14nError> {
    let default_xml_base_resolution = xml_base::XmlBaseResolutionBudget::default();
    let xml_base_resolution = xml_base_resolution.unwrap_or(&default_xml_base_resolution);
    // inherit_xml_attrs: Inclusive C14N inherits xml:* attrs from ancestors
    // per §2.4. Exclusive C14N explicitly omits this per Exc-C14N §3.
    // fixup_xml_base: C14N 1.1 resolves relative xml:base URIs via RFC 3986.
    match algo.mode {
        C14nMode::Inclusive1_0 | C14nMode::Inclusive1_1 => {
            let renderer = InclusiveNsRenderer;
            let config = C14nConfig::for_mode(algo.mode);
            serialize_canonical_visible_with_position_dispatch(
                doc,
                visibility,
                algo.with_comments,
                &renderer,
                config,
                tracked_element,
                max_output_bytes,
                xml_base_resolution,
                output,
            )
        }
        C14nMode::Exclusive1_0 => {
            let renderer = ExclusiveNsRenderer::new(&algo.inclusive_prefixes);
            let config = C14nConfig::for_mode(algo.mode);
            serialize_canonical_visible_with_position_dispatch(
                doc,
                visibility,
                algo.with_comments,
                &renderer,
                config,
                tracked_element,
                max_output_bytes,
                xml_base_resolution,
                output,
            )
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn serialize_canonical_visible_with_position_dispatch<D: DomStorage>(
    doc: &Document<'_, D>,
    visibility: Option<&dyn NodeVisibility<D>>,
    with_comments: bool,
    renderer: &dyn serialize::NsRenderer<scratch::Native, D>,
    config: C14nConfig,
    tracked_element: Option<NodeId>,
    max_output_bytes: Option<usize>,
    xml_base_resolution: &xml_base::XmlBaseResolutionBudget,
    output: &mut Vec<u8>,
) -> Result<Option<usize>, C14nError> {
    match max_output_bytes {
        Some(max_output_bytes) => serialize_canonical_visible_with_position_bounded(
            doc,
            visibility,
            with_comments,
            renderer,
            config,
            CanonicalOutputOptions::bounded(tracked_element, max_output_bytes, xml_base_resolution),
            output,
        ),
        None => serialize_canonical_visible_with_position_with_xml_base_budget(
            doc,
            visibility,
            with_comments,
            renderer,
            config,
            tracked_element,
            xml_base_resolution,
            output,
        ),
    }
}

/// Convenience: parse XML bytes and canonicalize the whole document.
///
/// Input must be valid UTF-8. DTDs and external entity resolution
/// are disabled, and the library's absolute XML byte, node, and depth ceilings apply.
///
/// # Errors
/// Returns `C14nError::Parse` for invalid UTF-8, malformed XML, or exceeded
/// input ceilings, and canonicalization failures as in [`canonicalize`].
pub fn canonicalize_xml(xml: &[u8], algo: &C14nAlgorithm) -> Result<Vec<u8>, C14nError> {
    canonicalize_xml_with_backend(xml, algo, crate::XmlBackend::default())
}

/// Parse and canonicalize a complete XML document with an explicit backend.
///
/// # Errors
/// Returns input/backend failures and canonicalization errors as in
/// [`canonicalize_xml`].
pub fn canonicalize_xml_with_backend(
    xml: &[u8],
    algo: &C14nAlgorithm,
    backend: crate::XmlBackend,
) -> Result<Vec<u8>, C14nError> {
    if xml.len() > crate::hard_limits::XML_DOCUMENT_BYTE_CEILING {
        return Err(C14nError::Parse(format!(
            "input exceeds maximum XML document size of {} bytes: got {}",
            crate::hard_limits::XML_DOCUMENT_BYTE_CEILING,
            xml.len()
        )));
    }
    let xml_str =
        core::str::from_utf8(xml).map_err(|e| C14nError::Parse(format!("invalid UTF-8: {e}")))?;
    let document = crate::document::parse_borrowed_with_settings_and_budget(
        xml_str,
        crate::document::DocumentParseSettings::default().with_backend(backend),
        None,
    )
    .map_err(|error| C14nError::Parse(error.to_string()))?;
    let mut output = Vec::new();
    canonicalize(&document, None, algo, &mut output)?;
    Ok(output)
}

/// Canonicalize a retained owned document without reparsing it.
///
/// # Errors
/// Returns canonicalization failures as in [`canonicalize`].
pub fn canonicalize_document(
    document: &crate::XmlDocument,
    algo: &C14nAlgorithm,
) -> Result<Vec<u8>, C14nError> {
    let mut output = Vec::new();
    document.with_view(|view| canonicalize(view.document(), None, algo, &mut output))?;
    Ok(output)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
