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
mod ns_common;
pub(crate) mod ns_exclusive;
pub(crate) mod ns_inclusive;
pub(crate) mod prefix;
pub(crate) mod serialize;
pub(crate) mod xml_base;

use std::collections::HashSet;

use crate::xml::dom::{Document, Node, NodeId};

use ns_exclusive::ExclusiveNsRenderer;
use ns_inclusive::InclusiveNsRenderer;
#[cfg(any(feature = "xmldsig", test))]
use serialize::CanonicalOutputLimitExceeded;
#[cfg(any(feature = "xmldsig", test))]
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
    /// For Exclusive C14N: prefixes forced via InclusiveNamespaces PrefixList.
    /// `"#default"` is normalized to `""` (empty string) by `with_prefix_list()`.
    inclusive_prefixes: HashSet<String>,
}

impl C14nAlgorithm {
    /// The canonicalization mode.
    pub fn mode(&self) -> C14nMode {
        self.mode
    }

    /// Whether comment nodes are preserved.
    pub fn with_comments(&self) -> bool {
        self.with_comments
    }

    /// Prefixes forced via InclusiveNamespaces PrefixList (exclusive C14N).
    pub fn inclusive_prefixes(&self) -> &HashSet<String> {
        &self.inclusive_prefixes
    }

    /// Create a new algorithm with the given mode and comments flag.
    pub fn new(mode: C14nMode, with_comments: bool) -> Self {
        Self {
            mode,
            with_comments,
            inclusive_prefixes: HashSet::new(),
        }
    }

    /// Parse from an algorithm URI. Returns `None` for unrecognized URIs.
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
            inclusive_prefixes: HashSet::new(),
        })
    }

    /// Set the InclusiveNamespaces PrefixList (exclusive C14N only).
    /// `"#default"` is normalized to empty string `""`.
    ///
    /// Only meaningful for [`C14nMode::Exclusive1_0`]. For inclusive modes,
    /// the prefix list is ignored during canonicalization.
    pub fn with_prefix_list(mut self, prefix_list: &str) -> Self {
        self.inclusive_prefixes = prefix_list
            .split_whitespace()
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
    /// XML parsing error.
    #[error("XML parse error: {0}")]
    Parse(String),
    /// Invalid node reference.
    #[error("invalid node reference")]
    InvalidNode,
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
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(any(feature = "xmldsig", test))]
pub(crate) fn is_output_limit_error(error: &C14nError) -> bool {
    matches!(
        error,
        C14nError::Io(error)
            if error
                .get_ref()
                .is_some_and(|source| source.is::<CanonicalOutputLimitExceeded>())
    )
}

/// Visibility contract for canonicalizing a precise XPath node-set.
///
/// XPath can select attributes and namespace nodes independently from their
/// owner element. The public closure API predates that requirement and treats
/// both categories as visible whenever their owner is visible; XMLDSig uses
/// this richer crate-private contract for standards-compliant subsets.
pub(crate) trait NodeVisibility {
    fn contains_node(&self, node: Node<'_, '_>) -> bool;

    fn contains_attribute(
        &self,
        owner: Node<'_, '_>,
        namespace: Option<&str>,
        local_name: &str,
    ) -> bool;

    fn contains_namespace(&self, owner: Node<'_, '_>, prefix: &str, uri: &str) -> bool;
}

struct ClosureVisibility<'a> {
    predicate: &'a dyn Fn(Node<'_, '_>) -> bool,
}

impl NodeVisibility for ClosureVisibility<'_> {
    fn contains_node(&self, node: Node<'_, '_>) -> bool {
        (self.predicate)(node)
    }

    fn contains_attribute(
        &self,
        owner: Node<'_, '_>,
        _namespace: Option<&str>,
        _local_name: &str,
    ) -> bool {
        (self.predicate)(owner)
    }

    fn contains_namespace(&self, owner: Node<'_, '_>, _prefix: &str, _uri: &str) -> bool {
        (self.predicate)(owner)
    }
}

/// Canonicalize an XML document or document subset.
///
/// - `doc`: parsed roxmltree document (read-only DOM).
/// - `node_set`: optional predicate controlling which nodes appear in output.
///   `None` means the entire document.
/// - `algo`: algorithm parameters (mode, comments, prefix list).
/// - `output`: byte buffer receiving canonical XML.
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

#[cfg(any(feature = "xmldsig", test))]
/// Canonicalize through the closure visibility API while enforcing both the
/// output ceiling and the caller's operation-wide XML Base work budget.
pub(crate) fn canonicalize_bounded_with_xml_base_budget(
    doc: &Document,
    node_set: Option<&dyn Fn(Node) -> bool>,
    algo: &C14nAlgorithm,
    max_output_bytes: usize,
    xml_base_resolution: &xml_base::XmlBaseResolutionBudget,
    output: &mut Vec<u8>,
) -> Result<(), C14nError> {
    let visibility = node_set.map(|predicate| ClosureVisibility { predicate });
    canonicalize_with_visibility_and_position_bounded_with_xml_base_budget(
        doc,
        visibility
            .as_ref()
            .map(|visibility| visibility as &dyn NodeVisibility),
        algo,
        None,
        max_output_bytes,
        xml_base_resolution,
        output,
    )?;
    Ok(())
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

#[cfg(any(feature = "xmldsig", test))]
pub(crate) fn canonicalize_with_visibility_and_position_bounded_with_xml_base_budget(
    doc: &Document,
    visibility: Option<&dyn NodeVisibility>,
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

#[cfg(any(feature = "xmldsig", test))]
pub(crate) fn canonicalize_with_visibility_and_positions_bounded_with_xml_base_budget(
    doc: &Document,
    visibility: Option<&dyn NodeVisibility>,
    algo: &C14nAlgorithm,
    tracked_elements: &[NodeId],
    max_output_bytes: usize,
    xml_base_resolution: &xml_base::XmlBaseResolutionBudget,
    output: &mut Vec<u8>,
) -> Result<Vec<(NodeId, usize)>, C14nError> {
    let config = C14nConfig {
        inherit_xml_attrs: !matches!(algo.mode, C14nMode::Exclusive1_0),
        fixup_xml_base: matches!(algo.mode, C14nMode::Inclusive1_1),
    };
    let inclusive = InclusiveNsRenderer;
    let exclusive = ExclusiveNsRenderer::new(&algo.inclusive_prefixes);
    let renderer: &dyn serialize::NsRenderer = match algo.mode {
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

fn canonicalize_with_visibility_and_position_impl(
    doc: &Document,
    visibility: Option<&dyn NodeVisibility>,
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
        C14nMode::Inclusive1_0 => {
            let renderer = InclusiveNsRenderer;
            let config = C14nConfig {
                inherit_xml_attrs: true,
                fixup_xml_base: false,
            };
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
        C14nMode::Inclusive1_1 => {
            let renderer = InclusiveNsRenderer;
            let config = C14nConfig {
                inherit_xml_attrs: true,
                fixup_xml_base: true,
            };
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
            let config = C14nConfig {
                inherit_xml_attrs: false,
                fixup_xml_base: false,
            };
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
fn serialize_canonical_visible_with_position_dispatch(
    doc: &Document,
    visibility: Option<&dyn NodeVisibility>,
    with_comments: bool,
    renderer: &dyn serialize::NsRenderer,
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
/// Input must be valid UTF-8 (XML 1.0 documents are UTF-8 or declare their
/// encoding; roxmltree only accepts UTF-8). DTDs and external entity resolution
/// are disabled, and the library's absolute XML byte, node, and depth ceilings apply.
/// Returns `C14nError::Parse` for invalid UTF-8, malformed XML, or exceeded
/// input ceilings.
pub fn canonicalize_xml(xml: &[u8], algo: &C14nAlgorithm) -> Result<Vec<u8>, C14nError> {
    if xml.len() > crate::hard_limits::XML_DOCUMENT_BYTE_CEILING {
        return Err(C14nError::Parse(format!(
            "input exceeds maximum XML document size of {} bytes: got {}",
            crate::hard_limits::XML_DOCUMENT_BYTE_CEILING,
            xml.len()
        )));
    }
    let xml_str =
        std::str::from_utf8(xml).map_err(|e| C14nError::Parse(format!("invalid UTF-8: {e}")))?;
    let document = crate::document::parse_borrowed_with_settings_and_budget(
        xml_str,
        crate::document::DocumentParseSettings::default(),
        None,
    )
    .map_err(|error| C14nError::Parse(error.to_string()))?;
    let mut output = Vec::new();
    canonicalize(&document, None, algo, &mut output)?;
    Ok(output)
}

/// Canonicalize a retained owned document without reparsing it.
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
mod tests {
    use super::*;

    #[test]
    fn from_uri_roundtrip() {
        let uris = [
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
            "http://www.w3.org/2006/12/xml-c14n11",
            "http://www.w3.org/2006/12/xml-c14n11#WithComments",
            "http://www.w3.org/2001/10/xml-exc-c14n#",
            "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
        ];
        for uri in uris {
            let algo = C14nAlgorithm::from_uri(uri).expect(uri);
            assert_eq!(algo.uri(), uri);
        }
    }

    #[test]
    fn unknown_uri_returns_none() {
        assert!(C14nAlgorithm::from_uri("http://example.com/unknown").is_none());
    }

    #[test]
    fn prefix_list_parsing() {
        let algo = C14nAlgorithm::new(C14nMode::Exclusive1_0, false)
            .with_prefix_list("foo bar #default baz");
        assert!(algo.inclusive_prefixes.contains("foo"));
        assert!(algo.inclusive_prefixes.contains("bar"));
        assert!(algo.inclusive_prefixes.contains("baz"));
        assert!(algo.inclusive_prefixes.contains("")); // #default → ""
        assert_eq!(algo.inclusive_prefixes.len(), 4);
    }

    #[test]
    fn canonicalize_xml_basic() {
        let xml = b"<root b=\"2\" a=\"1\"><empty/></root>";
        let algo = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
        let result = canonicalize_xml(xml, &algo).expect("c14n");
        assert_eq!(
            String::from_utf8(result).expect("utf8"),
            r#"<root a="1" b="2"><empty></empty></root>"#
        );
    }

    #[test]
    fn canonicalize_xml_rejects_input_above_the_document_byte_ceiling_before_parsing() {
        // The convenience parser accepts untrusted bytes, so allocation bounds
        // must apply before UTF-8 or XML parsing can inspect the payload.
        let xml = vec![b' '; crate::hard_limits::XML_DOCUMENT_BYTE_CEILING + 1];
        let error = match canonicalize_xml(&xml, &C14nAlgorithm::new(C14nMode::Inclusive1_0, false))
        {
            Err(error) => error,
            Ok(_) => panic!("oversized canonicalization input must be rejected"),
        };
        assert!(matches!(
            error,
            C14nError::Parse(message)
                if message.contains("exceeds maximum XML document size")
        ));
    }

    #[test]
    fn canonicalize_xml_rejects_input_above_the_document_node_ceiling() {
        // A compact document can otherwise force an effectively unbounded
        // parser-node allocation despite staying below the byte ceiling.
        let children = "<n/>".repeat(crate::hard_limits::XML_DOCUMENT_NODE_CEILING as usize);
        let xml = format!("<root>{children}</root>");
        let error = match canonicalize_xml(
            xml.as_bytes(),
            &C14nAlgorithm::new(C14nMode::Inclusive1_0, false),
        ) {
            Err(error) => error,
            Ok(_) => panic!("excessive canonicalization nodes must be rejected"),
        };
        assert!(matches!(
            error,
            C14nError::Parse(message) if message.contains("nodes limit reached")
        ));
    }

    #[test]
    fn canonicalize_xml_rejects_input_above_the_document_depth_ceiling() {
        // The convenience parser is a public untrusted-input boundary, so the
        // absolute depth ceiling must apply before recursive C14N traversal.
        let depth = crate::hard_limits::XML_DOCUMENT_DEPTH_CEILING + 1;
        let xml = format!("{}{}", "<n>".repeat(depth), "</n>".repeat(depth));

        let error = canonicalize_xml(
            xml.as_bytes(),
            &C14nAlgorithm::new(C14nMode::Inclusive1_0, false),
        )
        .expect_err("over-depth canonicalization input must be rejected");

        assert!(matches!(
            error,
            C14nError::Parse(message) if message.contains("maximum element depth")
        ));
    }

    #[test]
    fn canonicalize_xml_does_not_enable_dtd_or_external_entity_resolution() {
        // Whole-document C14N is a convenience API, not an implicit opt-in to
        // DTD parsing or external resource access.
        let xml = br#"<!DOCTYPE root [<!ENTITY value 'expanded'>]><root>&value;</root>"#;
        let error = canonicalize_xml(xml, &C14nAlgorithm::new(C14nMode::Inclusive1_0, false))
            .expect_err("DTD input must remain disabled");
        assert!(matches!(
            error,
            C14nError::Parse(message) if message.contains("DTD detected")
        ));
    }

    #[test]
    fn c14n_1_1_basic() {
        // C14N 1.1 serialization is identical to 1.0 for full documents.
        let xml = b"<root b=\"2\" a=\"1\"><empty/></root>";
        let algo = C14nAlgorithm::new(C14nMode::Inclusive1_1, false);
        let result = canonicalize_xml(xml, &algo).expect("c14n 1.1");
        assert_eq!(
            String::from_utf8(result).expect("utf8"),
            r#"<root a="1" b="2"><empty></empty></root>"#
        );
    }

    #[test]
    fn c14n_1_1_with_comments() {
        let xml = b"<root><!-- comment -->text</root>";
        let algo = C14nAlgorithm::new(C14nMode::Inclusive1_1, true);
        let result = canonicalize_xml(xml, &algo).expect("c14n 1.1 with comments");
        assert_eq!(
            String::from_utf8(result).expect("utf8"),
            "<root><!-- comment -->text</root>"
        );
    }

    #[test]
    fn c14n_1_1_without_comments() {
        let xml = b"<root><!-- comment -->text</root>";
        let algo = C14nAlgorithm::new(C14nMode::Inclusive1_1, false);
        let result = canonicalize_xml(xml, &algo).expect("c14n 1.1 without comments");
        assert_eq!(
            String::from_utf8(result).expect("utf8"),
            "<root>text</root>"
        );
    }

    #[test]
    fn c14n_1_1_namespaces() {
        // C14N 1.1 renders all in-scope namespaces like 1.0.
        let xml = b"<root xmlns:a=\"http://a\" xmlns:b=\"http://b\"><child/></root>";
        let algo_10 = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
        let algo_11 = C14nAlgorithm::new(C14nMode::Inclusive1_1, false);
        let result_10 = canonicalize_xml(xml, &algo_10).expect("1.0");
        let result_11 = canonicalize_xml(xml, &algo_11).expect("1.1");
        // For full documents, 1.0 and 1.1 produce identical output.
        assert_eq!(result_10, result_11);
    }

    #[test]
    fn c14n_1_1_xml_id_is_not_inherited_in_subset() {
        // C14N 1.1 explicitly excludes xml:id from simple inheritable
        // attributes, so omitting its owner must also omit the attribute.
        use crate::xml::dom::Document;
        use std::collections::HashSet;

        let xml = r#"<root xml:id="r1"><child>text</child></root>"#;
        let doc = Document::parse(xml).expect("parse");
        let child = doc.root_element().first_element_child().expect("child");

        // Build subset: child + its descendants, excluding root
        let mut ids = HashSet::new();
        let mut stack = vec![child];
        while let Some(n) = stack.pop() {
            ids.insert(n.id());
            for c in n.children() {
                stack.push(c);
            }
        }
        let pred = move |n: crate::xml::dom::Node| ids.contains(&n.id());

        let algo = C14nAlgorithm::new(C14nMode::Inclusive1_1, false);
        let mut out = Vec::new();
        canonicalize(&doc, Some(&pred), &algo, &mut out).expect("c14n 1.1 subset");
        let result = String::from_utf8(out).expect("utf8");

        assert!(
            !result.contains(r#"xml:id="r1""#),
            "xml:id must not be inherited in C14N 1.1 subset; got: {result}"
        );
    }

    #[test]
    fn c14n_1_0_xml_id_is_inherited_in_subset() {
        // C14N 1.0 predates the C14N 1.1 xml:id exception, so xml:id follows
        // the general xml:* apex inheritance rule in a document subset.
        use crate::xml::dom::Document;
        use std::collections::HashSet;

        let xml = r#"<root xml:id="r1"><child>text</child></root>"#;
        let doc = Document::parse(xml).expect("parse");
        let child = doc.root_element().first_element_child().expect("child");
        let ids = child
            .descendants()
            .map(|node| node.id())
            .collect::<HashSet<_>>();
        let pred = move |node: crate::xml::dom::Node| ids.contains(&node.id());

        let algo = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
        let mut out = Vec::new();
        canonicalize(&doc, Some(&pred), &algo, &mut out).expect("c14n 1.0 subset");

        assert_eq!(
            String::from_utf8(out).expect("utf8"),
            r#"<child xml:id="r1">text</child>"#
        );
    }

    #[test]
    fn bounded_canonicalization_stops_before_exceeding_the_limit() {
        // XMLDSig applies a signature-wide output ceiling. The serializer must
        // stop at that ceiling instead of allocating the complete hostile value
        // and rejecting it only after serialization has finished.
        let xml = format!("<root>{}</root>", "x".repeat(4_096));
        let document = Document::parse(&xml).expect("fixed XML must parse");
        let algorithm = C14nAlgorithm::new(C14nMode::Inclusive1_0, false);
        let mut output = Vec::new();

        let error = canonicalize_with_visibility_and_position_bounded(
            &document,
            None,
            &algorithm,
            None,
            64,
            &mut output,
        )
        .expect_err("canonicalization must stop at the caller's byte ceiling");

        assert!(is_output_limit_error(&error));
        assert!(
            output.len() <= 64,
            "bounded output grew to {} bytes",
            output.len()
        );
    }

    #[test]
    fn c14n_1_1_bounds_inherited_xml_base_components() {
        // C14N 1.1 subset fixup walks ancestors outside the selected node set.
        // Bounding that walk prevents deeply nested xml:base chains from
        // multiplying URI-resolution work during canonicalization.
        let mut xml = String::new();
        for _ in 0..=crate::hard_limits::XML_BASE_COMPONENT_CEILING {
            xml.push_str(r#"<n xml:base="segment/">"#);
        }
        xml.push_str("<leaf/>");
        for _ in 0..=crate::hard_limits::XML_BASE_COMPONENT_CEILING {
            xml.push_str("</n>");
        }
        let document = Document::parse(&xml).expect("fixed XML must parse");
        let leaf = document
            .descendants()
            .find(|node| node.has_tag_name("leaf"))
            .expect("leaf");
        let visible = |node: Node<'_, '_>| node == leaf;
        let algorithm = C14nAlgorithm::new(C14nMode::Inclusive1_1, false);
        let mut output = Vec::new();

        let error = canonicalize_with_visibility(
            &document,
            Some(&ClosureVisibility {
                predicate: &visible,
            }),
            &algorithm,
            &mut output,
        )
        .expect_err("C14N must reject an overlong inherited xml:base chain");

        assert!(
            error.to_string().contains("XML Base"),
            "unexpected C14N error: {error}"
        );
    }

    #[test]
    fn unbounded_output_preserves_the_callers_xml_base_budget() {
        // Output capacity and XML Base work are independent limits. Omitting
        // an output ceiling must not replace the caller's XML Base policy.
        let document = Document::parse(
            r#"<root xml:base="one/"><parent xml:base="two/"><leaf/></parent></root>"#,
        )
        .unwrap();
        let leaf = document
            .descendants()
            .find(|node| node.has_tag_name("leaf"))
            .unwrap();
        let visible = |node: Node<'_, '_>| node == leaf;
        let budget = xml_base::XmlBaseResolutionBudget::with_limits(1, usize::MAX);
        let algorithm = C14nAlgorithm::new(C14nMode::Inclusive1_1, false);
        let mut output = Vec::new();

        let error = canonicalize_with_visibility_and_position_impl(
            &document,
            Some(&ClosureVisibility {
                predicate: &visible,
            }),
            &algorithm,
            None,
            None,
            Some(&budget),
            &mut output,
        )
        .expect_err("the caller's component ceiling must survive unbounded dispatch");

        assert!(matches!(
            error,
            C14nError::XmlBaseComponentsTooLarge { max: 1, actual: 2 }
        ));
    }
}
