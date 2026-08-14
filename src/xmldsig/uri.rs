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

use std::cell::Cell;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};

use roxmltree::{Document, Node, NodeId};

use crate::c14n::xml_base::{
    XmlBaseResolutionBudget, XmlBaseResolutionError, resolve_uri_from_node_with_budget,
};

use super::types::{NodeSet, NodeSetMaterializationBudget, TransformData, TransformError};

/// Default ID attribute names to scan when building the ID index.
///
/// These cover the most common conventions:
/// - `ID` — SAML 2.0 (`<saml:Assertion ID="...">`)
/// - `Id` — XMLDSig (`<ds:Signature Id="...">`)
/// - `id` — general XML
const DEFAULT_ID_ATTRS: &[&str] = &["ID", "Id", "id"];

struct ExternalResourceBudget {
    remaining_total_bytes: Cell<usize>,
    max_resource_bytes: usize,
    max_total_bytes: usize,
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
            return Err(TransformError::ExternalResourceTooLarge {
                max_bytes: self.max_resource_bytes,
                actual: bytes,
            });
        }
        let remaining = self.remaining_total_bytes.get();
        let Some(next) = remaining.checked_sub(bytes) else {
            self.remaining_total_bytes.set(0);
            return Err(TransformError::ExternalResourceTotalTooLarge {
                max_bytes: self.max_total_bytes,
                actual: self
                    .max_total_bytes
                    .saturating_add(bytes.saturating_sub(remaining)),
            });
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
/// use xml_sec::xmldsig::uri::UriReferenceResolver;
///
/// let xml = r#"<root><item ID="abc">content</item></root>"#;
/// let doc = roxmltree::Document::parse(xml)?;
/// let resolver = UriReferenceResolver::new(&doc);
///
/// assert!(resolver.has_id("abc"));
/// assert_eq!(resolver.id_count(), 1);
/// # Ok(())
/// # }
/// ```
pub struct UriReferenceResolver<'a> {
    doc: &'a Document<'a>,
    /// ID → element node mapping for O(1) fragment lookups.
    id_map: HashMap<&'a str, Node<'a, 'a>>,
    external_resources: Option<&'a HashMap<String, Vec<u8>>>,
    external_resource_budget: ExternalResourceBudget,
}

impl<'a> UriReferenceResolver<'a> {
    /// Build a resolver with default ID attribute names (`ID`, `Id`, `id`).
    pub fn new(doc: &'a Document<'a>) -> Self {
        Self::with_id_attrs(doc, DEFAULT_ID_ATTRS)
    }

    /// Build a resolver scanning additional ID attribute names beyond the defaults.
    ///
    /// The defaults (`ID`, `Id`, `id`) are always included; `extra_attrs`
    /// adds to them (does not replace). Pass an empty slice to use only defaults.
    ///
    /// Attribute names are matched using `roxmltree`'s *local-name* view of
    /// attributes: any namespace prefix is stripped before comparison. For
    /// example, an attribute written as `wsu:Id="..."` in the XML is seen as
    /// simply `Id` by `roxmltree`, so callers **must** pass `"Id"`, not
    /// `"wsu:Id"` or `"{namespace}Id"`.
    pub fn with_id_attrs(doc: &'a Document<'a>, extra_attrs: &[&str]) -> Self {
        let mut id_map = HashMap::new();
        // Track IDs seen more than once so they are never reinserted
        // after being removed (handles 3+ occurrences correctly).
        let mut duplicate_ids: HashSet<&'a str> = HashSet::new();

        // Merge default + extra attribute names, dedup
        let mut attr_names: Vec<&str> = DEFAULT_ID_ATTRS.to_vec();
        for name in extra_attrs {
            if !attr_names.contains(name) {
                attr_names.push(name);
            }
        }

        // Scan all elements for ID attributes
        for node in doc.descendants() {
            if node.is_element() {
                for attr_name in &attr_names {
                    if let Some(value) = node.attribute(*attr_name) {
                        // Skip IDs already marked as duplicate
                        if duplicate_ids.contains(value) {
                            continue;
                        }

                        // Duplicate IDs are invalid per XML spec and can enable
                        // signature-wrapping attacks. Remove the entry so that
                        // lookups for ambiguous IDs fail with ElementNotFound
                        // rather than silently picking an arbitrary node.
                        match id_map.entry(value) {
                            Entry::Vacant(v) => {
                                v.insert(node);
                            }
                            Entry::Occupied(o) => {
                                // Only treat as duplicate if a *different* element
                                // maps the same ID value. The same element can
                                // expose the same value via multiple scanned attrs
                                // (e.g., both `ID="x"` and `Id="x"`).
                                if o.get().id() != node.id() {
                                    o.remove();
                                    duplicate_ids.insert(value);
                                }
                            }
                        }
                    }
                }
            }
        }

        Self {
            doc,
            id_map,
            external_resources: None,
            external_resource_budget: ExternalResourceBudget::default(),
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
        self.external_resource_budget =
            ExternalResourceBudget::with_limits(max_resource_bytes, max_total_bytes);
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
    /// | external URI in caller map | A copy of the mapped bytes |
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

    fn dereference_with_optional_budget(
        &self,
        uri: &str,
        budget: Option<&NodeSetMaterializationBudget>,
    ) -> Result<TransformData<'a>, TransformError> {
        if uri.is_empty() {
            // Empty URI = entire document without comments
            // XMLDSig §4.3.3.2: "the reference is to the document [...],
            // and the comment nodes are not included"
            let nodes = match budget {
                Some(budget) => {
                    NodeSet::entire_document_without_comments_with_budget(self.doc, budget)?
                }
                None => NodeSet::entire_document_without_comments(self.doc)?,
            };
            Ok(TransformData::NodeSet(nodes))
        } else if let Some(fragment) = uri.strip_prefix('#') {
            // Note: we intentionally do NOT percent-decode the fragment.
            // XMLDSig ID values are XML Name tokens (no spaces/special chars),
            // and real-world SAML never uses percent-encoded fragments.
            // xmlsec1 also passes fragments through without decoding.
            self.dereference_fragment(fragment, budget)
        } else {
            self.external_resource(uri)?
                .map(|bytes| TransformData::Binary(bytes.to_vec()))
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
        if fragment.is_empty() {
            // Bare "#" is not a valid same-document reference
            return Err(TransformError::UnsupportedUri("#".to_string()));
        }

        if fragment == "xpointer(/)" {
            // XPointer root: entire document WITH comments (unlike empty URI).
            // Per XMLDSig §4.3.3.3: "the XPointer expression [...] includes
            // comment nodes"
            let nodes = match budget {
                Some(budget) => {
                    NodeSet::entire_document_with_comments_with_budget(self.doc, budget)?
                }
                None => NodeSet::entire_document_with_comments(self.doc)?,
            };
            Ok(TransformData::NodeSet(nodes))
        } else if let Some(id) = parse_xpointer_id_fragment(fragment) {
            // XPointer dereference retains comments, unlike a bare-name fragment.
            // Reject empty parsed ID (e.g., xpointer(id(''))) — not a valid XML Name
            if id.is_empty() {
                return Err(TransformError::UnsupportedUri(format!("#{fragment}")));
            }
            self.resolve_id(id, budget, true)
        } else if fragment.starts_with("xpointer(") {
            // Any other XPointer expression is unsupported
            Err(TransformError::UnsupportedUri(format!("#{fragment}")))
        } else {
            // Bare-name fragment: #foo → element by ID
            self.resolve_id(fragment, budget, false)
        }
    }

    /// Look up an element by its ID attribute value and return a subtree node set.
    fn resolve_id(
        &self,
        id: &str,
        budget: Option<&NodeSetMaterializationBudget>,
        with_comments: bool,
    ) -> Result<TransformData<'a>, TransformError> {
        match self.id_map.get(id) {
            Some(&element) => {
                let nodes = if with_comments {
                    match budget {
                        Some(budget) => NodeSet::subtree_with_budget(element, budget)?,
                        None => NodeSet::subtree(element)?,
                    }
                } else {
                    NodeSet::subtree_without_comments_with_budget(element, budget)?
                };
                Ok(TransformData::NodeSet(nodes))
            }
            None => Err(TransformError::ElementNotFound(id.to_string())),
        }
    }

    /// Check if an ID is registered in the resolver's index.
    pub fn has_id(&self, id: &str) -> bool {
        self.id_map.contains_key(id)
    }

    /// Resolve a same-document ID token to a stable node identity.
    ///
    /// Returns `None` when the ID is absent or ambiguous (duplicate ID collision),
    /// matching the resolver behavior used by `dereference()`.
    pub(crate) fn node_id_for_id(&self, id: &str) -> Option<NodeId> {
        self.id_map.get(id).map(|node| node.id())
    }

    /// Resolve an unambiguous XML ID to its element node.
    ///
    /// Returns `None` when the ID is absent or duplicated, matching fragment
    /// dereferencing and operation start-node selection.
    pub fn node_for_id(&self, id: &str) -> Option<Node<'a, 'a>> {
        self.id_map.get(id).copied()
    }

    pub(crate) fn node_for_node_id(&self, id: NodeId) -> Option<Node<'a, 'a>> {
        self.doc.get_node(id)
    }

    /// Get the number of registered IDs.
    pub fn id_count(&self) -> usize {
        self.id_map.len()
    }
}

fn map_xml_base_resolution_error(error: XmlBaseResolutionError) -> TransformError {
    match error {
        XmlBaseResolutionError::Components { maximum, actual } => {
            TransformError::XmlBaseComponentsTooLarge {
                max: maximum,
                actual,
            }
        }
        XmlBaseResolutionError::Bytes { maximum, actual } => {
            TransformError::XmlBaseResolutionTooLarge {
                max_bytes: maximum,
                actual,
            }
        }
    }
}

/// Parse `xpointer(id('value'))` or `xpointer(id("value"))` and return the ID value.
/// Returns `None` if the fragment doesn't match this pattern.
pub(crate) fn parse_xpointer_id_fragment(fragment: &str) -> Option<&str> {
    let inner = fragment.strip_prefix("xpointer(id(")?.strip_suffix("))")?;

    // Strip single or double quotes using safe helpers to avoid panics
    // on malformed input (e.g., `xpointer(id('))` where inner is `'`)
    if let Some(stripped) = inner.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
        Some(stripped)
    } else if let Some(stripped) = inner.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        Some(stripped)
    } else {
        None
    }
}

/// Extract the ID selected by a supported same-document URI.
///
/// This keeps secondary consumers such as KeyInfo and Manifest processing in
/// lockstep with the resolver's bare-fragment and XPointer ID semantics.
pub(crate) fn same_document_reference_id(uri: &str) -> Option<&str> {
    let fragment = uri.strip_prefix('#')?;
    if fragment.is_empty() || fragment == "xpointer(/)" {
        return None;
    }
    if let Some(id) = parse_xpointer_id_fragment(fragment) {
        return (!id.is_empty()).then_some(id);
    }
    (!fragment.starts_with("xpointer(")).then_some(fragment)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::types::NodeSet;
    use super::*;

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
    fn same_document_reference_id_rejects_non_id_fragments() {
        assert_eq!(super::same_document_reference_id("#target"), Some("target"));
        assert_eq!(
            super::same_document_reference_id("#xpointer(id('target'))"),
            Some("target")
        );
        assert_eq!(
            super::same_document_reference_id(r#"#xpointer(id("target"))"#),
            Some("target")
        );
        for uri in [
            "",
            "target",
            "#",
            "#xpointer(/)",
            "#xpointer(id(''))",
            "#xpointer(id(target))",
        ] {
            assert_eq!(super::same_document_reference_id(uri), None, "{uri}");
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
