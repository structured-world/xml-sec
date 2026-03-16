//! URI dereference for XMLDSig `<Reference>` elements.
//!
//! Implements same-document URI resolution per
//! [XMLDSig §4.3.3.2](https://www.w3.org/TR/xmldsig-core1/#sec-Same-Document):
//!
//! - **Empty URI** (`""` or absent): the entire document, excluding comments.
//! - **Bare-name `#id`**: the element whose ID attribute matches `id`, as a subtree.
//! - **`#xpointer(/)`**: the entire document, including comments.
//! - **`#xpointer(id('id'))` / `#xpointer(id("id"))`**: element by ID (equivalent to bare-name).
//!
//! External URIs (http://, file://, etc.) are not supported — only same-document
//! references are needed for SAML signature verification.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};

use roxmltree::{Document, Node};

use super::types::{NodeSet, TransformData, TransformError};

/// Default ID attribute names to scan when building the ID index.
///
/// These cover the most common conventions:
/// - `ID` — SAML 2.0 (`<saml:Assertion ID="...">`)
/// - `Id` — XMLDSig (`<ds:Signature Id="...">`)
/// - `id` — general XML
const DEFAULT_ID_ATTRS: &[&str] = &["ID", "Id", "id"];

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
                                o.remove();
                                duplicate_ids.insert(value);
                            }
                        }
                    }
                }
            }
        }

        Self { doc, id_map }
    }

    /// Dereference a URI string to a [`TransformData`].
    ///
    /// # URI forms
    ///
    /// | URI | Result |
    /// |-----|--------|
    /// | `""` (empty) | Entire document, comments excluded |
    /// | `"#foo"` | Subtree rooted at element with ID `foo` |
    /// | `"#xpointer(/)"` | Entire document, comments included |
    /// | `"#xpointer(id('foo'))"` | Subtree rooted at element with ID `foo` |
    /// | other | `Err(UnsupportedUri)` |
    pub fn dereference(&self, uri: &str) -> Result<TransformData<'a>, TransformError> {
        if uri.is_empty() {
            // Empty URI = entire document without comments
            // XMLDSig §4.3.3.2: "the reference is to the document [...],
            // and the comment nodes are not included"
            Ok(TransformData::NodeSet(
                NodeSet::entire_document_without_comments(self.doc),
            ))
        } else if let Some(fragment) = uri.strip_prefix('#') {
            // Note: we intentionally do NOT percent-decode the fragment.
            // XMLDSig ID values are XML Name tokens (no spaces/special chars),
            // and real-world SAML never uses percent-encoded fragments.
            // xmlsec1 also passes fragments through without decoding.
            self.dereference_fragment(fragment)
        } else {
            Err(TransformError::UnsupportedUri(uri.to_string()))
        }
    }

    /// Resolve a URI fragment (the part after `#`).
    ///
    /// Handles:
    /// - `xpointer(/)` → entire document (with comments, per XPointer spec)
    /// - `xpointer(id('foo'))` → element by ID (equivalent to bare-name `#foo`)
    /// - bare name `foo` → element by ID attribute
    fn dereference_fragment(&self, fragment: &str) -> Result<TransformData<'a>, TransformError> {
        if fragment.is_empty() {
            // Bare "#" is not a valid same-document reference
            return Err(TransformError::UnsupportedUri("#".to_string()));
        }

        if fragment == "xpointer(/)" {
            // XPointer root: entire document WITH comments (unlike empty URI).
            // Per XMLDSig §4.3.3.3: "the XPointer expression [...] includes
            // comment nodes"
            Ok(TransformData::NodeSet(
                NodeSet::entire_document_with_comments(self.doc),
            ))
        } else if let Some(id) = parse_xpointer_id(fragment) {
            // xpointer(id('foo')) → same as bare-name #foo
            self.resolve_id(id)
        } else if fragment.starts_with("xpointer(") {
            // Any other XPointer expression is unsupported
            Err(TransformError::UnsupportedUri(format!("#{fragment}")))
        } else {
            // Bare-name fragment: #foo → element by ID
            self.resolve_id(fragment)
        }
    }

    /// Look up an element by its ID attribute value and return a subtree node set.
    fn resolve_id(&self, id: &str) -> Result<TransformData<'a>, TransformError> {
        match self.id_map.get(id) {
            Some(&element) => Ok(TransformData::NodeSet(NodeSet::subtree(self.doc, element))),
            None => Err(TransformError::ElementNotFound(id.to_string())),
        }
    }

    /// Check if an ID is registered in the resolver's index.
    pub fn has_id(&self, id: &str) -> bool {
        self.id_map.contains_key(id)
    }

    /// Get the number of registered IDs.
    pub fn id_count(&self) -> usize {
        self.id_map.len()
    }
}

/// Parse `xpointer(id('value'))` or `xpointer(id("value"))` and return the ID value.
/// Returns `None` if the fragment doesn't match this pattern.
fn parse_xpointer_id(fragment: &str) -> Option<&str> {
    let inner = fragment.strip_prefix("xpointer(id(")?.strip_suffix("))")?;

    // Strip single or double quotes
    if (inner.starts_with('\'') && inner.ends_with('\''))
        || (inner.starts_with('"') && inner.ends_with('"'))
    {
        Some(&inner[1..inner.len() - 1])
    } else {
        None
    }
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

        let node_set = NodeSet::entire_document_without_comments(&doc1);

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
    fn subtree_includes_comments() {
        // Subtree dereference (via #id) includes comments, unlike empty URI
        let xml = r#"<root><item ID="x"><!-- comment --><child/></item></root>"#;
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        let data = resolver.dereference("#x").unwrap();
        let node_set = data.into_node_set().unwrap();

        for node in doc.descendants() {
            if node.is_comment() {
                assert!(
                    node_set.contains(node),
                    "comment should be included in #id subtree"
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
        let xml = r#"<root><item ID="abc">content</item></root>"#;
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        let data = resolver.dereference("#xpointer(id('abc'))").unwrap();
        let node_set = data.into_node_set().unwrap();

        let elem = doc
            .descendants()
            .find(|n| n.attribute("ID") == Some("abc"))
            .unwrap();
        assert!(node_set.contains(elem));
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
    fn parse_xpointer_id_variants() {
        // Valid forms
        assert_eq!(super::parse_xpointer_id("xpointer(id('foo'))"), Some("foo"));
        assert_eq!(
            super::parse_xpointer_id(r#"xpointer(id("bar"))"#),
            Some("bar")
        );

        // Invalid forms
        assert_eq!(super::parse_xpointer_id("xpointer(/)"), None);
        assert_eq!(super::parse_xpointer_id("xpointer(id(foo))"), None); // no quotes
        assert_eq!(super::parse_xpointer_id("not-xpointer"), None);
        assert_eq!(super::parse_xpointer_id(""), None);
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
