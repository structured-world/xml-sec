//! Lexical prefix access through the backend-neutral semantic tree.

use crate::xml::dom::storage::Storage;
use crate::xml::dom::{Attribute, Node};

/// Exclusive C14N §4 uses the XML whitespace-delimited NMTOKENS format
/// (with its explicit #default token), not Unicode word whitespace.
/// https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/#sec-Use
/// https://www.w3.org/TR/2008/REC-xml-20081126/#NT-S
pub(crate) fn inclusive_tokens(list: &str) -> impl Iterator<Item = &str> {
    list.split([' ', '\t', '\r', '\n'])
        .filter(|token| !token.is_empty())
}

/// Extract the lexical prefix of an element from the source XML.
///
/// Returns `""` for unprefixed elements, or the prefix string (e.g., `"foo"`
/// for `<foo:Bar>`).
pub(crate) fn element_prefix<'a, D: Storage>(node: Node<'a, '_, D>) -> &'a str {
    node.prefix().unwrap_or_default()
}

/// Extract the lexical prefix of an attribute from the source XML.
///
/// Returns `""` for unprefixed attributes, or the prefix string (e.g., `"xml"`
/// for `xml:lang="en"`).
pub(crate) fn attribute_prefix<'a, D: Storage>(
    _node: Node<'a, '_, D>,
    attr: &Attribute<'a, D>,
) -> &'a str {
    attr.prefix().unwrap_or_default()
}

/// Check whether `xmlns=""` on `node` would be meaningful — i.e., whether
/// the in-scope default namespace (as determined by the nearest ancestor
/// `xmlns` declaration) is non-empty and would be undeclared.
///
/// This is needed for correct `xmlns=""` suppression in C14N document subsets:
/// when output ancestors are absent, `parent_rendered` alone cannot determine
/// whether `xmlns=""` is meaningful. We walk the source tree ancestors to
/// find the effective in-scope default namespace.
///
/// Returns `true` if the nearest ancestor element with a default-namespace
/// declaration has `xmlns="<non-empty-uri>"`, meaning `xmlns=""` on `node`
/// would actively undeclare the in-scope default namespace.
pub(crate) fn has_in_scope_default_namespace<D: Storage>(node: Node<'_, '_, D>) -> bool {
    // Walk ancestors to find the nearest default namespace declaration.
    let mut current = node.parent();
    while let Some(n) = current {
        if n.is_element() {
            for ns in n.namespaces() {
                if ns.name().is_none() {
                    // Found a default namespace on an ancestor.
                    // Non-empty URI means xmlns="" would undeclare it.
                    return !ns.uri().is_empty();
                }
            }
        }
        current = n.parent();
    }
    false
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::xml::dom::Document;

    #[test]
    fn prefixed_element() {
        let xml = r#"<foo:Root xmlns:foo="http://foo.com"/>"#;
        let doc = Document::parse(xml).expect("parse");
        let root = doc.root_element();
        assert_eq!(element_prefix(root), "foo");
    }

    #[test]
    fn unprefixed_element() {
        let xml = r#"<Root xmlns="http://default.com"/>"#;
        let doc = Document::parse(xml).expect("parse");
        let root = doc.root_element();
        assert_eq!(element_prefix(root), "");
    }

    #[test]
    fn nested_prefixed_element() {
        let xml = r#"<a:Root xmlns:a="http://a" xmlns:b="http://b"><b:Child/></a:Root>"#;
        let doc = Document::parse(xml).expect("parse");
        let child = doc.root_element().first_element_child().expect("child");
        assert_eq!(element_prefix(child), "b");
    }

    #[test]
    fn prefixed_attribute() {
        let xml = r#"<root xmlns:ns="http://ns" ns:attr="val"/>"#;
        let doc = Document::parse(xml).expect("parse");
        let root = doc.root_element();
        let attr = root.attributes().next().expect("attr");
        assert_eq!(attribute_prefix(root, &attr), "ns");
    }

    #[test]
    fn unprefixed_attribute() {
        let xml = r#"<root plain="val"/>"#;
        let doc = Document::parse(xml).expect("parse");
        let root = doc.root_element();
        let attr = root.attributes().next().expect("attr");
        assert_eq!(attribute_prefix(root, &attr), "");
    }

    #[test]
    fn xml_lang_attribute() {
        let xml = r#"<root xml:lang="en"/>"#;
        let doc = Document::parse(xml).expect("parse");
        let root = doc.root_element();
        let attr = root.attributes().next().expect("attr");
        assert_eq!(attribute_prefix(root, &attr), "xml");
    }

    #[test]
    fn aliased_prefixes_same_uri() {
        // Two prefixes bound to same URI — element uses "b", not "a"
        let xml = r#"<root xmlns:a="http://same" xmlns:b="http://same"><b:child a:x="1"/></root>"#;
        let doc = Document::parse(xml).expect("parse");
        let child = doc.root_element().first_element_child().expect("child");
        assert_eq!(element_prefix(child), "b");
        let attr = child.attributes().next().expect("attr");
        assert_eq!(attribute_prefix(child, &attr), "a");
    }

    #[test]
    fn has_default_ns_from_ancestor() {
        let xml = r#"<root xmlns="http://example.com"><child xmlns=""/></root>"#;
        let doc = Document::parse(xml).expect("parse");
        let root = doc.root_element();
        let child = root.first_element_child().expect("child");
        // root has no ancestor with default ns → false
        assert!(!has_in_scope_default_namespace(root));
        // child's parent (root) has xmlns="http://example.com" → true
        // (child's own xmlns="" means it needs to undeclare it)
        assert!(has_in_scope_default_namespace(child));
    }

    #[test]
    fn no_default_ns() {
        let xml = r#"<root xmlns:a="http://a"><child/></root>"#;
        let doc = Document::parse(xml).expect("parse");
        let root = doc.root_element();
        let child = root.first_element_child().expect("child");
        assert!(!has_in_scope_default_namespace(root));
        assert!(!has_in_scope_default_namespace(child));
    }

    #[test]
    fn inherited_default_ns() {
        let xml = r#"<root xmlns="http://example.com"><child/></root>"#;
        let doc = Document::parse(xml).expect("parse");
        let child = doc.root_element().first_element_child().expect("child");
        // child's parent (root) has xmlns="http://example.com" → true
        assert!(has_in_scope_default_namespace(child));
    }
}
