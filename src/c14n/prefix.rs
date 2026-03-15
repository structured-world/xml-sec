//! Lexical prefix extraction from roxmltree nodes.
//!
//! roxmltree's DOM stores only `(namespace_uri, local_name)` — the lexical
//! prefix is discarded during parsing. We recover it from the source XML
//! using byte-range positions (`roxmltree` `positions` feature).
//!
//! This avoids ambiguity when multiple prefixes bind the same namespace URI
//! (e.g., `xmlns:a="u" xmlns:b="u"`), where `lookup_prefix()` would return
//! an arbitrary match.

use roxmltree::{Attribute, Node};

/// Extract the lexical prefix of an element from the source XML.
///
/// Returns `""` for unprefixed elements, or the prefix string (e.g., `"foo"`
/// for `<foo:Bar>`).
pub(crate) fn element_prefix<'a>(node: Node<'a, '_>) -> &'a str {
    let input = node.document().input_text();
    let range = node.range();

    // range starts at '<', skip it to get to the QName
    let tag_start = range.start + 1;
    let tag_bytes = input.as_bytes();

    // Find end of QName: first space, '>', or '/'
    let mut qname_end = tag_start;
    while qname_end < input.len() {
        match tag_bytes[qname_end] {
            b' ' | b'\t' | b'\n' | b'\r' | b'>' | b'/' => break,
            _ => qname_end += 1,
        }
    }

    let qname = &input[tag_start..qname_end];
    match qname.find(':') {
        Some(pos) => &qname[..pos],
        None => "",
    }
}

/// Extract the lexical prefix of an attribute from the source XML.
///
/// Returns `""` for unprefixed attributes, or the prefix string (e.g., `"xml"`
/// for `xml:lang="en"`).
pub(crate) fn attribute_prefix<'a>(node: Node<'a, '_>, attr: &Attribute<'a, '_>) -> &'a str {
    let input = node.document().input_text();
    let qname_range = attr.range_qname();
    let qname = &input[qname_range];
    match qname.find(':') {
        Some(pos) => &qname[..pos],
        None => "",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use roxmltree::Document;

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
}
