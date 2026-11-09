//! Markup of one node of a tree-backed document, written from its semantic
//! view: what a parsed document reads as the node's source range.

use alloc::string::String;

use crate::{Node, NodeType};

/// Append the markup of `node` and its descendants to `output`.
///
/// Each element declares the bindings its parent does not have, as a start
/// tag in the source would, so the markup parses back to the same node in
/// the node's own context. Character data and attribute values are escaped
/// so that parsing reproduces them exactly, including the whitespace that
/// attribute-value normalization (XML 1.0 section 3.3.3) would otherwise
/// change.
pub(super) fn write_node(node: Node<'_, '_>, output: &mut String) {
    match node.node_type() {
        NodeType::Root => {
            for child in node.children() {
                write_node(child, output);
            }
        }
        NodeType::Element => {
            output.push('<');
            push_qualified(node.prefix(), node.tag_name().name(), output);
            let parent = node.parent_element();
            for namespace in node.namespaces() {
                let inherited = parent
                    .and_then(|parent| parent.lookup_namespace_uri(namespace.name()))
                    .unwrap_or_default();
                if inherited == namespace.uri() {
                    continue;
                }
                match namespace.name() {
                    Some(prefix) => {
                        output.push_str(" xmlns:");
                        output.push_str(prefix);
                    }
                    None => output.push_str(" xmlns"),
                }
                output.push_str("=\"");
                escape(namespace.uri(), true, output);
                output.push('"');
            }
            for attribute in node.attributes() {
                output.push(' ');
                match attribute.namespace() {
                    Some("http://www.w3.org/XML/1998/namespace") => output.push_str("xml:"),
                    Some(_) => {
                        if let Some(prefix) = attribute.prefix() {
                            output.push_str(prefix);
                            output.push(':');
                        }
                    }
                    None => {}
                }
                output.push_str(attribute.name());
                output.push_str("=\"");
                escape(attribute.value(), true, output);
                output.push('"');
            }
            if node.first_child().is_none() {
                output.push_str("/>");
                return;
            }
            output.push('>');
            for child in node.children() {
                write_node(child, output);
            }
            output.push_str("</");
            push_qualified(node.prefix(), node.tag_name().name(), output);
            output.push('>');
        }
        NodeType::Text => escape(node.text().unwrap_or_default(), false, output),
        NodeType::Comment => {
            output.push_str("<!--");
            output.push_str(node.text().unwrap_or_default());
            output.push_str("-->");
        }
        NodeType::PI => {
            if let Some(pi) = node.pi() {
                output.push_str("<?");
                output.push_str(pi.target);
                if let Some(value) = pi.value {
                    output.push(' ');
                    output.push_str(value);
                }
                output.push_str("?>");
            }
        }
    }
}

fn push_qualified(prefix: Option<&str>, local: &str, output: &mut String) {
    if let Some(prefix) = prefix {
        output.push_str(prefix);
        output.push(':');
    }
    output.push_str(local);
}

fn escape(value: &str, attribute: bool, output: &mut String) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            // `]]>` may not occur in character data (XML 1.0 section 2.4).
            '>' => output.push_str("&gt;"),
            '"' if attribute => output.push_str("&quot;"),
            '\t' if attribute => output.push_str("&#x9;"),
            '\n' if attribute => output.push_str("&#xA;"),
            // A literal CR is normalized away by every parse (section 2.11).
            '\r' => output.push_str("&#xD;"),
            character => output.push(character),
        }
    }
}
