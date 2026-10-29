//! Path queries over reports and fixtures parsed with the product's own DOM.
//! Names match by local name in any namespace unless a namespace is given.

use xml_sec::{XmlDomDocument, XmlDomNode};

pub(crate) type Node<'a, 'input> = XmlDomNode<'a, 'input>;

/// Reads `path` as text.
pub(crate) fn read(path: &std::path::Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|error| format!("read {}: {error}", path.display()))
}

/// Parses `text`, naming `what` on failure.
pub(crate) fn parse<'input>(
    text: &'input str,
    what: &str,
) -> Result<XmlDomDocument<'input>, String> {
    XmlDomDocument::parse(text).map_err(|error| format!("parse {what}: {error}"))
}

fn named(node: Node<'_, '_>, name: &str, namespace: Option<&str>) -> bool {
    node.is_element()
        && node.tag_name().name() == name
        && namespace.is_none_or(|namespace| node.tag_name().namespace() == Some(namespace))
}

/// The first element child called `name`.
pub(crate) fn child<'a, 'input>(node: Node<'a, 'input>, name: &str) -> Option<Node<'a, 'input>> {
    node.children().find(|child| named(*child, name, None))
}

/// Every element child of `node`.
pub(crate) fn elements<'a, 'input>(
    node: Node<'a, 'input>,
) -> impl Iterator<Item = Node<'a, 'input>> {
    node.children().filter(Node::is_element)
}

/// The text before the first child of the element at `path`; empty when the
/// element has none, absent when the element is missing.
pub(crate) fn text_at(node: Node<'_, '_>, path: &[&str]) -> Option<String> {
    let mut current = node;
    for name in path {
        current = child(current, name)?;
    }
    Some(current.text().unwrap_or_default().to_owned())
}

/// Elements strictly below `node` called `outer`, in document order.
pub(crate) fn below<'a, 'input>(
    node: Node<'a, 'input>,
    outer: &str,
    namespace: Option<&str>,
) -> impl Iterator<Item = Node<'a, 'input>> {
    node.descendants()
        .skip(1)
        .filter(move |candidate| named(*candidate, outer, namespace))
}

/// The first `inner` child of any `outer` element strictly below `node`.
pub(crate) fn find<'a, 'input>(
    node: Node<'a, 'input>,
    outer: &str,
    inner: &str,
) -> Option<Node<'a, 'input>> {
    below(node, outer, None).find_map(|candidate| child(candidate, inner))
}

/// The `DigestValue` texts of every `SignedInfo/Reference` in the document.
pub(crate) fn digest_values(text: &str, what: &str) -> Result<Vec<String>, String> {
    const DS: &str = super::DS;
    let document = parse(text, what)?;
    let mut values = Vec::new();
    for signed_info in below(document.root_element(), "SignedInfo", Some(DS)) {
        for reference in signed_info
            .children()
            .filter(|child| named(*child, "Reference", Some(DS)))
        {
            for value in reference
                .children()
                .filter(|child| named(*child, "DigestValue", Some(DS)))
            {
                values.push(value.text().unwrap_or_default().to_owned());
            }
        }
    }
    Ok(values)
}

/// Every child of `blocks` with a `Conclusion`, mapped by its local name to
/// the conclusion's `field` text.
pub(crate) fn conclusions(
    blocks: Node<'_, '_>,
    field: &str,
) -> serde_json::Map<String, serde_json::Value> {
    elements(blocks)
        .filter(|block| child(*block, "Conclusion").is_some())
        .map(|block| {
            let value =
                text_at(block, &["Conclusion", field]).map_or(serde_json::Value::Null, Into::into);
            (block.tag_name().name().to_owned(), value)
        })
        .collect()
}

/// The `BasicBuildingBlocks` of type `SIGNATURE` in a detailed DSS report.
pub(crate) fn signature_blocks<'a, 'input>(root: Node<'a, 'input>) -> Option<Node<'a, 'input>> {
    below(root, "BasicBuildingBlocks", None)
        .find(|block| block.attribute("Type") == Some("SIGNATURE"))
}
