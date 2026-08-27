//! `roxmltree` parser adapter for the shared semantic arena.

use super::{
    Document, ParseError, ParsingOptions, XmlBackend,
    tree::{AttributeData, NamespaceData, NodeId, NodeKind, TreeBuilder},
};

pub(super) struct RoxmltreeBackend;

impl XmlBackend for RoxmltreeBackend {
    fn parse<'input>(
        input: &'input str,
        options: ParsingOptions,
    ) -> Result<Document<'input>, ParseError> {
        let parsed = ::roxmltree::Document::parse_with_options(
            input,
            ::roxmltree::ParsingOptions {
                allow_dtd: options.allow_dtd,
                nodes_limit: options.nodes_limit,
                entity_resolver: None,
            },
        )
        .map_err(map_error)?;
        let mut target = TreeBuilder::new(input, parsed.descendants().count());
        project_node(&mut target, parsed.root(), None);
        Ok(target.finish())
    }
}

fn map_error(error: ::roxmltree::Error) -> ParseError {
    match error {
        ::roxmltree::Error::DtdDetected => ParseError::DtdDetected,
        ::roxmltree::Error::NodesLimitReached => ParseError::NodesLimitReached,
        other => ParseError::Backend {
            backend: "roxmltree",
            message: other.to_string(),
        },
    }
}

fn project_node(
    target: &mut TreeBuilder<'_>,
    source: ::roxmltree::Node<'_, '_>,
    parent: Option<NodeId>,
) -> NodeId {
    let kind = match source.node_type() {
        ::roxmltree::NodeType::Root => NodeKind::Root,
        ::roxmltree::NodeType::Element => NodeKind::Element {
            name: source.tag_name().name().to_owned(),
            namespace: source.tag_name().namespace().map(str::to_owned),
            prefix: element_prefix(source).map(str::to_owned),
            attributes: source
                .attributes()
                .map(|attribute| AttributeData {
                    name: attribute.name().to_owned(),
                    namespace: attribute.namespace().map(str::to_owned),
                    prefix: attribute_prefix(target.input(), &attribute).map(str::to_owned),
                    value: attribute.value().to_owned(),
                })
                .collect(),
            namespaces: source
                .namespaces()
                .map(|namespace| NamespaceData {
                    prefix: namespace.name().map(str::to_owned),
                    uri: namespace.uri().to_owned(),
                })
                .collect(),
        },
        ::roxmltree::NodeType::Text => NodeKind::Text(source.text().unwrap_or_default().to_owned()),
        ::roxmltree::NodeType::Comment => {
            NodeKind::Comment(source.text().unwrap_or_default().to_owned())
        }
        ::roxmltree::NodeType::PI => {
            let pi = source.pi().expect("PI node exposes PI data");
            NodeKind::PI {
                target: pi.target.to_owned(),
                value: pi.value.map(str::to_owned),
            }
        }
    };
    let id = target.push(parent, kind, source.range());
    for child in source.children() {
        project_node(target, child, Some(id));
    }
    target.finish_subtree(id);
    id
}

fn element_prefix<'a>(node: ::roxmltree::Node<'a, 'a>) -> Option<&'a str> {
    let source = node.document().input_text();
    let start = node.range().start.saturating_add(1);
    let end = source[start..]
        .find(|ch: char| ch.is_ascii_whitespace() || matches!(ch, '>' | '/'))
        .map_or(source.len(), |offset| start + offset);
    source[start..end].split_once(':').map(|(prefix, _)| prefix)
}

fn attribute_prefix<'a>(
    input: &'a str,
    attribute: &::roxmltree::Attribute<'_, '_>,
) -> Option<&'a str> {
    input[attribute.range_qname()]
        .split_once(':')
        .map(|(prefix, _)| prefix)
}
