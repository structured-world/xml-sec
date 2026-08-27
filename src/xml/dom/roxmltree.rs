//! `roxmltree` parser adapter for the shared semantic arena.

use super::{
    Document, LexicalPreflight, ParseError, ParsingOptions, XmlBackend,
    tree::{AttributeData, NamespaceData, NodeId, NodeKind, TreeBuilder, range_contains},
};

pub(super) struct RoxmltreeBackend;

impl XmlBackend for RoxmltreeBackend {
    fn parse<'input>(
        input: &'input str,
        options: ParsingOptions,
        preflight: &LexicalPreflight,
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
        let mut target = TreeBuilder::new(
            input,
            parsed.descendants().count().max(preflight.node_count()),
        );
        project_document(
            &mut target,
            parsed.root(),
            preflight.doctype_range(),
            preflight,
        )?;
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

enum ProjectionFrame<'document, 'input> {
    Enter {
        source: ::roxmltree::Node<'document, 'input>,
        parent: Option<NodeId>,
        depth: usize,
    },
    Exit(NodeId),
}

fn project_document<'document, 'input>(
    target: &mut TreeBuilder<'_>,
    root: ::roxmltree::Node<'document, 'input>,
    doctype: Option<&std::ops::Range<usize>>,
    preflight: &LexicalPreflight,
) -> Result<(), ParseError> {
    let mut stack = vec![ProjectionFrame::Enter {
        source: root,
        parent: None,
        depth: 0,
    }];
    while let Some(frame) = stack.pop() {
        match frame {
            ProjectionFrame::Exit(node) => target.finish_subtree(node),
            ProjectionFrame::Enter {
                source,
                parent,
                depth,
            } => {
                let mut source_range = source.range();
                let inside_doctype =
                    doctype.is_some_and(|range| range_contains(range, &source_range));
                let mut range_actionable = !inside_doctype;
                if source.parent().is_some_and(|node| node.is_root()) && inside_doctype {
                    continue;
                }
                if source.is_element() && depth > crate::hard_limits::XML_DOCUMENT_DEPTH_CEILING {
                    return Err(ParseError::DepthLimitReached {
                        maximum: crate::hard_limits::XML_DOCUMENT_DEPTH_CEILING,
                        actual: depth,
                    });
                }
                let kind = match source.node_type() {
                    ::roxmltree::NodeType::Root => NodeKind::Root,
                    ::roxmltree::NodeType::Element => NodeKind::Element {
                        name: source.tag_name().name().to_owned(),
                        namespace: source
                            .tag_name()
                            .namespace()
                            .filter(|uri| !uri.is_empty())
                            .map(str::to_owned),
                        prefix: element_prefix(source).map(str::to_owned),
                        attributes: source
                            .attributes()
                            .map(|attribute| AttributeData {
                                name: attribute.name().to_owned(),
                                namespace: attribute.namespace().map(str::to_owned),
                                prefix: attribute_prefix(target.input(), &attribute)
                                    .map(str::to_owned),
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
                    ::roxmltree::NodeType::Text => {
                        if let Some((range, actionable)) =
                            preflight.folded_character_data_range(source_range.start)
                        {
                            source_range = range;
                            range_actionable &= actionable;
                        }
                        NodeKind::Text(source.text().unwrap_or_default().to_owned())
                    }
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
                let id =
                    target.push_with_actionability(parent, kind, source_range, range_actionable);
                stack.push(ProjectionFrame::Exit(id));
                for child in source.children().rev() {
                    stack.push(ProjectionFrame::Enter {
                        source: child,
                        parent: Some(id),
                        depth: depth + usize::from(child.is_element()),
                    });
                }
            }
        }
    }
    Ok(())
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
