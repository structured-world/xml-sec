//! `roxmltree` parser adapter for the shared semantic arena.

use super::storage::{Native, Storage, Values};
use crate::parser_roxmltree as backend;

use super::{
    Document, LexicalPreflight, ParseError, ParsingOptions, XmlBackendImplementation,
    tree::{AttributeData, NamespaceData, NodeId, NodeKind, TreeBuilder, range_contains},
};

pub(super) struct RoxmltreeBackend;

#[cfg(feature = "xmldsig")]
impl RoxmltreeBackend {
    pub(super) fn parse_in<'input, 'w, W: structured_asn1::memory::Work>(
        input: &'input str,
        options: ParsingOptions,
        preflight: &LexicalPreflight<'input, super::storage::Accounted<'w, W>>,
        storage: super::storage::Accounted<'w, W>,
    ) -> Result<Document<'input, super::storage::Accounted<'w, W>>, super::AccountedParseError>
    {
        let parsed = backend::Document::parse_with_storage(
            input,
            backend::ParsingOptions {
                allow_dtd: options.allow_dtd,
                nodes_limit: options.nodes_limit,
                entity_resolver: None,
            },
            storage,
        )
        .map_err(|error| {
            super::AccountedParseError::Roxmltree(
                error.map_text(structured_asn1::memory::OwnedText::into_owned),
            )
        })?;
        Ok(project_in(input, &parsed, preflight, storage)?)
    }
}

impl XmlBackendImplementation for RoxmltreeBackend {
    fn parse<'input>(
        input: &'input str,
        options: ParsingOptions,
        preflight: &LexicalPreflight,
    ) -> Result<Document<'input>, ParseError> {
        let parsed = backend::Document::parse_with_options(
            input,
            backend::ParsingOptions {
                allow_dtd: options.allow_dtd,
                nodes_limit: options.nodes_limit,
                entity_resolver: None,
            },
        )
        .map_err(map_error)?;
        project(input, &parsed, preflight)
    }
}

pub(super) fn project<'input>(
    input: &'input str,
    parsed: &backend::Document<'input>,
    preflight: &LexicalPreflight,
) -> Result<Document<'input>, ParseError> {
    project_in(input, parsed, preflight, Native)
}

pub(super) fn project_in<'input, R: Storage, S: Storage, P: Storage>(
    input: &'input str,
    parsed: &backend::Document<'input, R>,
    preflight: &LexicalPreflight<'_, P>,
    storage: S,
) -> Result<Document<'input, S>, ParseError> {
    let mut target = TreeBuilder::new(
        input,
        parsed.descendants().len().max(preflight.node_count()),
        storage,
    )?;
    project_document(
        &mut target,
        parsed.root(),
        preflight.doctype_range(),
        preflight,
    )?;
    target.finish(preflight)
}

fn map_error(error: backend::Error) -> ParseError {
    match error {
        backend::Error::DtdDetected => ParseError::DtdDetected,
        backend::Error::NodesLimitReached => ParseError::NodesLimitReached,
        other => ParseError::Backend {
            backend: "roxmltree",
            message: other.to_string(),
        },
    }
}

enum ProjectionFrame<'document, 'input, R: Storage> {
    Enter {
        source: backend::Node<'document, 'input, R>,
        parent: Option<NodeId>,
        depth: usize,
    },
    Exit(NodeId),
}

fn project_document<R: Storage, S: Storage, P: Storage>(
    target: &mut TreeBuilder<'_, S>,
    root: backend::Node<'_, '_, R>,
    doctype: Option<&std::ops::Range<usize>>,
    preflight: &LexicalPreflight<'_, P>,
) -> Result<(), ParseError> {
    let storage = target.storage();
    let mut stack = storage.values(0)?;
    stack.push(ProjectionFrame::Enter {
        source: root,
        parent: None,
        depth: 0,
    })?;
    while let Some(frame) = stack.pop() {
        storage.charge(1)?;
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
                    backend::NodeType::Root => NodeKind::Root,
                    backend::NodeType::Element => {
                        let mut attributes = storage.values(source.attributes().len())?;
                        for attribute in source.attributes() {
                            storage.charge(1)?;
                            attributes.push(AttributeData {
                                name: storage.text(attribute.name())?,
                                namespace: storage.optional_text(attribute.namespace())?,
                                prefix: storage.optional_text(attribute_prefix(
                                    target.input(),
                                    &attribute,
                                    storage,
                                )?)?,
                                value: storage.text(attribute.value())?,
                                is_id: false,
                                xml_id_error: None,
                            })?;
                        }
                        let mut namespaces = storage.values(source.namespaces().len())?;
                        for namespace in source.namespaces() {
                            storage.charge(1)?;
                            namespaces.push(NamespaceData {
                                prefix: storage.optional_text(namespace.name())?,
                                uri: storage.text(namespace.uri())?,
                            })?;
                        }
                        NodeKind::Element {
                            name: storage.text(source.tag_name().name())?,
                            namespace: storage.optional_text(
                                source.tag_name().namespace().filter(|uri| !uri.is_empty()),
                            )?,
                            prefix: storage.optional_text(element_prefix(source, storage)?)?,
                            attributes,
                            namespaces,
                        }
                    }
                    backend::NodeType::Text => {
                        if let Some((range, actionable)) =
                            preflight.folded_character_data_range(source_range.start)?
                        {
                            source_range = range;
                            range_actionable &= actionable;
                        }
                        NodeKind::Text(storage.text(source.text().unwrap_or_default())?)
                    }
                    backend::NodeType::Comment => {
                        NodeKind::Comment(storage.text(source.text().unwrap_or_default())?)
                    }
                    backend::NodeType::PI => {
                        let pi = source.pi().expect("PI node exposes PI data");
                        NodeKind::PI {
                            target: storage.text(pi.target)?,
                            value: storage.optional_text(pi.value)?,
                        }
                    }
                };
                let id =
                    target.push_with_actionability(parent, kind, source_range, range_actionable)?;
                stack.push(ProjectionFrame::Exit(id))?;
                for child in source.children().rev() {
                    stack.push(ProjectionFrame::Enter {
                        source: child,
                        parent: Some(id),
                        depth: depth + usize::from(child.is_element()),
                    })?;
                }
            }
        }
    }
    Ok(())
}

fn element_prefix<'input, R: Storage, S: Storage>(
    node: backend::Node<'_, 'input, R>,
    storage: S,
) -> Result<Option<&'input str>, ParseError> {
    let source = node.document().input_text();
    let start = node.range().start.saturating_add(1);
    let mut end = start;
    for &byte in &source.as_bytes()[start..] {
        storage.charge(1)?;
        if byte.is_ascii_whitespace() || matches!(byte, b'>' | b'/') {
            break;
        }
        end += 1;
    }
    storage.charge(end - start)?;
    Ok(source[start..end].split_once(':').map(|(prefix, _)| prefix))
}

fn attribute_prefix<'a, R: Storage, S: Storage>(
    input: &'a str,
    attribute: &backend::Attribute<'_, '_, R>,
    storage: S,
) -> Result<Option<&'a str>, ParseError> {
    let name = &input[attribute.range_qname()];
    storage.charge(name.len())?;
    Ok(name.split_once(':').map(|(prefix, _)| prefix))
}
