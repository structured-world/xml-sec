//! `xmloxide` parser adapter for the shared semantic arena.

use std::ops::Range;

use quick_xml::{Reader, events::Event};
use xmloxide::tree::{NodeId as XmloxNodeId, NodeKind as XmloxNodeKind};

use super::{
    Document, ParseError, ParsingOptions, XmlBackend,
    tree::{AttributeData, NamespaceData, NodeId, NodeKind, TreeBuilder},
};

pub(super) struct XmloxideBackend;

impl XmlBackend for XmloxideBackend {
    fn parse<'input>(
        input: &'input str,
        options: ParsingOptions,
    ) -> Result<Document<'input>, ParseError> {
        let positions = SourcePositions::scan(input, options.allow_dtd)?;
        let parsed = xmloxide::parser::parse_str_with_options(input, &backend_options()).map_err(
            |error| ParseError::Backend {
                backend: "xmloxide",
                message: error.to_string(),
            },
        )?;
        let mut projector = Projector {
            source: &parsed,
            target: TreeBuilder::new(input, parsed.node_count()),
            positions: PositionCursor::new(positions),
            nodes_limit: options.nodes_limit,
        };
        let root = projector.target.push(None, NodeKind::Root, 0..input.len());
        for child in parsed.children(parsed.root()) {
            projector.project_node(child, root, &[], None)?;
        }
        projector.positions.finish()?;
        projector.target.finish_subtree(root);
        Ok(projector.target.finish())
    }
}

fn backend_options() -> xmloxide::parser::ParseOptions {
    // The common streaming preflight owns deployment limits. Backend-local
    // defaults must not make the selected parser expose a narrower contract.
    xmloxide::parser::ParseOptions::default()
        .max_depth(u32::MAX)
        .max_attributes(u32::MAX)
        .max_attribute_length(usize::MAX)
        .max_text_length(usize::MAX)
        .max_name_length(usize::MAX)
        .max_entity_expansions(u32::MAX)
}

struct Projector<'source, 'input> {
    source: &'source xmloxide::Document,
    target: TreeBuilder<'input>,
    positions: PositionCursor,
    nodes_limit: u32,
}

impl Projector<'_, '_> {
    fn project_node(
        &mut self,
        source_id: XmloxNodeId,
        parent: NodeId,
        inherited_namespaces: &[NamespaceData],
        inherited_range: Option<Range<usize>>,
    ) -> Result<(), ParseError> {
        let source_node = self.source.node(source_id);
        match &source_node.kind {
            XmloxNodeKind::Document | XmloxNodeKind::DocumentType { .. } => {
                for child in self.source.children(source_id) {
                    self.project_node(
                        child,
                        parent,
                        inherited_namespaces,
                        inherited_range.clone(),
                    )?;
                }
            }
            XmloxNodeKind::Element {
                name,
                prefix,
                namespace,
                attributes,
            } => {
                let range = match inherited_range.clone() {
                    Some(range) => range,
                    None => self.positions.take(SourceKind::Element)?,
                };
                let mut namespaces = inherited_namespaces.to_vec();
                let mut semantic_attributes = Vec::with_capacity(attributes.len());
                for attribute in attributes {
                    if attribute.prefix.as_deref() == Some("xmlns") {
                        set_namespace(
                            &mut namespaces,
                            Some(attribute.name.clone()),
                            attribute.value.clone(),
                        );
                    } else if attribute.prefix.is_none() && attribute.name == "xmlns" {
                        set_namespace(&mut namespaces, None, attribute.value.clone());
                    } else {
                        semantic_attributes.push(AttributeData {
                            name: attribute.name.clone(),
                            namespace: attribute.namespace.clone(),
                            prefix: attribute.prefix.clone(),
                            value: attribute.value.clone(),
                        });
                    }
                }
                let node = self.target.push(
                    Some(parent),
                    NodeKind::Element {
                        name: name.clone(),
                        namespace: namespace.clone(),
                        prefix: prefix.clone(),
                        attributes: semantic_attributes,
                        namespaces,
                    },
                    range,
                );
                self.enforce_node_limit()?;
                let child_namespaces = self.target_namespace_snapshot(node);
                for child in self.source.children(source_id) {
                    self.project_node(child, node, &child_namespaces, inherited_range.clone())?;
                }
                self.target.finish_subtree(node);
            }
            XmloxNodeKind::Text { content } => {
                if self.source.parent(source_id) == Some(self.source.root())
                    && content.chars().all(char::is_whitespace)
                {
                    return Ok(());
                }
                let range = match inherited_range {
                    Some(range) => range,
                    None => self.positions.take(SourceKind::Text)?,
                };
                self.target.append_text(parent, content, range);
                self.enforce_node_limit()?;
            }
            XmloxNodeKind::CData { content } => {
                let range = match inherited_range {
                    Some(range) => range,
                    None => self.positions.take(SourceKind::CData)?,
                };
                self.target.append_text(parent, content, range);
                self.enforce_node_limit()?;
            }
            XmloxNodeKind::Comment { content } => {
                let range = match inherited_range {
                    Some(range) => range,
                    None => self.positions.take(SourceKind::Comment)?,
                };
                self.target
                    .push(Some(parent), NodeKind::Comment(content.clone()), range);
                self.enforce_node_limit()?;
            }
            XmloxNodeKind::ProcessingInstruction {
                target: pi_target,
                data,
            } => {
                let range = match inherited_range {
                    Some(range) => range,
                    None => self.positions.take(SourceKind::Pi)?,
                };
                self.target.push(
                    Some(parent),
                    NodeKind::PI {
                        target: pi_target.clone(),
                        value: data.clone(),
                    },
                    range,
                );
                self.enforce_node_limit()?;
            }
            XmloxNodeKind::EntityRef { value, .. } => {
                let range = match inherited_range {
                    Some(range) => range,
                    None => self.positions.take(SourceKind::EntityRef)?,
                };
                let mut children = self.source.children(source_id).peekable();
                if children.peek().is_some() {
                    for child in children {
                        self.project_node(
                            child,
                            parent,
                            inherited_namespaces,
                            Some(range.clone()),
                        )?;
                    }
                } else if let Some(value) = value {
                    self.target.append_text(parent, value, range);
                    self.enforce_node_limit()?;
                }
            }
        }
        Ok(())
    }

    fn target_namespace_snapshot(&self, node: NodeId) -> Vec<NamespaceData> {
        self.target
            .namespaces(node)
            .expect("newly projected element contains namespaces")
            .to_vec()
    }

    fn enforce_node_limit(&self) -> Result<(), ParseError> {
        if self.target.len() > self.nodes_limit as usize {
            Err(ParseError::NodesLimitReached)
        } else {
            Ok(())
        }
    }
}

fn set_namespace(namespaces: &mut Vec<NamespaceData>, prefix: Option<String>, uri: String) {
    if let Some(existing) = namespaces.iter_mut().find(|item| item.prefix == prefix) {
        existing.uri = uri;
    } else {
        namespaces.push(NamespaceData { prefix, uri });
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SourceKind {
    Element,
    Text,
    CData,
    EntityRef,
    Comment,
    Pi,
}

struct SourceNode {
    kind: SourceKind,
    range: Range<usize>,
}

struct SourcePositions {
    nodes: Vec<SourceNode>,
}

impl SourcePositions {
    fn scan(input: &str, allow_dtd: bool) -> Result<Self, ParseError> {
        let mut reader = Reader::from_str(input);
        let mut nodes: Vec<SourceNode> = Vec::new();
        let mut elements = Vec::new();
        loop {
            let start = source_offset(reader.buffer_position())?;
            let event = reader.read_event().map_err(|error| ParseError::Backend {
                backend: "xmloxide-source-map",
                message: error.to_string(),
            })?;
            let end = source_offset(reader.buffer_position())?;
            match event {
                Event::Start(_) => {
                    let index = nodes.len();
                    nodes.push(SourceNode {
                        kind: SourceKind::Element,
                        range: start..end,
                    });
                    elements.push(index);
                }
                Event::Empty(_) => nodes.push(SourceNode {
                    kind: SourceKind::Element,
                    range: start..end,
                }),
                Event::End(_) => {
                    if let Some(index) = elements.pop() {
                        nodes[index].range.end = end;
                    }
                }
                // Both supported DOMs omit whitespace outside the document
                // element. Keeping it in the sidecar would shift every later
                // source position even though no semantic node owns it.
                Event::Text(_) if !elements.is_empty() => {
                    push_text_position(&mut nodes, start..end);
                }
                Event::Text(_) => {}
                Event::CData(_) => nodes.push(SourceNode {
                    kind: SourceKind::CData,
                    range: start..end,
                }),
                Event::GeneralRef(reference)
                    if is_builtin_or_character_reference(reference.as_ref()) =>
                {
                    push_text_position(&mut nodes, start..end);
                }
                Event::GeneralRef(_) => nodes.push(SourceNode {
                    kind: SourceKind::EntityRef,
                    range: start..end,
                }),
                Event::Comment(_) => nodes.push(SourceNode {
                    kind: SourceKind::Comment,
                    range: start..end,
                }),
                Event::PI(_) => nodes.push(SourceNode {
                    kind: SourceKind::Pi,
                    range: start..end,
                }),
                Event::DocType(_) if !allow_dtd => return Err(ParseError::DtdDetected),
                Event::Eof => break,
                _ => {}
            }
        }
        Ok(Self { nodes })
    }
}

fn push_text_position(nodes: &mut Vec<SourceNode>, range: Range<usize>) {
    if let Some(previous) = nodes.last_mut()
        && previous.kind == SourceKind::Text
        && previous.range.end == range.start
    {
        previous.range.end = range.end;
    } else {
        nodes.push(SourceNode {
            kind: SourceKind::Text,
            range,
        });
    }
}

fn is_builtin_or_character_reference(reference: &[u8]) -> bool {
    reference.starts_with(b"#") || matches!(reference, b"amp" | b"lt" | b"gt" | b"apos" | b"quot")
}

fn source_offset(offset: u64) -> Result<usize, ParseError> {
    usize::try_from(offset).map_err(|_| ParseError::Backend {
        backend: "xmloxide-source-map",
        message: "XML source offset exceeds the platform address space".to_owned(),
    })
}

struct PositionCursor {
    positions: SourcePositions,
    next: usize,
}

impl PositionCursor {
    fn new(positions: SourcePositions) -> Self {
        Self { positions, next: 0 }
    }

    fn take(&mut self, expected: SourceKind) -> Result<Range<usize>, ParseError> {
        let Some(node) = self.positions.nodes.get(self.next) else {
            return Err(source_map_mismatch(format!(
                "expected {expected:?}, but the lexical stream ended"
            )));
        };
        if node.kind != expected {
            return Err(source_map_mismatch(format!(
                "expected {expected:?}, found {:?}",
                node.kind
            )));
        }
        self.next += 1;
        Ok(node.range.clone())
    }

    fn finish(&self) -> Result<(), ParseError> {
        if let Some(node) = self.positions.nodes.get(self.next) {
            Err(source_map_mismatch(format!(
                "unmapped lexical {:?} node remains",
                node.kind
            )))
        } else {
            Ok(())
        }
    }
}

fn source_map_mismatch(message: String) -> ParseError {
    ParseError::Backend {
        backend: "xmloxide-source-map",
        message,
    }
}
