//! `xmloxide` parser adapter for the shared semantic arena.

use std::ops::Range;

use xmloxide::tree::{NodeId as XmloxNodeId, NodeKind as XmloxNodeKind};

use super::{
    Document, LexicalPreflight, ParseError, ParsingOptions, XmlBackend,
    preflight::{PositionCursor, SourceKind},
    tree::{AttributeData, NamespaceData, NodeId, NodeKind, TreeBuilder},
};

pub(super) struct XmloxideBackend;

impl XmlBackend for XmloxideBackend {
    fn parse<'input>(
        input: &'input str,
        options: ParsingOptions,
        preflight: &LexicalPreflight,
    ) -> Result<Document<'input>, ParseError> {
        let parsed = xmloxide::parser::parse_str_with_options(input, &backend_options()).map_err(
            |error| ParseError::Backend {
                backend: "xmloxide",
                message: error.to_string(),
            },
        )?;
        let mut projector = Projector {
            source: &parsed,
            target: TreeBuilder::new(input, parsed.node_count()),
            positions: preflight.positions(),
            nodes_limit: options.nodes_limit,
        };
        let root = projector.target.push(None, NodeKind::Root, 0..input.len());
        projector.project_children(parsed.root(), root)?;
        projector.positions.finish()?;
        projector.target.finish_subtree(root);
        Ok(projector.target.finish())
    }
}

fn backend_options() -> xmloxide::parser::ParseOptions {
    // The shared preflight owns the backend-neutral contract. These absolute
    // limits are defense in depth against a backend regression allocating
    // expanded entity data before returning control to the projector.
    xmloxide::parser::ParseOptions::default()
        .max_depth(
            u32::try_from(crate::hard_limits::XML_DOCUMENT_DEPTH_CEILING)
                .expect("XML depth ceiling fits into u32"),
        )
        .max_attributes(u32::MAX)
        .max_attribute_length(usize::MAX)
        .max_text_length(crate::hard_limits::XML_ENTITY_EXPANSION_WORK_BYTE_CEILING)
        .max_name_length(usize::MAX)
        .max_entity_expansions(crate::hard_limits::XML_ENTITY_EXPANSION_CEILING)
}

struct Projector<'source, 'input, 'positions> {
    source: &'source xmloxide::Document,
    target: TreeBuilder<'input>,
    positions: PositionCursor<'positions>,
    nodes_limit: u32,
}

enum ProjectionFrame {
    Enter {
        source: XmloxNodeId,
        parent: NodeId,
        namespace_owner: Option<NodeId>,
        inherited_range: Option<Range<usize>>,
        range_actionable: bool,
    },
    Exit(NodeId),
}

impl Projector<'_, '_, '_> {
    fn project_children(&mut self, source: XmloxNodeId, parent: NodeId) -> Result<(), ParseError> {
        let mut stack = Vec::new();
        self.push_children(&mut stack, source, parent, None, None, true);
        while let Some(frame) = stack.pop() {
            match frame {
                ProjectionFrame::Exit(node) => self.target.finish_subtree(node),
                ProjectionFrame::Enter {
                    source,
                    parent,
                    namespace_owner,
                    inherited_range,
                    range_actionable,
                } => {
                    let source_node = self.source.node(source);
                    match &source_node.kind {
                        XmloxNodeKind::Document | XmloxNodeKind::DocumentType { .. } => {
                            self.push_children(
                                &mut stack,
                                source,
                                parent,
                                namespace_owner,
                                inherited_range,
                                range_actionable,
                            );
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
                            let mut namespaces = namespace_owner
                                .and_then(|owner| self.target.namespaces(owner))
                                .unwrap_or_default()
                                .to_vec();
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
                            let node = self.target.push_with_actionability(
                                Some(parent),
                                NodeKind::Element {
                                    name: name.clone(),
                                    namespace: namespace
                                        .as_deref()
                                        .filter(|uri| !uri.is_empty())
                                        .map(str::to_owned),
                                    prefix: prefix.clone(),
                                    attributes: semantic_attributes,
                                    namespaces,
                                },
                                range,
                                range_actionable,
                            );
                            self.enforce_node_limit()?;
                            stack.push(ProjectionFrame::Exit(node));
                            self.push_children(
                                &mut stack,
                                source,
                                node,
                                Some(node),
                                inherited_range,
                                range_actionable,
                            );
                        }
                        XmloxNodeKind::Text { content } => {
                            if self.source.parent(source) == Some(self.source.root())
                                && content.chars().all(char::is_whitespace)
                            {
                                continue;
                            }
                            let range = match inherited_range {
                                Some(range) => range,
                                None => self.positions.take(SourceKind::Text)?,
                            };
                            self.target
                                .append_text(parent, content, range, range_actionable);
                            self.enforce_node_limit()?;
                        }
                        XmloxNodeKind::CData { content } => {
                            let range = match inherited_range {
                                Some(range) => range,
                                None => self.positions.take(SourceKind::CData)?,
                            };
                            self.target
                                .append_text(parent, content, range, range_actionable);
                            self.enforce_node_limit()?;
                        }
                        XmloxNodeKind::Comment { content } => {
                            let range = match inherited_range {
                                Some(range) => range,
                                None => self.positions.take(SourceKind::Comment)?,
                            };
                            self.target.push_with_actionability(
                                Some(parent),
                                NodeKind::Comment(content.clone()),
                                range,
                                range_actionable,
                            );
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
                            self.target.push_with_actionability(
                                Some(parent),
                                NodeKind::PI {
                                    target: pi_target.clone(),
                                    value: data.clone(),
                                },
                                range,
                                range_actionable,
                            );
                            self.enforce_node_limit()?;
                        }
                        XmloxNodeKind::EntityRef { value, .. } => {
                            let range = match inherited_range {
                                Some(range) => range,
                                None => self.positions.take(SourceKind::EntityRef)?,
                            };
                            if self.source.children(source).next().is_some() {
                                self.push_children(
                                    &mut stack,
                                    source,
                                    parent,
                                    namespace_owner,
                                    Some(range),
                                    false,
                                );
                            } else if let Some(value) = value {
                                self.target.append_text(parent, value, range, false);
                                self.enforce_node_limit()?;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn push_children(
        &self,
        stack: &mut Vec<ProjectionFrame>,
        source: XmloxNodeId,
        parent: NodeId,
        namespace_owner: Option<NodeId>,
        inherited_range: Option<Range<usize>>,
        range_actionable: bool,
    ) {
        let children = self.source.children(source).collect::<Vec<_>>();
        for child in children.into_iter().rev() {
            stack.push(ProjectionFrame::Enter {
                source: child,
                parent,
                namespace_owner,
                inherited_range: inherited_range.clone(),
                range_actionable,
            });
        }
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
