//! `xmloxide` parser adapter for the shared semantic arena.

use std::ops::Range;

use super::storage::names::NameStorage;
use super::storage::{Native, Storage, Values};
use crate::parser_xmloxide as xmloxide;
use xmloxide::tree::{NodeId as XmloxNodeId, NodeKind as XmloxNodeKind};

use super::{
    Document, LexicalPreflight, ParseError, ParsingOptions, XmlBackendImplementation,
    preflight::{PositionCursor, SourceKind},
    tree::{AttributeData, NamespaceData, NodeId, NodeKind, TreeBuilder},
};

pub(super) struct XmloxideBackend;

#[cfg(feature = "xmldsig")]
impl XmloxideBackend {
    pub(super) fn parse_in<'input, 'w, W: structured_asn1::memory::Work>(
        input: &'input str,
        options: ParsingOptions,
        preflight: &LexicalPreflight<'input, super::storage::Accounted<'w, W>>,
        storage: super::storage::Accounted<'w, W>,
    ) -> Result<Document<'input, super::storage::Accounted<'w, W>>, super::AccountedParseError>
    {
        let parsed = xmloxide::parser::XmlParser::with_storage(input, &backend_options(), storage)
            .and_then(xmloxide::parser::XmlParser::parse)
            .map_err(|error| match error {
                xmloxide::error::ParseError::Resource(error) => {
                    super::AccountedParseError::Semantic(error)
                }
                xmloxide::error::ParseError::Syntax {
                    message,
                    location,
                    diagnostics,
                } => super::AccountedParseError::Xmloxide(xmloxide::error::ParseError::Syntax {
                    message,
                    location,
                    diagnostics: diagnostics.into_owned(),
                }),
            })?;
        Ok(project_in(input, &parsed, options, preflight, storage)?)
    }
}

impl XmlBackendImplementation for XmloxideBackend {
    fn parse<'input>(
        input: &'input str,
        options: ParsingOptions,
        preflight: &LexicalPreflight,
    ) -> Result<Document<'input>, ParseError> {
        let parsed = xmloxide::parser::parse_str_with_options(input, &backend_options()).map_err(
            |error| match error {
                xmloxide::error::ParseError::Resource(error) => error,
                error @ xmloxide::error::ParseError::Syntax { .. } => ParseError::Backend {
                    backend: "xmloxide",
                    message: error.to_string(),
                },
            },
        )?;
        project(input, &parsed, options, preflight)
    }
}

pub(super) fn project<'input>(
    input: &'input str,
    parsed: &xmloxide::Document,
    options: ParsingOptions,
    preflight: &LexicalPreflight,
) -> Result<Document<'input>, ParseError> {
    project_in(input, parsed, options, preflight, Native)
}

pub(super) fn project_in<'input, S: Storage, P: Storage, R: NameStorage>(
    input: &'input str,
    parsed: &xmloxide::Document<R>,
    options: ParsingOptions,
    preflight: &LexicalPreflight<'_, P>,
    storage: S,
) -> Result<Document<'input, S>, ParseError> {
    if options.nodes_limit == 0 {
        return Err(ParseError::NodesLimitReached);
    }
    let mut projector = Projector {
        source: parsed,
        target: TreeBuilder::new(
            input,
            parsed.node_count().min(options.nodes_limit as usize),
            storage,
        )?,
        positions: preflight.positions(),
        nodes_limit: options.nodes_limit,
    };
    let root = projector
        .target
        .push(None, NodeKind::Root, 0..input.len())?;
    projector.project_children(parsed.root(), root)?;
    projector.positions.finish()?;
    projector.target.finish_subtree(root);
    projector.target.finish(preflight)
}

pub(super) fn backend_options() -> xmloxide::parser::ParseOptions {
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

struct Projector<'source, 'input, 'positions, S: Storage = Native, R: NameStorage = Native> {
    source: &'source xmloxide::Document<R>,
    target: TreeBuilder<'input, S>,
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

impl<S: Storage, R: NameStorage> Projector<'_, '_, '_, S, R> {
    fn project_children(&mut self, source: XmloxNodeId, parent: NodeId) -> Result<(), ParseError> {
        let storage = self.target.storage();
        let mut stack = storage.values(0)?;
        self.push_children(&mut stack, source, parent, None, None, true)?;
        while let Some(frame) = stack.pop() {
            storage.charge(1)?;
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
                                inherited_range.as_ref(),
                                range_actionable,
                            )?;
                        }
                        kind @ XmloxNodeKind::Element { .. } => {
                            let node = self.project_element(
                                kind,
                                parent,
                                namespace_owner,
                                inherited_range.as_ref(),
                                range_actionable,
                            )?;
                            stack.push(ProjectionFrame::Exit(node))?;
                            self.push_children(
                                &mut stack,
                                source,
                                node,
                                Some(node),
                                inherited_range.as_ref(),
                                range_actionable,
                            )?;
                        }
                        kind @ (XmloxNodeKind::Text { .. }
                        | XmloxNodeKind::CData { .. }
                        | XmloxNodeKind::Comment { .. }
                        | XmloxNodeKind::ProcessingInstruction { .. }) => {
                            self.project_leaf(
                                source,
                                parent,
                                kind,
                                inherited_range,
                                range_actionable,
                            )?;
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
                                    Some(&range),
                                    false,
                                )?;
                            } else if let Some(value) = value {
                                self.admit_text(parent)?;
                                self.target.append_text(parent, value, range, false)?;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn project_element(
        &mut self,
        kind: &XmloxNodeKind<R>,
        parent: NodeId,
        namespace_owner: Option<NodeId>,
        inherited_range: Option<&Range<usize>>,
        range_actionable: bool,
    ) -> Result<NodeId, ParseError> {
        let XmloxNodeKind::Element {
            name,
            prefix,
            namespace,
            attributes,
        } = kind
        else {
            unreachable!("element projection requires an element");
        };
        let storage = self.target.storage();
        self.admit_node()?;
        let range = match inherited_range {
            Some(range) => range.clone(),
            None => self.positions.take(SourceKind::Element)?,
        };
        let inherited = namespace_owner
            .and_then(|owner| self.target.namespaces(owner))
            .unwrap_or_default();
        let mut namespaces = storage.values(inherited.len())?;
        for namespace in inherited {
            storage.charge(1)?;
            namespaces.push(NamespaceData {
                prefix: storage.optional_text(namespace.prefix.as_deref())?,
                uri: storage.text(namespace.uri.as_ref())?,
            })?;
        }
        let mut semantic_attributes = storage.values(attributes.len())?;
        for attribute in &**attributes {
            storage.charge(1)?;
            if attribute.prefix.as_deref() == Some("xmlns") {
                set_namespace(
                    &mut namespaces,
                    Some(&attribute.name),
                    &attribute.value,
                    storage,
                )?;
            } else if attribute.prefix.is_none() && attribute.name.as_ref() == "xmlns" {
                set_namespace(&mut namespaces, None, &attribute.value, storage)?;
            } else {
                semantic_attributes.push(AttributeData {
                    name: storage.text(&attribute.name)?,
                    namespace: storage.optional_text(attribute.namespace.as_deref())?,
                    prefix: storage.optional_text(attribute.prefix.as_deref())?,
                    value: storage.text(&attribute.value)?,
                    is_id: false,
                    xml_id_error: None,
                })?;
            }
        }
        self.target.push_with_actionability(
            Some(parent),
            NodeKind::Element {
                name: storage.text(name)?,
                namespace: storage
                    .optional_text(namespace.as_deref().filter(|uri| !uri.is_empty()))?,
                prefix: storage.optional_text(prefix.as_deref())?,
                attributes: semantic_attributes,
                namespaces,
            },
            range,
            range_actionable,
        )
    }

    fn project_leaf(
        &mut self,
        source: XmloxNodeId,
        parent: NodeId,
        kind: &XmloxNodeKind<R>,
        inherited_range: Option<Range<usize>>,
        range_actionable: bool,
    ) -> Result<(), ParseError> {
        let storage = self.target.storage();
        match kind {
            XmloxNodeKind::Text { content } => {
                if self.source.parent(source) == Some(self.source.root()) {
                    storage.charge(content.len())?;
                    if content.chars().all(char::is_whitespace) {
                        return Ok(());
                    }
                }
                self.admit_text(parent)?;
                let range = match inherited_range {
                    Some(range) => range,
                    None => self.positions.take(SourceKind::Text)?,
                };
                self.target
                    .append_text(parent, content, range, range_actionable)?;
            }
            XmloxNodeKind::CData { content } => {
                self.admit_text(parent)?;
                let range = match inherited_range {
                    Some(range) => range,
                    None => self.positions.take(SourceKind::CData)?,
                };
                self.target
                    .append_text(parent, content, range, range_actionable)?;
            }
            XmloxNodeKind::Comment { content } => {
                self.admit_node()?;
                let range = match inherited_range {
                    Some(range) => range,
                    None => self.positions.take(SourceKind::Comment)?,
                };
                self.target.push_with_actionability(
                    Some(parent),
                    NodeKind::Comment(storage.text(content)?),
                    range,
                    range_actionable,
                )?;
            }
            XmloxNodeKind::ProcessingInstruction {
                target: pi_target,
                data,
            } => {
                self.admit_node()?;
                let range = match inherited_range {
                    Some(range) => range,
                    None => self.positions.take(SourceKind::Pi)?,
                };
                self.target.push_with_actionability(
                    Some(parent),
                    NodeKind::PI {
                        target: storage.text(pi_target)?,
                        value: storage.optional_text(data.as_deref())?,
                    },
                    range,
                    range_actionable,
                )?;
            }
            _ => unreachable!("leaf projection requires a leaf"),
        }
        Ok(())
    }

    fn push_children(
        &self,
        stack: &mut S::Values<ProjectionFrame>,
        source: XmloxNodeId,
        parent: NodeId,
        namespace_owner: Option<NodeId>,
        inherited_range: Option<&Range<usize>>,
        range_actionable: bool,
    ) -> Result<(), ParseError> {
        // Walk linked siblings backwards instead of allocating a second child
        // vector merely to reverse iteration.
        let mut child = self.source.last_child(source);
        while let Some(current) = child {
            stack.push(ProjectionFrame::Enter {
                source: current,
                parent,
                namespace_owner,
                inherited_range: inherited_range.cloned(),
                range_actionable,
            })?;
            child = self.source.prev_sibling(current);
        }
        Ok(())
    }

    fn admit_node(&self) -> Result<(), ParseError> {
        if self.target.len() >= self.nodes_limit as usize {
            Err(ParseError::NodesLimitReached)
        } else {
            Ok(())
        }
    }

    fn admit_text(&self, parent: NodeId) -> Result<(), ParseError> {
        if self.target.len() < self.nodes_limit as usize || self.target.has_text_tail(parent) {
            return Ok(());
        }
        Err(ParseError::NodesLimitReached)
    }
}

fn set_namespace<S: Storage>(
    namespaces: &mut S::Values<NamespaceData<S>>,
    prefix: Option<&str>,
    uri: &str,
    storage: S,
) -> Result<(), ParseError> {
    for existing in namespaces.iter_mut() {
        storage.charge(1)?;
        storage.charge(prefix.map_or(0, str::len))?;
        if existing.prefix.as_deref() == prefix {
            existing.uri = storage.text(uri)?;
            return Ok(());
        }
    }
    namespaces.push(NamespaceData {
        prefix: storage.optional_text(prefix)?,
        uri: storage.text(uri)?,
    })?;
    Ok(())
}
