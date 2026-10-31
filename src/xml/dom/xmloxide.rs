//! `xmloxide` parser adapter for the shared semantic arena.

use alloc::string::{String, ToString};
use core::ops::Range;

use super::storage::names::NameStorage;
use super::storage::{Native, Storage, Values};
use crate::parser_xmloxide as xmloxide;
use xmloxide::tree::{NodeId as XmloxNodeId, NodeKind as XmloxNodeKind};

use super::{
    Document, LexicalPreflight, ParseError, ParsingOptions, XmlBackendImplementation,
    preflight::{PositionCursor, SourceKind, SourceNode},
    tree::{AttributeData, NamespaceData, NamespaceSet, NodeId, NodeKind, TreeBuilder},
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
        let (parsed, recorded) =
            xmloxide::parser::XmlParser::with_storage(input, &backend_options(), storage)
                .and_then(|parser| {
                    if preflight.is_unscanned() {
                        let (parsed, positions) = parser.parse_recording_positions()?;
                        Ok((parsed, Some(positions)))
                    } else {
                        Ok((parser.parse()?, None))
                    }
                })
                .map_err(|error| match error {
                    xmloxide::error::ParseError::Resource(error) => {
                        super::AccountedParseError::Semantic(error)
                    }
                    xmloxide::error::ParseError::Syntax {
                        message,
                        location,
                        diagnostics,
                    } => {
                        super::AccountedParseError::Xmloxide(xmloxide::error::ParseError::Syntax {
                            message,
                            location,
                            diagnostics: diagnostics.into_owned(),
                        })
                    }
                })?;
        let positions = recorded.as_deref().unwrap_or(preflight.source_nodes());
        Ok(project_in(
            input, parsed, options, preflight, positions, storage,
        )?)
    }
}

/// Takes a backend text into the semantic tree. The two trees share one storage
/// in a parse, so the text moves with its allocation and its charge.
pub(super) trait AdoptText<R: Storage>: Storage {
    fn adopt(&self, text: R::Text) -> Result<Self::Text, ParseError>;
}

impl AdoptText<Native> for Native {
    fn adopt(&self, text: String) -> Result<String, ParseError> {
        Ok(text)
    }
}

#[cfg(feature = "xmldsig")]
impl<'w, W: structured_asn1::memory::Work> AdoptText<super::storage::Accounted<'w, W>>
    for super::storage::Accounted<'w, W>
{
    fn adopt(&self, text: Self::Text) -> Result<Self::Text, ParseError> {
        Ok(text)
    }
}

// Tests project a natively parsed tree into a limited account.
#[cfg(all(test, feature = "xmldsig"))]
impl<W: structured_asn1::memory::Work> AdoptText<Native> for super::storage::Accounted<'_, W> {
    fn adopt(&self, text: String) -> Result<Self::Text, ParseError> {
        self.text(&text)
    }
}

fn adopt_optional<S: AdoptText<R>, R: Storage>(
    storage: S,
    text: Option<R::Text>,
) -> Result<Option<S::Text>, ParseError> {
    text.map(|text| storage.adopt(text)).transpose()
}

impl XmlBackendImplementation for XmloxideBackend {
    fn parse<'input>(
        input: &'input str,
        options: ParsingOptions,
        preflight: &LexicalPreflight,
    ) -> Result<Document<'input>, ParseError> {
        let failure = |error| match error {
            xmloxide::error::ParseError::Resource(error) => error,
            error @ xmloxide::error::ParseError::Syntax { .. } => ParseError::Backend {
                backend: "xmloxide",
                message: error.to_string(),
            },
        };
        if preflight.is_unscanned() {
            let (parsed, positions) =
                xmloxide::parser::parse_str_recording_positions(input, &backend_options())
                    .map_err(failure)?;
            return project_in(input, parsed, options, preflight, &positions, Native);
        }
        let parsed =
            xmloxide::parser::parse_str_with_options(input, &backend_options()).map_err(failure)?;
        project(input, parsed, options, preflight)
    }
}

pub(super) fn project<'input>(
    input: &'input str,
    parsed: xmloxide::Document,
    options: ParsingOptions,
    preflight: &LexicalPreflight,
) -> Result<Document<'input>, ParseError> {
    let positions = preflight.source_nodes();
    project_in(input, parsed, options, preflight, positions, Native)
}

pub(super) fn project_in<'input, S: AdoptText<R>, P: Storage, R: NameStorage>(
    input: &'input str,
    parsed: xmloxide::Document<R>,
    options: ParsingOptions,
    preflight: &LexicalPreflight<'_, P>,
    positions: &[SourceNode],
    storage: S,
) -> Result<Document<'input, S>, ParseError> {
    if options.nodes_limit == 0 {
        return Err(ParseError::NodesLimitReached);
    }
    let parsed_root = parsed.root();
    let mut projector = Projector {
        target: TreeBuilder::new(
            input,
            parsed.node_count().min(options.nodes_limit as usize),
            storage,
        )?,
        source: parsed,
        positions: PositionCursor::new(positions),
        nodes_limit: options.nodes_limit,
    };
    let root = projector
        .target
        .push(None, NodeKind::Root, 0..input.len())?;
    projector.project_children(parsed_root, root)?;
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

struct Projector<'input, 'positions, S: Storage = Native, R: NameStorage = Native> {
    source: xmloxide::Document<R>,
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

impl<S: AdoptText<R>, R: NameStorage> Projector<'_, '_, S, R> {
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
                    // The next sibling waits under this node's subtree, so the
                    // stack grows with depth and not with an element's width.
                    if let Some(next) = self.source.next_sibling(source) {
                        stack.push(ProjectionFrame::Enter {
                            source: next,
                            parent,
                            namespace_owner,
                            inherited_range: inherited_range.clone(),
                            range_actionable,
                        })?;
                    }
                    // Each node is entered once, so its payload moves out.
                    let kind = core::mem::replace(
                        &mut self.source.node_mut(source).kind,
                        XmloxNodeKind::Document,
                    );
                    match kind {
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
                                let value = self.target.storage().adopt(value)?;
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
        kind: XmloxNodeKind<R>,
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
        let namespaces = self.project_namespaces(&attributes, namespace_owner)?;
        let mut semantic_attributes = storage.values(attributes.len())?;
        for attribute in attributes {
            storage.charge(1)?;
            if namespace_declaration(&attribute).is_none() {
                semantic_attributes.push(AttributeData {
                    name: storage.adopt(attribute.name)?,
                    namespace: adopt_optional(storage, attribute.namespace)?,
                    prefix: adopt_optional(storage, attribute.prefix)?,
                    value: storage.adopt(attribute.value)?,
                    is_id: false,
                    xml_id_error: None,
                })?;
            }
        }
        self.target.push_with_actionability(
            Some(parent),
            NodeKind::Element {
                name: storage.adopt(name)?,
                namespace: adopt_optional(storage, namespace.filter(|uri| !uri.is_empty()))?,
                prefix: adopt_optional(storage, prefix)?,
                attributes: semantic_attributes,
                namespaces,
            },
            range,
            range_actionable,
        )
    }

    /// The element's in-scope set: its parent's, unless it declares bindings.
    fn project_namespaces(
        &mut self,
        attributes: &[xmloxide::tree::Attribute<R>],
        namespace_owner: Option<NodeId>,
    ) -> Result<NamespaceSet, ParseError> {
        let storage = self.target.storage();
        let inherited = self.target.namespace_set_of(namespace_owner);
        storage.charge(attributes.len())?;
        if attributes
            .iter()
            .all(|attribute| namespace_declaration(attribute).is_none())
        {
            return Ok(inherited);
        }
        let inherited = self.target.namespace_bindings(inherited);
        let mut namespaces = storage.values(inherited.len())?;
        for namespace in inherited {
            storage.charge(1)?;
            namespaces.push(NamespaceData {
                prefix: storage.optional_text(namespace.prefix.as_deref())?,
                uri: storage.text(namespace.uri.as_ref())?,
            })?;
        }
        for attribute in attributes {
            if let Some(declared) = namespace_declaration(attribute) {
                set_namespace(
                    &mut namespaces,
                    declared.prefix(),
                    &attribute.value,
                    storage,
                )?;
            }
        }
        self.target.add_namespace_set(namespaces)
    }

    fn project_leaf(
        &mut self,
        source: XmloxNodeId,
        parent: NodeId,
        kind: XmloxNodeKind<R>,
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
                self.target.append_text(
                    parent,
                    storage.adopt(content)?,
                    range,
                    range_actionable,
                )?;
            }
            XmloxNodeKind::CData { content } => {
                self.admit_text(parent)?;
                let range = match inherited_range {
                    Some(range) => range,
                    None => self.positions.take(SourceKind::CData)?,
                };
                self.target.append_text(
                    parent,
                    storage.adopt(content)?,
                    range,
                    range_actionable,
                )?;
            }
            XmloxNodeKind::Comment { content } => {
                self.admit_node()?;
                let range = match inherited_range {
                    Some(range) => range,
                    None => self.positions.take(SourceKind::Comment)?,
                };
                self.target.push_with_actionability(
                    Some(parent),
                    NodeKind::Comment(storage.adopt(content)?),
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
                        target: storage.adopt(pi_target)?,
                        value: adopt_optional(storage, data)?,
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
        if let Some(first) = self.source.first_child(source) {
            stack.push(ProjectionFrame::Enter {
                source: first,
                parent,
                namespace_owner,
                inherited_range: inherited_range.cloned(),
                range_actionable,
            })?;
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

/// What a namespace declaration attribute binds.
#[derive(Clone, Copy)]
enum Declared<'a> {
    Default,
    Prefix(&'a str),
}

impl<'a> Declared<'a> {
    fn prefix(self) -> Option<&'a str> {
        match self {
            Self::Default => None,
            Self::Prefix(prefix) => Some(prefix),
        }
    }
}

fn namespace_declaration<R: NameStorage>(
    attribute: &xmloxide::tree::Attribute<R>,
) -> Option<Declared<'_>> {
    if attribute.prefix.as_deref() == Some("xmlns") {
        Some(Declared::Prefix(&attribute.name))
    } else if attribute.prefix.is_none() && attribute.name.as_ref() == "xmlns" {
        Some(Declared::Default)
    } else {
        None
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
