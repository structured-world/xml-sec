use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{Error, Result};

const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
const XMLNS_NS: &str = "http://www.w3.org/2000/xmlns/";
// Keep the streaming fallback aligned with roxmltree's entity-expansion safety ceilings.
const MAX_ENTITY_EXPANSION_DEPTH: usize = 10;
const TREE_PARSER_DEPTH_LIMIT: usize = 64;
const MAX_NESTED_ENTITY_REFERENCES: usize = 255;

/// Stable index of a node inside one owned document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub usize);

/// Stable identity of any XPath node in one owned document.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NodeReference {
    /// A root, element, text, comment, or processing-instruction arena node.
    Node(NodeId),
    /// An attribute identified within its owning element's stable attribute order.
    Attribute { owner: NodeId, index: usize },
    /// A namespace node identified within its owning element's namespace set.
    Namespace { owner: NodeId, index: usize },
}

/// Namespace-expanded XML name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExpandedName {
    pub namespace: Option<String>,
    pub local: String,
}

impl ExpandedName {
    #[must_use]
    pub fn new(namespace: Option<impl Into<String>>, local: impl Into<String>) -> Self {
        Self {
            namespace: namespace.map(Into::into),
            local: local.into(),
        }
    }
}

/// Owned XML attribute retained in source order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub name: ExpandedName,
    pub prefix: Option<String>,
    pub value: String,
}

/// Owned namespace declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Namespace {
    pub prefix: Option<String>,
    pub uri: String,
}

/// XML node kind used by both source and result trees.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NodeKind {
    Root,
    Element {
        name: ExpandedName,
        prefix: Option<String>,
        attributes: Vec<Attribute>,
        namespaces: Vec<Namespace>,
    },
    Text {
        value: String,
        disable_output_escaping: bool,
    },
    Comment(String),
    ProcessingInstruction {
        target: String,
        value: Option<String>,
    },
}

/// One node in an owned document arena.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub kind: NodeKind,
    pub parent: Option<NodeId>,
    pub children: Vec<NodeId>,
    pub base_uri: Option<String>,
    /// One-based source line when the parser can retain lexical location.
    pub source_line: Option<usize>,
}

/// Parser-independent owned XML tree.
#[derive(Debug, Clone)]
pub struct Document {
    identity: u64,
    nodes: Vec<Node>,
    root: NodeId,
    logical_roots: Vec<NodeId>,
    source_xml: Option<String>,
    ids: HashMap<(NodeId, String), NodeId>,
    unparsed_entities: HashMap<(NodeId, String), String>,
}

impl PartialEq for Document {
    fn eq(&self, other: &Self) -> bool {
        self.nodes == other.nodes
            && self.root == other.root
            && self.logical_roots == other.logical_roots
            && self.source_xml == other.source_xml
            && self.ids == other.ids
            && self.unparsed_entities == other.unparsed_entities
    }
}

impl Eq for Document {}

impl Document {
    /// Parse caller-supplied XML into the engine semantic model.
    pub fn parse(xml: &str, base_uri: Option<&str>) -> Result<Self> {
        if lexical_nesting_depth(xml) > TREE_PARSER_DEPTH_LIMIT {
            return Self::parse_deep_streaming(xml, base_uri);
        }
        Self::parse_tree(xml, base_uri)
    }

    // Account for heap storage materialized by Clone before duplicating the source document.
    pub(crate) fn estimated_clone_bytes(&self) -> usize {
        let mut bytes = self
            .nodes
            .len()
            .saturating_mul(std::mem::size_of::<Node>())
            .saturating_add(
                self.logical_roots
                    .len()
                    .saturating_mul(std::mem::size_of::<NodeId>()),
            )
            .saturating_add(self.source_xml.as_deref().map_or(0, str::len));
        for node in &self.nodes {
            bytes = bytes
                .saturating_add(
                    node.children
                        .len()
                        .saturating_mul(std::mem::size_of::<NodeId>()),
                )
                .saturating_add(node.base_uri.as_deref().map_or(0, str::len));
            bytes = bytes.saturating_add(match &node.kind {
                NodeKind::Root => 0,
                NodeKind::Text { value, .. } | NodeKind::Comment(value) => value.len(),
                NodeKind::ProcessingInstruction { target, value } => target
                    .len()
                    .saturating_add(value.as_deref().map_or(0, str::len)),
                NodeKind::Element {
                    name,
                    prefix,
                    attributes,
                    namespaces,
                } => name
                    .local
                    .len()
                    .saturating_add(name.namespace.as_deref().map_or(0, str::len))
                    .saturating_add(prefix.as_deref().map_or(0, str::len))
                    .saturating_add(
                        attributes
                            .len()
                            .saturating_mul(std::mem::size_of::<Attribute>()),
                    )
                    .saturating_add(attributes.iter().fold(0usize, |total, attribute| {
                        total
                            .saturating_add(attribute.name.local.len())
                            .saturating_add(attribute.name.namespace.as_deref().map_or(0, str::len))
                            .saturating_add(attribute.prefix.as_deref().map_or(0, str::len))
                            .saturating_add(attribute.value.len())
                    }))
                    .saturating_add(
                        namespaces
                            .len()
                            .saturating_mul(std::mem::size_of::<Namespace>()),
                    )
                    .saturating_add(namespaces.iter().fold(0usize, |total, namespace| {
                        total
                            .saturating_add(namespace.prefix.as_deref().map_or(0, str::len))
                            .saturating_add(namespace.uri.len())
                    })),
            });
        }
        bytes = bytes
            .saturating_add(
                self.ids.capacity().saturating_mul(
                    std::mem::size_of::<((NodeId, String), NodeId)>()
                        .saturating_add(std::mem::size_of::<u64>()),
                ),
            )
            .saturating_add(
                self.ids
                    .keys()
                    .fold(0usize, |total, (_, name)| total.saturating_add(name.len())),
            )
            .saturating_add(
                self.unparsed_entities.capacity().saturating_mul(
                    std::mem::size_of::<((NodeId, String), String)>()
                        .saturating_add(std::mem::size_of::<u64>()),
                ),
            )
            .saturating_add(self.unparsed_entities.iter().fold(
                0usize,
                |total, ((_, name), value)| {
                    total.saturating_add(name.len()).saturating_add(value.len())
                },
            ));
        bytes
    }

    fn parse_tree(xml: &str, base_uri: Option<&str>) -> Result<Self> {
        let parsed =
            roxmltree::Document::parse(xml).map_err(|error| Error::Xml(error.to_string()))?;
        let mut document = Self::empty(base_uri.map(str::to_owned));
        document.source_xml = Some(xml.to_owned());
        let line_starts = std::iter::once(0)
            .chain(
                xml.bytes()
                    .enumerate()
                    .filter_map(|(index, byte)| (byte == b'\n').then_some(index + 1)),
            )
            .collect::<Vec<_>>();
        let mut mapping = HashMap::new();
        mapping.insert(parsed.root().id(), document.root);
        for source in parsed.descendants().filter(|node| !node.is_root()) {
            let parent = source
                .parent()
                .and_then(|node| mapping.get(&node.id()).copied())
                .ok_or_else(|| Error::Xml("parsed node has no projected parent".into()))?;
            let kind = if source.is_element() {
                let prefix = lexical_prefix(xml, source.range().start, source.tag_name().name());
                if !crate::lexical::is_ncname(source.tag_name().name())
                    || prefix
                        .as_deref()
                        .is_some_and(|prefix| !crate::lexical::is_ncname(prefix))
                {
                    return Err(Error::Xml("invalid element QName".into()));
                }
                let attributes = source
                    .attributes()
                    .map(|attribute| {
                        let prefix = attribute_prefix(xml, source, attribute);
                        if !crate::lexical::is_ncname(attribute.name())
                            || prefix
                                .as_deref()
                                .is_some_and(|prefix| !crate::lexical::is_ncname(prefix))
                        {
                            return Err(Error::Xml("invalid attribute QName".into()));
                        }
                        Ok(Attribute {
                            name: ExpandedName::new(attribute.namespace(), attribute.name()),
                            prefix,
                            value: attribute.value().to_owned(),
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                let mut namespaces = Vec::new();
                for namespace in source.namespaces() {
                    if namespace
                        .name()
                        .is_some_and(|prefix| !crate::lexical::is_ncname(prefix))
                    {
                        return Err(Error::Xml("invalid namespace prefix".into()));
                    }
                    validate_namespace_binding(namespace.name(), namespace.uri())?;
                    namespaces.push(Namespace {
                        prefix: namespace.name().map(str::to_owned),
                        uri: namespace.uri().to_owned(),
                    });
                }
                if !namespaces.iter().any(|namespace| {
                    namespace.prefix.as_deref() == Some("xml")
                        && namespace.uri == "http://www.w3.org/XML/1998/namespace"
                }) {
                    namespaces.insert(
                        0,
                        Namespace {
                            prefix: Some("xml".into()),
                            uri: "http://www.w3.org/XML/1998/namespace".into(),
                        },
                    );
                }
                NodeKind::Element {
                    name: ExpandedName::new(
                        source.tag_name().namespace(),
                        source.tag_name().name(),
                    ),
                    prefix,
                    attributes,
                    namespaces,
                }
            } else if source.is_text() {
                NodeKind::Text {
                    value: source.text().unwrap_or_default().to_owned(),
                    disable_output_escaping: false,
                }
            } else if source.is_comment() {
                NodeKind::Comment(source.text().unwrap_or_default().to_owned())
            } else if let Some(pi) = source.pi() {
                NodeKind::ProcessingInstruction {
                    target: pi.target.to_owned(),
                    value: pi.value.map(str::to_owned),
                }
            } else {
                continue;
            };
            let inherited_base = document.node(parent).and_then(|node| node.base_uri.clone());
            let effective_base = if let Some(reference) = source
                .is_element()
                .then(|| source.attribute((XML_NS, "base")))
                .flatten()
            {
                Some(resolve_base_uri(inherited_base.as_deref(), reference)?)
            } else {
                inherited_base
            };
            let id = document.push(parent, kind, effective_base);
            if let Some(projected) = document.node_mut(id) {
                projected.source_line =
                    Some(line_starts.partition_point(|offset| *offset <= source.range().start));
            }
            mapping.insert(source.id(), id);
        }
        document.register_xml_ids()?;
        Ok(document)
    }

    fn parse_deep_streaming(xml: &str, base_uri: Option<&str>) -> Result<Self> {
        use quick_xml::Reader;
        use quick_xml::events::Event;

        #[derive(Clone, Copy, PartialEq, Eq)]
        enum DocumentPhase {
            Start,
            Prolog,
            Content,
            Epilog,
        }

        let mut document = Self::empty(base_uri.map(str::to_owned));
        document.source_xml = Some(xml.to_owned());
        let entities = internal_general_entities(xml)?;
        let expanded_xml = expand_document_entities(xml, &entities)?;
        let mut reader = Reader::from_str(&expanded_xml);
        let line_starts = std::iter::once(0)
            .chain(
                expanded_xml
                    .bytes()
                    .enumerate()
                    .filter_map(|(index, byte)| (byte == b'\n').then_some(index + 1)),
            )
            .collect::<Vec<_>>();
        let mut phase = DocumentPhase::Start;
        let mut saw_doctype = false;
        let mut elements = vec![(
            document.root,
            vec![Namespace {
                prefix: Some("xml".into()),
                uri: "http://www.w3.org/XML/1998/namespace".into(),
            }],
        )];
        loop {
            let event_offset = reader.buffer_position() as usize;
            let event = reader
                .read_event()
                .map_err(|error| Error::Xml(error.to_string()))?;
            let source_line = line_starts.partition_point(|offset| *offset <= event_offset);
            match event {
                Event::Start(start) => {
                    if elements.len() == 1 {
                        if phase == DocumentPhase::Epilog {
                            return Err(Error::Xml("multiple document elements".into()));
                        }
                        phase = DocumentPhase::Content;
                    }
                    let id = push_stream_element(&mut document, &mut elements, &start, false)?;
                    document.nodes[id.0].source_line = Some(source_line);
                }
                Event::Empty(start) => {
                    if elements.len() == 1 {
                        if phase == DocumentPhase::Epilog {
                            return Err(Error::Xml("multiple document elements".into()));
                        }
                        phase = DocumentPhase::Epilog;
                    }
                    let id = push_stream_element(&mut document, &mut elements, &start, true)?;
                    document.nodes[id.0].source_line = Some(source_line);
                }
                Event::End(_) => {
                    if elements.len() == 1 {
                        return Err(Error::Xml("unmatched closing element".into()));
                    }
                    elements.pop();
                    if elements.len() == 1 {
                        phase = DocumentPhase::Epilog;
                    }
                }
                Event::Text(text) => {
                    let value = text.xml10_content().into_owned();
                    if elements.len() == 1
                        && !value.trim_matches([' ', '\t', '\r', '\n']).is_empty()
                    {
                        return Err(Error::Xml(
                            "non-whitespace text outside the document element".into(),
                        ));
                    }
                    if elements.len() > 1 && !value.is_empty() {
                        let id = push_parsed_text(&mut document, &elements, value);
                        document.nodes[id.0].source_line.get_or_insert(source_line);
                    } else if phase == DocumentPhase::Start {
                        phase = DocumentPhase::Prolog;
                    }
                }
                Event::CData(text) => {
                    if elements.len() == 1 {
                        return Err(Error::Xml(
                            "CDATA is not allowed outside the document element".into(),
                        ));
                    }
                    let id = push_parsed_text(
                        &mut document,
                        &elements,
                        text.xml10_content().into_owned(),
                    );
                    document.nodes[id.0].source_line.get_or_insert(source_line);
                }
                Event::Comment(comment) => {
                    if phase == DocumentPhase::Start {
                        phase = DocumentPhase::Prolog;
                    }
                    let parent = elements.last().expect("document frame remains present").0;
                    let inherited_base =
                        document.node(parent).and_then(|node| node.base_uri.clone());
                    let id = document.push(
                        parent,
                        NodeKind::Comment(comment.xml10_content().into_owned()),
                        inherited_base,
                    );
                    document.nodes[id.0].source_line = Some(source_line);
                }
                Event::PI(pi) => {
                    if phase == DocumentPhase::Start {
                        phase = DocumentPhase::Prolog;
                    }
                    let parent = elements.last().expect("document frame remains present").0;
                    let inherited_base =
                        document.node(parent).and_then(|node| node.base_uri.clone());
                    let id = document.push(
                        parent,
                        NodeKind::ProcessingInstruction {
                            target: pi.target().to_owned(),
                            value: (!pi.content().is_empty()).then(|| pi.content().to_owned()),
                        },
                        inherited_base,
                    );
                    document.nodes[id.0].source_line = Some(source_line);
                }
                Event::GeneralRef(reference) => {
                    if elements.len() == 1 {
                        return Err(Error::Xml(
                            "character and entity references are not allowed outside the document element"
                                .into(),
                        ));
                    }
                    let reference = reference.as_ref();
                    let value = match reference {
                        "amp" => "&".into(),
                        "apos" => "'".into(),
                        "gt" => ">".into(),
                        "lt" => "<".into(),
                        "quot" => "\"".into(),
                        value if value.starts_with("#x") => {
                            decode_xml_character_reference(&value[2..], 16)?
                        }
                        value if value.starts_with('#') => {
                            decode_xml_character_reference(&value[1..], 10)?
                        }
                        name => {
                            return Err(Error::Xml(format!(
                                "unresolved entity reference &{name};"
                            )));
                        }
                    };
                    let id = push_parsed_text(&mut document, &elements, value);
                    document.nodes[id.0].source_line.get_or_insert(source_line);
                }
                Event::Eof => break,
                Event::Decl(_) => {
                    if phase != DocumentPhase::Start {
                        return Err(Error::Xml(
                            "XML declaration is permitted only at the start of the document".into(),
                        ));
                    }
                    phase = DocumentPhase::Prolog;
                }
                Event::DocType(_) => {
                    if matches!(phase, DocumentPhase::Content | DocumentPhase::Epilog) {
                        return Err(Error::Xml(
                            "document type declaration is permitted only in the prolog".into(),
                        ));
                    }
                    if saw_doctype {
                        return Err(Error::Xml("duplicate document type declaration".into()));
                    }
                    saw_doctype = true;
                    phase = DocumentPhase::Prolog;
                }
            }
        }
        if elements.len() != 1 {
            return Err(Error::Xml("unclosed element".into()));
        }
        if phase != DocumentPhase::Epilog {
            return Err(Error::Xml("document element is missing".into()));
        }
        document.register_xml_ids()?;
        Ok(document)
    }

    #[must_use]
    pub fn empty(base_uri: Option<String>) -> Self {
        static NEXT_DOCUMENT_IDENTITY: AtomicU64 = AtomicU64::new(1);
        Self {
            identity: NEXT_DOCUMENT_IDENTITY.fetch_add(1, Ordering::Relaxed),
            nodes: vec![Node {
                kind: NodeKind::Root,
                parent: None,
                children: Vec::new(),
                base_uri,
                source_line: None,
            }],
            root: NodeId(0),
            logical_roots: vec![NodeId(0)],
            source_xml: None,
            ids: HashMap::new(),
            unparsed_entities: HashMap::new(),
        }
    }

    #[must_use]
    pub const fn root(&self) -> NodeId {
        self.root
    }

    #[must_use]
    pub fn node(&self, id: NodeId) -> Option<&Node> {
        self.nodes.get(id.0)
    }

    pub(crate) fn node_mut(&mut self, id: NodeId) -> Option<&mut Node> {
        self.nodes.get_mut(id.0)
    }

    pub(crate) fn source_xml(&self) -> Option<&str> {
        self.source_xml.as_deref()
    }

    pub(crate) const fn identity(&self) -> u64 {
        self.identity
    }

    pub(crate) fn source_line(&self, reference: &NodeReference) -> Option<usize> {
        let id = match reference {
            NodeReference::Node(id) => *id,
            NodeReference::Attribute { owner, .. } | NodeReference::Namespace { owner, .. } => {
                *owner
            }
        };
        self.node(id).and_then(|node| node.source_line)
    }

    pub(crate) fn logical_roots(&self) -> &[NodeId] {
        &self.logical_roots
    }

    pub(crate) fn logical_root_for(&self, reference: &NodeReference) -> Option<NodeId> {
        let mut current = match reference {
            NodeReference::Node(id) => *id,
            NodeReference::Attribute { owner, .. } | NodeReference::Namespace { owner, .. } => {
                *owner
            }
        };
        while let Some(parent) = self.node(current)?.parent {
            current = parent;
        }
        self.logical_roots.contains(&current).then_some(current)
    }

    pub(crate) fn document_order_key(
        &self,
        reference: &NodeReference,
    ) -> Option<(usize, u8, usize)> {
        match reference {
            NodeReference::Node(id) => self.node(*id).map(|_| (id.0, 0, 0)),
            NodeReference::Namespace { owner, index } => {
                self.node(*owner).and_then(|node| match &node.kind {
                    NodeKind::Element { namespaces, .. } if *index < namespaces.len() => {
                        Some((owner.0, 1, *index))
                    }
                    _ => None,
                })
            }
            NodeReference::Attribute { owner, index } => {
                self.node(*owner).and_then(|node| match &node.kind {
                    NodeKind::Element { attributes, .. } if *index < attributes.len() => {
                        Some((owner.0, 2, *index))
                    }
                    _ => None,
                })
            }
        }
    }

    pub(crate) fn import(&mut self, source: &Self) -> NodeId {
        let offset = self.nodes.len();
        let remap = |id: NodeId| NodeId(offset + id.0);
        self.nodes
            .extend(source.nodes.iter().cloned().map(|mut node| {
                node.parent = node.parent.map(remap);
                node.children = node.children.into_iter().map(remap).collect();
                node
            }));
        let root = remap(source.root);
        self.ids
            .extend(source.ids.iter().map(|((logical_root, value), owner)| {
                ((remap(*logical_root), value.clone()), remap(*owner))
            }));
        self.unparsed_entities
            .extend(
                source
                    .unparsed_entities
                    .iter()
                    .map(|((logical_root, name), uri)| {
                        ((remap(*logical_root), name.clone()), uri.clone())
                    }),
            );
        self.logical_roots.push(root);
        root
    }

    /// Mark one existing attribute as carrying an XML ID value.
    ///
    /// This lets a caller that parsed trusted DTD/schema metadata preserve the
    /// typed ID information without enabling DTD processing in this crate.
    pub fn mark_id_attribute(&mut self, owner: NodeId, attribute_index: usize) -> Result<()> {
        let value = self
            .node(owner)
            .and_then(|node| match &node.kind {
                NodeKind::Element { attributes, .. } => attributes.get(attribute_index),
                _ => None,
            })
            .ok_or_else(|| Error::Xml("ID attribute reference is stale".into()))?
            .value
            .split_ascii_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if value.is_empty() {
            return Err(Error::Xml("ID attribute value is empty".into()));
        }
        let logical_root = self
            .logical_root_for(&NodeReference::Node(owner))
            .ok_or_else(|| Error::Xml("ID attribute is outside a logical document".into()))?;
        if self
            .ids
            .insert((logical_root, value.clone()), owner)
            .is_some()
        {
            return Err(Error::Xml(format!("duplicate XML ID `{value}`")));
        }
        Ok(())
    }

    /// Apply XML's whitespace collapsing rule to an attribute declared with a
    /// tokenized DTD type. The caller supplies trusted declaration metadata;
    /// the core parser deliberately does not load DTD resources itself.
    pub fn normalize_tokenized_attribute(
        &mut self,
        owner: NodeId,
        attribute_index: usize,
    ) -> Result<()> {
        let attribute = self
            .node_mut(owner)
            .and_then(|node| match &mut node.kind {
                NodeKind::Element { attributes, .. } => attributes.get_mut(attribute_index),
                _ => None,
            })
            .ok_or_else(|| Error::Xml("tokenized attribute reference is stale".into()))?;
        attribute.value = attribute
            .value
            .split_ascii_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        Ok(())
    }

    /// Add a schema/DTD-defaulted attribute supplied by a trusted parser.
    pub fn add_default_attribute(&mut self, owner: NodeId, attribute: Attribute) -> Result<()> {
        let node = self
            .node_mut(owner)
            .ok_or_else(|| Error::Xml("defaulted attribute owner is stale".into()))?;
        let NodeKind::Element { attributes, .. } = &mut node.kind else {
            return Err(Error::Xml(
                "defaulted attribute owner is not an element".into(),
            ));
        };
        if attributes
            .iter()
            .any(|existing| existing.name == attribute.name)
        {
            return Ok(());
        }
        attributes.push(attribute);
        Ok(())
    }

    pub(crate) fn ids(&self) -> impl Iterator<Item = (&str, NodeId, NodeId)> {
        self.ids
            .iter()
            .map(|((root, value), owner)| (value.as_str(), *root, *owner))
    }

    /// Register one DTD-declared unparsed entity for the principal document.
    ///
    /// The URI is metadata supplied by a trusted external parser. The XSLT
    /// engine exposes it through `unparsed-entity-uri()` but never dereferences it.
    pub fn register_unparsed_entity(
        &mut self,
        name: impl Into<String>,
        uri: impl Into<String>,
    ) -> Result<()> {
        let name = name.into();
        let uri = uri.into();
        if name.is_empty() || uri.is_empty() {
            return Err(Error::Xml(
                "unparsed entity name and URI must not be empty".into(),
            ));
        }
        let key = (self.root, name.clone());
        if self.unparsed_entities.insert(key, uri).is_some() {
            return Err(Error::Xml(format!("duplicate unparsed entity `{name}`")));
        }
        Ok(())
    }

    pub(crate) fn unparsed_entities(&self) -> impl Iterator<Item = (&str, &str, NodeId)> {
        self.unparsed_entities
            .iter()
            .map(|((root, name), uri)| (name.as_str(), uri.as_str(), *root))
    }

    fn register_xml_ids(&mut self) -> Result<()> {
        let attributes = self
            .nodes()
            .filter_map(|(owner, node)| match &node.kind {
                NodeKind::Element { attributes, .. } => attributes
                    .iter()
                    .position(|attribute| {
                        attribute.name.namespace.as_deref()
                            == Some("http://www.w3.org/XML/1998/namespace")
                            && attribute.name.local == "id"
                    })
                    .map(|index| (owner, index)),
                _ => None,
            })
            .collect::<Vec<_>>();
        for (owner, index) in attributes {
            self.mark_id_attribute(owner, index)?;
        }
        Ok(())
    }

    #[must_use]
    pub fn nodes(&self) -> impl ExactSizeIterator<Item = (NodeId, &Node)> {
        self.nodes
            .iter()
            .enumerate()
            .map(|(index, node)| (NodeId(index), node))
    }

    pub(crate) fn subtree_in_document_order(&self, root: NodeId) -> Vec<NodeId> {
        let mut ordered = Vec::new();
        let mut pending = vec![root];
        while let Some(id) = pending.pop() {
            let Some(node) = self.node(id) else {
                continue;
            };
            ordered.push(id);
            pending.extend(node.children.iter().rev().copied());
        }
        ordered
    }

    pub(crate) fn push(
        &mut self,
        parent: NodeId,
        kind: NodeKind,
        base_uri: Option<String>,
    ) -> NodeId {
        let id = NodeId(self.nodes.len());
        self.nodes.push(Node {
            kind,
            parent: Some(parent),
            children: Vec::new(),
            base_uri,
            source_line: None,
        });
        if let Some(parent) = self.nodes.get_mut(parent.0) {
            parent.children.push(id);
        }
        id
    }

    pub(crate) fn append_subtree_from(
        &mut self,
        parent: NodeId,
        source: &Self,
        source_id: NodeId,
        mapping: &mut HashMap<NodeId, NodeId>,
    ) -> NodeId {
        let source_node = source.node(source_id).expect("source subtree node exists");
        let root = self.push(
            parent,
            source_node.kind.clone(),
            source_node.base_uri.clone(),
        );
        if let Some(node) = self.node_mut(root) {
            node.source_line = source_node.source_line;
        }
        mapping.insert(source_id, root);
        let mut pending = source_node
            .children
            .iter()
            .rev()
            .map(|child| (*child, root))
            .collect::<Vec<_>>();
        while let Some((source_id, target_parent)) = pending.pop() {
            let source_node = source.node(source_id).expect("source subtree node exists");
            let target = self.push(
                target_parent,
                source_node.kind.clone(),
                source_node.base_uri.clone(),
            );
            if let Some(node) = self.node_mut(target) {
                node.source_line = source_node.source_line;
            }
            mapping.insert(source_id, target);
            pending.extend(
                source_node
                    .children
                    .iter()
                    .rev()
                    .map(|child| (*child, target)),
            );
        }
        root
    }

    pub(crate) fn remap_ids_from(
        &mut self,
        source: &Self,
        mapping: &HashMap<NodeId, NodeId>,
    ) -> Result<()> {
        for (value, _, source_owner) in source.ids() {
            let Some(owner) = mapping.get(&source_owner).copied() else {
                continue;
            };
            let logical_root = self
                .logical_root_for(&NodeReference::Node(owner))
                .ok_or_else(|| Error::Xml("remapped ID is outside a logical document".into()))?;
            if self
                .ids
                .insert((logical_root, value.to_owned()), owner)
                .is_some()
            {
                return Err(Error::Xml(format!("duplicate XML ID `{value}`")));
            }
        }
        Ok(())
    }

    pub(crate) fn string_value(&self, id: NodeId) -> String {
        let Some(node) = self.node(id) else {
            return String::new();
        };
        match &node.kind {
            NodeKind::Text { value, .. } => value.clone(),
            NodeKind::Comment(value) => value.clone(),
            NodeKind::ProcessingInstruction { value, .. } => value.clone().unwrap_or_default(),
            NodeKind::Root | NodeKind::Element { .. } => {
                let mut output = String::new();
                let mut pending = node.children.iter().rev().copied().collect::<Vec<_>>();
                while let Some(current) = pending.pop() {
                    let Some(current) = self.node(current) else {
                        continue;
                    };
                    if let NodeKind::Text { value, .. } = &current.kind {
                        output.push_str(value);
                    }
                    pending.extend(current.children.iter().rev().copied());
                }
                output
            }
        }
    }

    pub(crate) fn retain_nodes(
        &mut self,
        mut keep: impl FnMut(NodeId, &Node) -> bool,
    ) -> HashMap<NodeId, NodeId> {
        let mut retained = vec![self.root];
        let mut cursor = 0;
        while cursor < retained.len() {
            let id = retained[cursor];
            for child in &self.nodes[id.0].children {
                if keep(*child, &self.nodes[child.0]) {
                    retained.push(*child);
                }
            }
            cursor += 1;
        }
        let remap = retained
            .iter()
            .enumerate()
            .map(|(new, old)| (*old, NodeId(new)))
            .collect::<HashMap<_, _>>();
        self.ids = std::mem::take(&mut self.ids)
            .into_iter()
            .filter_map(|((root, value), owner)| {
                Some((
                    (remap.get(&root).copied()?, value),
                    remap.get(&owner).copied()?,
                ))
            })
            .collect();
        self.unparsed_entities = std::mem::take(&mut self.unparsed_entities)
            .into_iter()
            .filter_map(|((root, name), uri)| Some(((remap.get(&root).copied()?, name), uri)))
            .collect();
        self.nodes = retained
            .into_iter()
            .map(|old| {
                let mut node = self.nodes[old.0].clone();
                node.parent = node.parent.and_then(|parent| remap.get(&parent).copied());
                node.children = node
                    .children
                    .into_iter()
                    .filter_map(|child| remap.get(&child).copied())
                    .collect();
                node
            })
            .collect();
        self.root = NodeId(0);
        self.logical_roots = vec![self.root];
        self.source_xml = None;
        remap
    }
}

fn decode_xml_character_reference(digits: &str, radix: u32) -> Result<String> {
    u32::from_str_radix(digits, radix)
        .ok()
        .and_then(char::from_u32)
        .filter(|character| is_xml10_character(*character))
        .map(String::from)
        .ok_or_else(|| Error::Xml("invalid character reference".into()))
}

fn is_xml10_character(character: char) -> bool {
    matches!(
        u32::from(character),
        0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF
    )
}

fn push_stream_element(
    document: &mut Document,
    elements: &mut Vec<(NodeId, Vec<Namespace>)>,
    start: &quick_xml::events::BytesStart<'_>,
    empty: bool,
) -> Result<NodeId> {
    let parent = elements
        .last()
        .map(|(parent, _)| *parent)
        .expect("document frame remains present");
    let mut namespaces = elements
        .last()
        .map(|(_, namespaces)| namespaces.clone())
        .expect("document frame remains present");
    let mut raw_attributes = Vec::new();
    for attribute in start.attributes() {
        let attribute = attribute.map_err(|error| Error::Xml(error.to_string()))?;
        let name = attribute.key.as_ref();
        let value = attribute
            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
            .map_err(|error| Error::Xml(error.to_string()))?
            .into_owned();
        if name == "xmlns" {
            validate_namespace_binding(None, &value)?;
            set_namespace(&mut namespaces, None, value);
        } else if let Some(prefix) = name.strip_prefix("xmlns:") {
            if !crate::lexical::is_ncname(prefix) {
                return Err(Error::Xml(format!("invalid namespace prefix {prefix}")));
            }
            validate_namespace_binding(Some(prefix), &value)?;
            set_namespace(&mut namespaces, Some(prefix.into()), value);
        } else {
            raw_attributes.push((name.to_owned(), value));
        }
    }
    let binding = start.name();
    let lexical_name = binding.as_ref();
    let (prefix, local) = split_lexical_name(lexical_name)?;
    let namespace = namespace_for(&namespaces, prefix.as_deref());
    if prefix.is_some() && namespace.is_none() {
        return Err(Error::Xml(format!(
            "undeclared namespace prefix in element {lexical_name}"
        )));
    }
    let attributes = raw_attributes
        .into_iter()
        .map(|(lexical, value)| {
            let (prefix, local) = split_lexical_name(&lexical)?;
            let namespace = prefix
                .as_deref()
                .and_then(|prefix| namespace_for(&namespaces, Some(prefix)));
            if prefix.is_some() && namespace.is_none() {
                return Err(Error::Xml(format!(
                    "undeclared namespace prefix in attribute {lexical}"
                )));
            }
            Ok(Attribute {
                name: ExpandedName::new(namespace, local),
                prefix,
                value,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut expanded_names = HashSet::with_capacity(attributes.len());
    if let Some(duplicate) = attributes
        .iter()
        .find(|attribute| !expanded_names.insert(attribute.name.clone()))
    {
        return Err(Error::Xml(format!(
            "duplicate expanded attribute {{{}}}{}",
            duplicate.name.namespace.as_deref().unwrap_or(""),
            duplicate.name.local
        )));
    }
    let inherited_base = document.node(parent).and_then(|node| node.base_uri.clone());
    let effective_base = if let Some(attribute) = attributes.iter().find(|attribute| {
        attribute.name.namespace.as_deref() == Some(XML_NS) && attribute.name.local == "base"
    }) {
        Some(resolve_base_uri(
            inherited_base.as_deref(),
            &attribute.value,
        )?)
    } else {
        inherited_base
    };
    let projected = document.push(
        parent,
        NodeKind::Element {
            name: ExpandedName::new(namespace, local),
            prefix,
            attributes,
            namespaces: namespaces.clone(),
        },
        effective_base,
    );
    if !empty {
        elements.push((projected, namespaces));
    }
    Ok(projected)
}

fn push_parsed_text(
    document: &mut Document,
    elements: &[(NodeId, Vec<Namespace>)],
    value: String,
) -> NodeId {
    let parent = elements.last().expect("document frame remains present").0;
    if let Some(last_child) = document
        .node(parent)
        .and_then(|node| node.children.last())
        .copied()
        && let NodeKind::Text {
            value: existing,
            disable_output_escaping: false,
        } = &mut document.nodes[last_child.0].kind
    {
        existing.push_str(&value);
        return last_child;
    }
    let inherited_base = document.node(parent).and_then(|node| node.base_uri.clone());
    document.push(
        parent,
        NodeKind::Text {
            value,
            disable_output_escaping: false,
        },
        inherited_base,
    )
}

fn split_lexical_name(name: &str) -> Result<(Option<String>, String)> {
    let (prefix, local) = name
        .split_once(':')
        .map_or((None, name), |(prefix, local)| (Some(prefix), local));
    if !crate::lexical::is_ncname(local)
        || prefix.is_some_and(|prefix| !crate::lexical::is_ncname(prefix))
        || local.contains(':')
    {
        return Err(Error::Xml(format!("invalid XML QName {name}")));
    }
    Ok((prefix.map(str::to_owned), local.to_owned()))
}

fn namespace_for(namespaces: &[Namespace], prefix: Option<&str>) -> Option<String> {
    namespaces
        .iter()
        .rev()
        .find(|namespace| namespace.prefix.as_deref() == prefix)
        .map(|namespace| namespace.uri.clone())
        .filter(|namespace| !namespace.is_empty())
}

fn set_namespace(namespaces: &mut Vec<Namespace>, prefix: Option<String>, uri: String) {
    if let Some(existing) = namespaces
        .iter_mut()
        .find(|namespace| namespace.prefix == prefix)
    {
        existing.uri = uri;
    } else {
        namespaces.push(Namespace { prefix, uri });
    }
}

fn validate_namespace_binding(prefix: Option<&str>, uri: &str) -> Result<()> {
    if prefix.is_some() && uri.is_empty() {
        return Err(Error::Xml(
            "prefixed namespace bindings cannot have an empty namespace URI".into(),
        ));
    }
    if prefix == Some("xmlns") || uri == XMLNS_NS {
        return Err(Error::Xml(
            "the xmlns prefix and namespace URI are reserved".into(),
        ));
    }
    if (prefix == Some("xml")) != (uri == XML_NS) {
        return Err(Error::Xml(
            "the xml prefix must be bound only to its reserved namespace URI".into(),
        ));
    }
    Ok(())
}

fn internal_general_entities(xml: &str) -> Result<HashMap<String, String>> {
    let Some((start, end)) = doctype_span(xml)? else {
        return Ok(HashMap::new());
    };
    let doctype = &xml[start..end];
    let Some(subset_start) = doctype.find('[') else {
        return Ok(HashMap::new());
    };
    let Some(subset_end) = doctype.rfind(']') else {
        return Err(Error::Xml(
            "unterminated document type internal subset".into(),
        ));
    };
    let subset = &doctype[subset_start + 1..subset_end];
    let mut entities = HashMap::new();
    let mut cursor = 0;
    while cursor < subset.len() {
        if subset[cursor..].starts_with("<!--") {
            let length = subset[cursor + 4..]
                .find("-->")
                .map(|offset| offset + 7)
                .ok_or_else(|| Error::Xml("unterminated DTD comment".into()))?;
            cursor += length;
            continue;
        }
        if !subset[cursor..].starts_with("<!ENTITY") {
            cursor += subset[cursor..].chars().next().map_or(1, char::len_utf8);
            continue;
        }
        cursor += "<!ENTITY".len();
        skip_xml_whitespace(subset, &mut cursor);
        if subset[cursor..].starts_with('%') {
            cursor = declaration_end(subset, cursor)?;
            continue;
        }
        let name_start = cursor;
        while cursor < subset.len()
            && !subset.as_bytes()[cursor].is_ascii_whitespace()
            && subset.as_bytes()[cursor] != b'>'
        {
            cursor += 1;
        }
        let name = &subset[name_start..cursor];
        if name.is_empty() {
            return Err(Error::Xml("internal entity declaration has no name".into()));
        }
        skip_xml_whitespace(subset, &mut cursor);
        let Some(quote) = subset.as_bytes().get(cursor).copied() else {
            return Err(Error::Xml(
                "unterminated internal entity declaration".into(),
            ));
        };
        if !matches!(quote, b'\'' | b'"') {
            cursor = declaration_end(subset, cursor)?;
            continue;
        }
        cursor += 1;
        let value_start = cursor;
        while subset
            .as_bytes()
            .get(cursor)
            .is_some_and(|byte| *byte != quote)
        {
            cursor += 1;
        }
        if cursor == subset.len() {
            return Err(Error::Xml(format!(
                "unterminated value for internal entity `{name}`"
            )));
        }
        let value = subset[value_start..cursor].to_owned();
        cursor += 1;
        cursor = declaration_end(subset, cursor)?;
        if entities.insert(name.to_owned(), value).is_some() {
            return Err(Error::Xml(format!(
                "duplicate internal entity declaration `{name}`"
            )));
        }
    }
    Ok(entities)
}

fn doctype_span(xml: &str) -> Result<Option<(usize, usize)>> {
    let Some(start) = xml.find("<!DOCTYPE") else {
        return Ok(None);
    };
    let mut quote = None;
    let mut subset_depth = 0usize;
    let mut cursor = start + "<!DOCTYPE".len();
    while cursor < xml.len() {
        if let Some(active) = quote {
            let ch = xml[cursor..]
                .chars()
                .next()
                .expect("cursor remains before the string end");
            cursor += ch.len_utf8();
            if ch == active {
                quote = None;
            }
            continue;
        }
        if xml[cursor..].starts_with("<!--") {
            let length = xml[cursor + 4..]
                .find("-->")
                .map(|offset| offset + 7)
                .ok_or_else(|| Error::Xml("unterminated DTD comment".into()))?;
            cursor += length;
            continue;
        }
        let ch = xml[cursor..]
            .chars()
            .next()
            .expect("cursor remains before the string end");
        cursor += ch.len_utf8();
        match ch {
            '\'' | '"' => quote = Some(ch),
            '[' => subset_depth += 1,
            ']' if subset_depth > 0 => subset_depth -= 1,
            '>' if subset_depth == 0 => return Ok(Some((start, cursor))),
            _ => {}
        }
    }
    Err(Error::Xml("unterminated document type declaration".into()))
}

fn declaration_end(subset: &str, mut cursor: usize) -> Result<usize> {
    let mut quote = None;
    while cursor < subset.len() {
        let ch = subset[cursor..]
            .chars()
            .next()
            .expect("cursor remains on a character boundary");
        cursor += ch.len_utf8();
        if let Some(active) = quote {
            if ch == active {
                quote = None;
            }
        } else {
            match ch {
                '\'' | '"' => quote = Some(ch),
                '>' => return Ok(cursor),
                _ => {}
            }
        }
    }
    Err(Error::Xml("unterminated entity declaration".into()))
}

fn skip_xml_whitespace(value: &str, cursor: &mut usize) {
    while value
        .as_bytes()
        .get(*cursor)
        .is_some_and(u8::is_ascii_whitespace)
    {
        *cursor += 1;
    }
}

fn expand_document_entities(xml: &str, entities: &HashMap<String, String>) -> Result<String> {
    if entities.is_empty() {
        return Ok(xml.to_owned());
    }
    let Some((_, doctype_end)) = doctype_span(xml)? else {
        return Ok(xml.to_owned());
    };
    let mut expanded = String::with_capacity(xml.len());
    let mut references = 0;
    expanded.push_str(&xml[..doctype_end]);
    expanded.push_str(&expand_entity_references(
        &xml[doctype_end..],
        entities,
        0,
        &mut references,
    )?);
    Ok(expanded)
}

fn expand_entity_references(
    value: &str,
    entities: &HashMap<String, String>,
    depth: usize,
    references: &mut usize,
) -> Result<String> {
    let mut output = String::with_capacity(value.len());
    let mut cursor = 0;
    while cursor < value.len() {
        let tail = &value[cursor..];
        let protected_end = if tail.starts_with("<!--") {
            tail.find("-->").map(|offset| offset + 3)
        } else if tail.starts_with("<![CDATA[") {
            tail.find("]]>").map(|offset| offset + 3)
        } else if tail.starts_with("<?") {
            tail.find("?>").map(|offset| offset + 2)
        } else {
            None
        };
        if let Some(length) = protected_end {
            output.push_str(&tail[..length]);
            cursor += length;
            continue;
        }
        if tail.starts_with('&')
            && let Some(end) = tail.find(';')
            && let name = &tail[1..end]
            && let Some(replacement) = entities.get(name)
        {
            let mut top_level_references = 0;
            let references = if depth == 0 {
                &mut top_level_references
            } else {
                &mut *references
            };
            *references += 1;
            if depth >= MAX_ENTITY_EXPANSION_DEPTH || *references > MAX_NESTED_ENTITY_REFERENCES {
                return Err(Error::Xml(format!(
                    "entity reference expansion limit exceeded at `{name}`"
                )));
            }
            output.push_str(&expand_entity_references(
                replacement,
                entities,
                depth + 1,
                references,
            )?);
            cursor += end + 1;
            continue;
        }
        let ch = tail
            .chars()
            .next()
            .expect("cursor remains before the string end");
        output.push(ch);
        cursor += ch.len_utf8();
    }
    Ok(output)
}

fn lexical_nesting_depth(xml: &str) -> usize {
    let bytes = xml.as_bytes();
    let mut cursor = 0usize;
    let mut depth = 0usize;
    let mut maximum = 0usize;
    while let Some(relative) = xml[cursor..].find('<') {
        let start = cursor + relative;
        if bytes.get(start + 1) == Some(&b'/') {
            depth = depth.saturating_sub(1);
        }
        let mut end = start + 1;
        let mut quote = None;
        while end < bytes.len() {
            let byte = bytes[end];
            if let Some(active) = quote {
                if byte == active {
                    quote = None;
                }
            } else if matches!(byte, b'\'' | b'"') {
                quote = Some(byte);
            } else if byte == b'>' {
                break;
            }
            end += 1;
        }
        if end == bytes.len() {
            break;
        }
        let marker = bytes.get(start + 1).copied();
        let self_closing = bytes[start + 1..end]
            .iter()
            .rev()
            .find(|byte| !byte.is_ascii_whitespace())
            == Some(&b'/');
        if !matches!(marker, Some(b'/' | b'!' | b'?')) && !self_closing {
            depth = depth.saturating_add(1);
            maximum = maximum.max(depth);
        }
        cursor = end + 1;
    }
    maximum
}

fn lexical_prefix(xml: &str, offset: usize, local: &str) -> Option<String> {
    let tail = xml.get(offset..)?;
    let start = tail.find('<')? + 1;
    let name = tail
        .get(start..)?
        .split(|character: char| character.is_whitespace() || matches!(character, '>' | '/'))
        .next()?;
    name.strip_suffix(local)?
        .strip_suffix(':')
        .map(str::to_owned)
}

fn attribute_prefix(
    xml: &str,
    node: roxmltree::Node<'_, '_>,
    attribute: roxmltree::Attribute<'_, '_>,
) -> Option<String> {
    let namespace = attribute.namespace()?;
    if namespace == "http://www.w3.org/XML/1998/namespace" {
        return Some("xml".into());
    }
    lexical_attribute_prefix(xml, attribute.range().start, attribute.name()).or_else(|| {
        node.namespaces()
            .find(|entry| entry.uri() == namespace && entry.name().is_some())
            .and_then(|entry| entry.name())
            .map(str::to_owned)
    })
}

fn lexical_attribute_prefix(xml: &str, offset: usize, local: &str) -> Option<String> {
    let lexical = xml
        .get(offset..)?
        .split(|character: char| character.is_whitespace() || character == '=')
        .next()?;
    lexical
        .strip_suffix(local)?
        .strip_suffix(':')
        .map(str::to_owned)
}

fn resolve_base_uri(base: Option<&str>, reference: &str) -> Result<String> {
    if let Ok(absolute) = url::Url::parse(reference) {
        return Ok(absolute.to_string());
    }
    if let Some(base) = base {
        if let Ok(joined) = url::Url::parse(base).and_then(|base| base.join(reference)) {
            return Ok(joined.to_string());
        }
        if let Some((directory, _)) = base.rsplit_once('/') {
            return Ok(format!("{directory}/{reference}"));
        }
    }
    Ok(reference.to_owned())
}

#[cfg(test)]
mod parser_boundary_tests {
    use super::{Document, Result};

    fn nested_xml(depth: usize, leaf: &str) -> String {
        format!("{}{}{}", "<n>".repeat(depth), leaf, "</n>".repeat(depth))
    }

    fn parse_tree_with_oracle_stack(xml: &str, base_uri: Option<&str>) -> Result<Document> {
        let xml = xml.to_owned();
        let base_uri = base_uri.map(str::to_owned);
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(move || Document::parse_tree(&xml, base_uri.as_deref()))
            .expect("parser oracle thread starts")
            .join()
            .expect("parser oracle thread does not panic")
    }

    #[test]
    fn tree_and_streaming_parsers_have_identical_boundary_semantics() {
        // Attacker-controlled depth must not select a different namespace, ID, or node model.
        for depth in (62..=66).chain(126..=130) {
            let xml = nested_xml(
                depth,
                r#"<p:leaf xmlns:p="urn:leaf" xml:id="target" p:value="ok">text</p:leaf>"#,
            );
            let tree = parse_tree_with_oracle_stack(&xml, Some("memory:source.xml"))
                .expect("tree parser accepts boundary document");
            let streaming = Document::parse_deep_streaming(&xml, Some("memory:source.xml"))
                .expect("streaming parser accepts boundary document");
            assert_eq!(tree, streaming, "parser models differ at depth {depth}");
        }
    }

    #[test]
    fn tree_and_streaming_parsers_coalesce_adjacent_character_data() {
        // Tokenizer event boundaries are not XPath text-node boundaries: text, references and
        // CDATA in one character-data run must project as one semantic text node.
        for depth in 126..=130 {
            let xml = nested_xml(depth, "<leaf>a&amp;b&#x21;<![CDATA[c]]>d</leaf>");
            let tree = parse_tree_with_oracle_stack(&xml, None)
                .expect("tree parser accepts adjacent character data");
            let streaming = Document::parse_deep_streaming(&xml, None)
                .expect("streaming parser accepts adjacent character data");
            assert_eq!(tree, streaming, "text projection differs at depth {depth}");
        }
    }

    #[test]
    fn tree_and_streaming_parsers_reject_the_same_boundary_malformations() {
        // Namespace and document-well-formedness failures cannot depend on the depth threshold.
        for depth in (62..=66).chain(126..=130) {
            for leaf in [
                "<p:leaf/>",
                "<p:a:b xmlns:p=\"urn:p\"/>",
                "<:leaf/>",
                "<leaf:/>",
                "<leaf p:a:b=\"x\" xmlns:p=\"urn:p\"/>",
                "<leaf xmlns:a=\"urn:u\" xmlns:b=\"urn:u\" a:x=\"1\" b:x=\"2\"/>",
                "<leaf xmlns:xml=\"urn:wrong\"/>",
                "<leaf xmlns:p=\"\"/>",
                "<leaf>&#0;</leaf>",
                "<leaf>&#x1;</leaf>",
            ] {
                let xml = nested_xml(depth, leaf);
                let tree_ok = parse_tree_with_oracle_stack(&xml, None).is_ok();
                let streaming_ok = Document::parse_deep_streaming(&xml, None).is_ok();
                assert!(
                    !tree_ok,
                    "tree parser accepted malformed input at depth {depth}: {leaf}"
                );
                assert_eq!(
                    tree_ok, streaming_ok,
                    "parser acceptance differs at depth {depth} for {leaf}"
                );
            }
        }
    }

    #[test]
    fn tree_and_streaming_parsers_reject_misplaced_and_duplicate_doctypes() {
        // Document depth must not make invalid prolog structure acceptable.
        let deep_document = nested_xml(65, "<leaf/>");
        for xml in [
            format!("<!DOCTYPE n><!DOCTYPE n>{deep_document}"),
            nested_xml(65, "<!DOCTYPE leaf><leaf/>"),
        ] {
            assert!(
                parse_tree_with_oracle_stack(&xml, None).is_err(),
                "tree parser accepted malformed doctype placement"
            );
            assert!(
                Document::parse_deep_streaming(&xml, None).is_err(),
                "streaming parser accepted malformed doctype placement"
            );
        }
    }
}
