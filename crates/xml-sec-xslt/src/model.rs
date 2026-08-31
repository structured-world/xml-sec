use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use xml_sec_xml_input::lexical::{Event, Scanner};

use crate::budget::{
    ENTITY_EXPANSION_BYTE_CEILING, ENTITY_EXPANSION_DEPTH_CEILING, ENTITY_REFERENCE_CEILING,
};
use crate::{Error, Result};

const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
const XMLNS_NS: &str = "http://www.w3.org/2000/xmlns/";

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
    source_bytes: usize,
    ids: HashMap<(NodeId, String), NodeId>,
    unparsed_entities: HashMap<(NodeId, String), String>,
}

impl PartialEq for Document {
    fn eq(&self, other: &Self) -> bool {
        self.nodes == other.nodes
            && self.root == other.root
            && self.logical_roots == other.logical_roots
            && self.source_bytes == other.source_bytes
            && self.ids == other.ids
            && self.unparsed_entities == other.unparsed_entities
    }
}

impl Eq for Document {}

impl Document {
    /// Parse caller-supplied XML into the engine semantic model.
    pub fn parse(xml: &str, base_uri: Option<&str>) -> Result<Self> {
        Self::parse_iterative(xml, base_uri)
    }

    /// Decode and parse caller-supplied XML bytes into the semantic model.
    pub fn parse_bytes(bytes: &[u8], base_uri: Option<&str>) -> Result<Self> {
        let xml =
            xml_sec_xml_input::decode_xml(bytes, None).map_err(crate::error::decoded_xml_error)?;
        Self::parse_iterative(&xml, base_uri)
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
            );
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

    #[cfg(test)]
    fn parse_tree(xml: &str, base_uri: Option<&str>) -> Result<Self> {
        let parsed =
            roxmltree::Document::parse(xml).map_err(|error| Error::Xml(error.to_string()))?;
        let mut document = Self::empty(base_uri.map(str::to_owned));
        document.source_bytes = xml.len();
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
                    set_namespace(
                        &mut namespaces,
                        namespace.name().map(str::to_owned),
                        namespace.uri().to_owned(),
                    );
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
                Some(crate::resolver::resolve_uri_reference(
                    inherited_base.as_deref(),
                    reference,
                )?)
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

    fn parse_iterative(xml: &str, base_uri: Option<&str>) -> Result<Self> {
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum DocumentPhase {
            Start,
            Prolog,
            Content,
            Epilog,
        }

        let mut document = Self::empty(base_uri.map(str::to_owned));
        document.source_bytes = xml.len();
        let mut entity_references = 0;
        let mut entity_expansion = EntityExpansionMeter::new(ENTITY_EXPANSION_BYTE_CEILING);
        let (parameter_expanded_xml, entities) =
            internal_general_entities(xml, &mut entity_references, &mut entity_expansion)?;
        let expanded_xml = expand_document_entities(
            parameter_expanded_xml.as_ref(),
            &entities,
            &mut entity_references,
            &mut entity_expansion,
        )?;
        let mut reader = Scanner::new(expanded_xml.as_ref());
        let mut previous_event_offset = 0usize;
        let mut source_line = 1usize;
        let mut phase = DocumentPhase::Start;
        let mut doctype_name = None::<&str>;
        let mut elements = vec![StreamElementFrame {
            node: document.root,
            lexical_name: None,
        }];
        while let Some(event) = reader
            .next_event()
            .map_err(|error| Error::Xml(error.to_string()))?
        {
            let event_offset = event_range_start(&event);
            source_line = source_line.saturating_add(
                expanded_xml.as_bytes()[previous_event_offset..event_offset]
                    .iter()
                    .filter(|byte| **byte == b'\n')
                    .count(),
            );
            previous_event_offset = event_offset;
            match event {
                Event::Start(start) => {
                    if elements.len() == 1 {
                        if phase == DocumentPhase::Epilog {
                            return Err(Error::Xml("multiple document elements".into()));
                        }
                        validate_doctype_root(doctype_name, start.name)?;
                        phase = DocumentPhase::Content;
                    }
                    let id = push_stream_element(
                        &mut document,
                        &mut elements,
                        &start,
                        false,
                        &entities,
                        &mut entity_references,
                        &mut entity_expansion,
                    )?;
                    document.nodes[id.0].source_line = Some(source_line);
                }
                Event::Empty(start) => {
                    if elements.len() == 1 {
                        if phase == DocumentPhase::Epilog {
                            return Err(Error::Xml("multiple document elements".into()));
                        }
                        validate_doctype_root(doctype_name, start.name)?;
                        phase = DocumentPhase::Epilog;
                    }
                    let id = push_stream_element(
                        &mut document,
                        &mut elements,
                        &start,
                        true,
                        &entities,
                        &mut entity_references,
                        &mut entity_expansion,
                    )?;
                    document.nodes[id.0].source_line = Some(source_line);
                }
                Event::End { name, .. } => {
                    if elements.len() == 1 {
                        return Err(Error::Xml("unmatched closing element".into()));
                    }
                    let closing_name = name.qualified();
                    let opening_name = elements
                        .last()
                        .and_then(|frame| frame.lexical_name.as_deref())
                        .expect("non-root element frames retain their lexical name");
                    if closing_name != opening_name {
                        return Err(Error::Xml(format!(
                            "closing element `{closing_name}` does not match `{opening_name}`"
                        )));
                    }
                    elements.pop();
                    if elements.len() == 1 {
                        phase = DocumentPhase::Epilog;
                    }
                }
                Event::Text { text, .. } => {
                    let value = normalize_xml_line_endings(text);
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
                Event::CData { text, .. } => {
                    if elements.len() == 1 {
                        return Err(Error::Xml(
                            "CDATA is not allowed outside the document element".into(),
                        ));
                    }
                    let id = push_parsed_text(
                        &mut document,
                        &elements,
                        normalize_xml_line_endings(text),
                    );
                    document.nodes[id.0].source_line.get_or_insert(source_line);
                }
                Event::Comment { text, .. } => {
                    if phase == DocumentPhase::Start {
                        phase = DocumentPhase::Prolog;
                    }
                    let parent = elements
                        .last()
                        .expect("document frame remains present")
                        .node;
                    let inherited_base =
                        document.node(parent).and_then(|node| node.base_uri.clone());
                    let id = document.push(
                        parent,
                        NodeKind::Comment(normalize_xml_line_endings(text)),
                        inherited_base,
                    );
                    document.nodes[id.0].source_line = Some(source_line);
                }
                Event::ProcessingInstruction {
                    target, content, ..
                } => {
                    if phase == DocumentPhase::Start {
                        phase = DocumentPhase::Prolog;
                    }
                    let parent = elements
                        .last()
                        .expect("document frame remains present")
                        .node;
                    let inherited_base =
                        document.node(parent).and_then(|node| node.base_uri.clone());
                    let id = document.push(
                        parent,
                        NodeKind::ProcessingInstruction {
                            target: target.to_owned(),
                            value: content.map(normalize_xml_line_endings),
                        },
                        inherited_base,
                    );
                    document.nodes[id.0].source_line = Some(source_line);
                }
                Event::Reference {
                    name: reference, ..
                } => {
                    if elements.len() == 1 {
                        return Err(Error::Xml(
                            "character and entity references are not allowed outside the document element"
                                .into(),
                        ));
                    }
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
                Event::Declaration { .. } => {
                    if phase != DocumentPhase::Start {
                        return Err(Error::Xml(
                            "XML declaration is permitted only at the start of the document".into(),
                        ));
                    }
                    phase = DocumentPhase::Prolog;
                }
                Event::DocType { name, .. } => {
                    if matches!(phase, DocumentPhase::Content | DocumentPhase::Epilog) {
                        return Err(Error::Xml(
                            "document type declaration is permitted only in the prolog".into(),
                        ));
                    }
                    if doctype_name.is_some() {
                        return Err(Error::Xml("duplicate document type declaration".into()));
                    }
                    doctype_name = Some(name);
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
            source_bytes: 0,
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

    pub(crate) const fn source_bytes(&self) -> usize {
        self.source_bytes
    }

    pub(crate) fn node_count(&self) -> usize {
        self.nodes.len()
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
        let value = &self
            .node(owner)
            .and_then(|node| match &node.kind {
                NodeKind::Element { attributes, .. } => attributes.get(attribute_index),
                _ => None,
            })
            .ok_or_else(|| Error::Xml("ID attribute reference is stale".into()))?
            .value;
        let value = collapse_xml_whitespace(value).into_owned();
        self.register_id_value(owner, value)
    }

    fn register_id_value(&mut self, owner: NodeId, value: String) -> Result<()> {
        if value.is_empty() {
            return Err(Error::Xml("ID attribute value is empty".into()));
        }
        let logical_root = self
            .logical_root_for(&NodeReference::Node(owner))
            .ok_or_else(|| Error::Xml("ID attribute is outside a logical document".into()))?;
        self.register_id_for_root(logical_root, owner, value)
    }

    fn register_id_for_root(
        &mut self,
        logical_root: NodeId,
        owner: NodeId,
        value: String,
    ) -> Result<()> {
        match self.ids.entry((logical_root, value)) {
            std::collections::hash_map::Entry::Occupied(entry) => {
                Err(Error::Xml(format!("duplicate XML ID `{}`", entry.key().1)))
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(owner);
                Ok(())
            }
        }
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
        if let Cow::Owned(normalized) = collapse_xml_whitespace(&attribute.value) {
            attribute.value = normalized;
        }
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
            let value = self
                .node_mut(owner)
                .and_then(|node| match &mut node.kind {
                    NodeKind::Element { attributes, .. } => attributes.get_mut(index),
                    _ => None,
                })
                .ok_or_else(|| Error::Xml("xml:id attribute reference is stale".into()))?;
            let normalized = collapse_xml_whitespace(&value.value).into_owned();
            if value.value != normalized {
                value.value.clone_from(&normalized);
            }
            self.register_id_value(owner, normalized)?;
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
            self.register_id_for_root(logical_root, owner, value.to_owned())?;
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

    pub(crate) fn visit_string_value(&self, id: NodeId, mut visit: impl FnMut(&str)) {
        let Some(node) = self.node(id) else {
            return;
        };
        match &node.kind {
            NodeKind::Text { value, .. } | NodeKind::Comment(value) => visit(value),
            NodeKind::ProcessingInstruction { value, .. } => {
                if let Some(value) = value {
                    visit(value);
                }
            }
            NodeKind::Root | NodeKind::Element { .. } => {
                let mut pending = node.children.iter().rev().copied().collect::<Vec<_>>();
                while let Some(current) = pending.pop() {
                    let Some(current) = self.node(current) else {
                        continue;
                    };
                    if let NodeKind::Text { value, .. } = &current.kind {
                        visit(value);
                    }
                    pending.extend(current.children.iter().rev().copied());
                }
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
        self.source_bytes = 0;
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

fn normalize_xml_line_endings(value: &str) -> String {
    if !value.contains('\r') {
        return value.to_owned();
    }
    let mut output = String::with_capacity(value.len());
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\r' {
            if characters.peek() == Some(&'\n') {
                characters.next();
            }
            output.push('\n');
        } else {
            output.push(character);
        }
    }
    output
}

fn normalize_xml_attribute_value(value: Cow<'_, str>) -> Cow<'_, str> {
    if !value.contains(['\r', '\n', '\t']) {
        return value;
    }
    let mut normalized = String::with_capacity(value.len());
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\r' => {
                if characters.peek() == Some(&'\n') {
                    characters.next();
                }
                normalized.push(' ');
            }
            '\n' | '\t' => normalized.push(' '),
            other => normalized.push(other),
        }
    }
    Cow::Owned(normalized)
}

struct StreamElementFrame {
    node: NodeId,
    lexical_name: Option<String>,
}

fn push_stream_element(
    document: &mut Document,
    elements: &mut Vec<StreamElementFrame>,
    start: &xml_sec_xml_input::lexical::StartTag<'_>,
    empty: bool,
    entities: &HashMap<String, String>,
    entity_references: &mut usize,
    entity_expansion: &mut EntityExpansionMeter,
) -> Result<NodeId> {
    let parent = elements
        .last()
        .map(|frame| frame.node)
        .expect("document frame remains present");
    let mut namespaces = match document.node(parent).map(|node| &node.kind) {
        Some(NodeKind::Element { namespaces, .. }) => namespaces.clone(),
        _ => vec![Namespace {
            prefix: Some("xml".into()),
            uri: "http://www.w3.org/XML/1998/namespace".into(),
        }],
    };
    let mut raw_attributes = Vec::new();
    for attribute in &start.attributes {
        let name = attribute.name.qualified();
        let value = expand_entity_references(
            attribute.value,
            entities,
            0,
            entity_references,
            entity_expansion,
        )?;
        if value.contains('<') {
            return Err(Error::Xml(format!(
                "attribute `{name}` entity replacement contains a literal `<`"
            )));
        }
        let value = normalize_xml_attribute_value(value);
        let value = match xml_sec_xml_input::lexical::decode_references(&value)
            .map_err(|error| Error::Xml(error.to_string()))?
        {
            Cow::Borrowed(_) => value,
            Cow::Owned(value) => Cow::Owned(value),
        };
        if name == "xmlns" {
            validate_namespace_binding(None, &value)?;
            set_namespace(&mut namespaces, None, value.into_owned());
        } else if let Some(prefix) = name.strip_prefix("xmlns:") {
            if !crate::lexical::is_ncname(prefix) {
                return Err(Error::Xml(format!("invalid namespace prefix {prefix}")));
            }
            validate_namespace_binding(Some(prefix), &value)?;
            set_namespace(&mut namespaces, Some(prefix.into()), value.into_owned());
        } else {
            raw_attributes.push((name.into_owned(), value.into_owned()));
        }
    }
    let lexical_name = start.name.qualified();
    let prefix = start.name.prefix().map(str::to_owned);
    let local = start.name.local().to_owned();
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
        Some(crate::resolver::resolve_uri_reference(
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
            namespaces,
        },
        effective_base,
    );
    if !empty {
        elements.push(StreamElementFrame {
            node: projected,
            lexical_name: Some(lexical_name.into_owned()),
        });
    }
    Ok(projected)
}

fn event_range_start(event: &xml_sec_xml_input::lexical::Event<'_>) -> usize {
    use xml_sec_xml_input::lexical::Event;
    match event {
        Event::Declaration { range, .. }
        | Event::ProcessingInstruction { range, .. }
        | Event::Comment { range, .. }
        | Event::DocType { range, .. }
        | Event::End { range, .. }
        | Event::Text { range, .. }
        | Event::CData { range, .. }
        | Event::Reference { range, .. } => range.start,
        Event::Start(tag) | Event::Empty(tag) => tag.range.start,
    }
}

fn validate_doctype_root(
    doctype_name: Option<&str>,
    element_name: xml_sec_xml_input::lexical::Name<'_>,
) -> Result<()> {
    if let Some(doctype_name) = doctype_name
        && !element_name.is_qualified(doctype_name)
    {
        return Err(Error::Xml(format!(
            "document type name `{doctype_name}` does not match the document element"
        )));
    }
    Ok(())
}

fn collapse_xml_whitespace(value: &str) -> Cow<'_, str> {
    let mut parts = value
        .split(crate::lexical::is_xml_whitespace)
        .filter(|part| !part.is_empty());
    let Some(first) = parts.next() else {
        return Cow::Owned(String::new());
    };
    if value == first {
        return Cow::Borrowed(value);
    }
    let mut normalized = String::with_capacity(value.len());
    normalized.push_str(first);
    for part in parts {
        normalized.push(' ');
        normalized.push_str(part);
    }
    Cow::Owned(normalized)
}

fn push_parsed_text(
    document: &mut Document,
    elements: &[StreamElementFrame],
    value: String,
) -> NodeId {
    let parent = elements
        .last()
        .expect("document frame remains present")
        .node;
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

fn internal_general_entities<'a>(
    xml: &'a str,
    references: &mut usize,
    meter: &mut EntityExpansionMeter,
) -> Result<(Cow<'a, str>, HashMap<String, String>)> {
    let Some((start, end)) = doctype_span(xml)? else {
        return Ok((Cow::Borrowed(xml), HashMap::new()));
    };
    let doctype = &xml[start..end];
    let Some(subset_start) = doctype.find('[') else {
        return Ok((Cow::Borrowed(xml), HashMap::new()));
    };
    let Some(subset_end) = doctype.rfind(']') else {
        return Err(Error::Xml(
            "unterminated document type internal subset".into(),
        ));
    };
    let subset_start = start + subset_start + 1;
    let subset_end = start + subset_end;
    let subset = &xml[subset_start..subset_end];
    let declarations = collect_internal_entity_declarations(subset)?;
    let expanded_subset = expand_parameter_entity_references(
        subset,
        &declarations.parameter,
        &declarations.parameter_spans,
        0,
        references,
        meter,
    )?;
    let entities = if matches!(expanded_subset, Cow::Borrowed(_)) {
        declarations.general
    } else {
        collect_internal_entity_declarations(expanded_subset.as_ref())?.general
    };
    if matches!(expanded_subset, Cow::Borrowed(_)) {
        return Ok((Cow::Borrowed(xml), entities));
    }
    let mut expanded_xml = String::with_capacity(
        xml.len()
            .saturating_sub(subset.len())
            .saturating_add(expanded_subset.len()),
    );
    expanded_xml.push_str(&xml[..subset_start]);
    expanded_xml.push_str(expanded_subset.as_ref());
    expanded_xml.push_str(&xml[subset_end..]);
    Ok((Cow::Owned(expanded_xml), entities))
}

#[derive(Default)]
struct InternalEntityDeclarations {
    general: HashMap<String, String>,
    parameter: HashMap<String, String>,
    parameter_spans: Vec<(usize, usize)>,
}

fn collect_internal_entity_declarations(subset: &str) -> Result<InternalEntityDeclarations> {
    let mut declarations = InternalEntityDeclarations::default();
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
        if subset[cursor..].starts_with("<?") {
            let length = subset[cursor + 2..]
                .find("?>")
                .map(|offset| offset + 4)
                .ok_or_else(|| Error::Xml("unterminated DTD processing instruction".into()))?;
            cursor += length;
            continue;
        }
        if !subset[cursor..].starts_with("<!ENTITY") {
            cursor += subset[cursor..].chars().next().map_or(1, char::len_utf8);
            continue;
        }
        let declaration_start = cursor;
        cursor += "<!ENTITY".len();
        skip_xml_whitespace(subset, &mut cursor);
        let parameter = subset[cursor..].starts_with('%');
        if parameter {
            cursor += 1;
            skip_xml_whitespace(subset, &mut cursor);
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
        let mut value = subset[value_start..cursor].to_owned();
        cursor += 1;
        cursor = declaration_end(subset, cursor)?;
        if parameter {
            declarations
                .parameter_spans
                .push((declaration_start, cursor));
        }
        let entities = if parameter {
            &mut declarations.parameter
        } else {
            &mut declarations.general
        };
        if !parameter {
            value = normalize_predefined_entity_declaration(name, value)?;
        }
        if let std::collections::hash_map::Entry::Vacant(entry) = entities.entry(name.to_owned()) {
            entry.insert(value);
        }
    }
    Ok(declarations)
}

fn normalize_predefined_entity_declaration(name: &str, value: String) -> Result<String> {
    let (expected, required_replacement) = match name {
        "amp" => ('&', Some("&#38;")),
        "apos" => ('\'', None),
        "gt" => ('>', None),
        "lt" => ('<', Some("&#60;")),
        "quot" => ('"', None),
        _ => return Ok(value),
    };
    let first = xml_sec_xml_input::lexical::decode_references(&value)
        .map_err(|error| Error::Xml(error.to_string()))?;
    if required_replacement.is_some_and(|required| first.as_ref() != required) {
        return Err(Error::Xml(format!(
            "invalid predefined entity declaration `{name}`"
        )));
    }
    let second = xml_sec_xml_input::lexical::decode_references(&first)
        .map_err(|_| Error::Xml(format!("invalid predefined entity declaration `{name}`")))?;
    if !second.chars().eq(std::iter::once(expected)) {
        return Err(Error::Xml(format!(
            "invalid predefined entity declaration `{name}`"
        )));
    }
    Ok(first.into_owned())
}

fn expand_parameter_entity_references<'a>(
    value: &'a str,
    entities: &HashMap<String, String>,
    excluded_declarations: &[(usize, usize)],
    depth: usize,
    references: &mut usize,
    meter: &mut EntityExpansionMeter,
) -> Result<Cow<'a, str>> {
    if excluded_declarations.is_empty()
        && (entities.is_empty() || !value.as_bytes().contains(&b'%'))
    {
        return Ok(Cow::Borrowed(value));
    }
    let mut output = String::with_capacity(value.len());
    let mut cursor = 0;
    for &(start, end) in excluded_declarations {
        expand_parameter_entity_references_into(
            &value[cursor..start],
            entities,
            depth,
            references,
            meter,
            &mut output,
        )?;
        cursor = end;
    }
    expand_parameter_entity_references_into(
        &value[cursor..],
        entities,
        depth,
        references,
        meter,
        &mut output,
    )?;
    Ok(Cow::Owned(output))
}

fn expand_parameter_entity_references_into(
    value: &str,
    entities: &HashMap<String, String>,
    depth: usize,
    references: &mut usize,
    meter: &mut EntityExpansionMeter,
    output: &mut String,
) -> Result<()> {
    const MAX_ENTITY_NAME_SCAN_BYTES: usize = 1_024;
    let mut cursor = 0usize;
    while cursor < value.len() {
        let tail = &value[cursor..];
        let protected_end = if tail.starts_with("<!--") {
            tail.find("-->").map(|offset| offset + 3)
        } else if tail.starts_with("<?") {
            tail.find("?>").map(|offset| offset + 2)
        } else {
            None
        };
        if let Some(length) = protected_end {
            meter.append(output, &tail[..length])?;
            cursor += length;
            continue;
        }
        if tail.starts_with('%')
            && let Some(end) = tail.as_bytes()[..tail.len().min(MAX_ENTITY_NAME_SCAN_BYTES)]
                .iter()
                .position(|byte| *byte == b';')
            && let name = &tail[1..end]
            && let Some(replacement) = entities.get(name)
        {
            *references += 1;
            if depth >= ENTITY_EXPANSION_DEPTH_CEILING || *references > ENTITY_REFERENCE_CEILING {
                return Err(Error::Xml(format!(
                    "entity reference expansion limit exceeded at `%{name};`"
                )));
            }
            expand_parameter_entity_references_into(
                replacement,
                entities,
                depth + 1,
                references,
                meter,
                output,
            )?;
            cursor += end + 1;
            continue;
        }
        let plain_end = tail
            .char_indices()
            .find_map(|(offset, character)| matches!(character, '<' | '%').then_some(offset))
            .filter(|offset| *offset > 0)
            .unwrap_or_else(|| {
                if matches!(tail.as_bytes().first(), Some(b'<' | b'%')) {
                    tail.chars()
                        .next()
                        .expect("cursor remains before the string end")
                        .len_utf8()
                } else {
                    tail.len()
                }
            });
        meter.append(output, &tail[..plain_end])?;
        cursor += plain_end;
    }
    Ok(())
}

fn doctype_span(xml: &str) -> Result<Option<(usize, usize)>> {
    let mut cursor = usize::from(xml.starts_with('\u{feff}')) * '\u{feff}'.len_utf8();
    loop {
        skip_xml_whitespace(xml, &mut cursor);
        let tail = &xml[cursor..];
        if tail.starts_with("<!--") {
            cursor += tail
                .find("-->")
                .map(|offset| offset + 3)
                .ok_or_else(|| Error::Xml("unterminated XML comment".into()))?;
            continue;
        }
        if tail.starts_with("<?") {
            cursor += tail
                .find("?>")
                .map(|offset| offset + 2)
                .ok_or_else(|| Error::Xml("unterminated XML processing instruction".into()))?;
            continue;
        }
        if !tail.starts_with("<!DOCTYPE") {
            return Ok(None);
        }
        return scan_doctype_end(tail).map(|length| Some((cursor, cursor + length)));
    }
}

fn scan_doctype_end(doctype: &str) -> Result<usize> {
    let mut cursor = "<!DOCTYPE".len();
    let mut quote = None;
    let mut internal_subset_depth = 0usize;
    while cursor < doctype.len() {
        let tail = &doctype[cursor..];
        if quote.is_none() && tail.starts_with("<!--") {
            cursor += tail
                .find("-->")
                .map(|offset| offset + 3)
                .ok_or_else(|| Error::Xml("unterminated DTD comment".into()))?;
            continue;
        }
        if quote.is_none() && tail.starts_with("<?") {
            cursor += tail
                .find("?>")
                .map(|offset| offset + 2)
                .ok_or_else(|| Error::Xml("unterminated DTD processing instruction".into()))?;
            continue;
        }
        let character = tail
            .chars()
            .next()
            .expect("cursor remains before the string end");
        cursor += character.len_utf8();
        if let Some(active) = quote {
            if character == active {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            '[' => internal_subset_depth += 1,
            ']' => {
                internal_subset_depth = internal_subset_depth.saturating_sub(1);
            }
            '>' if internal_subset_depth == 0 => return Ok(cursor),
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

fn expand_document_entities<'a>(
    xml: &'a str,
    entities: &HashMap<String, String>,
    references: &mut usize,
    meter: &mut EntityExpansionMeter,
) -> Result<Cow<'a, str>> {
    if entities.is_empty() {
        return Ok(Cow::Borrowed(xml));
    }
    let Some((_, doctype_end)) = doctype_span(xml)? else {
        return Ok(Cow::Borrowed(xml));
    };
    if !contains_expandable_entity_reference(&xml[doctype_end..], entities) {
        return Ok(Cow::Borrowed(xml));
    }
    let mut expanded = String::with_capacity(xml.len());
    meter.append(&mut expanded, &xml[..doctype_end])?;
    expand_entity_references_into(
        &xml[doctype_end..],
        entities,
        0,
        references,
        meter,
        &mut expanded,
    )?;
    Ok(Cow::Owned(expanded))
}

fn expand_entity_references<'a>(
    value: &'a str,
    entities: &HashMap<String, String>,
    depth: usize,
    references: &mut usize,
    meter: &mut EntityExpansionMeter,
) -> Result<Cow<'a, str>> {
    if entities.is_empty() || !contains_expandable_entity_reference(value, entities) {
        return Ok(Cow::Borrowed(value));
    }
    let mut output = String::with_capacity(value.len());
    expand_entity_references_into(value, entities, depth, references, meter, &mut output)?;
    Ok(Cow::Owned(output))
}

fn contains_expandable_entity_reference(value: &str, entities: &HashMap<String, String>) -> bool {
    const MAX_ENTITY_NAME_SCAN_BYTES: usize = 1_024;
    let bytes = value.as_bytes();
    let mut cursor = 0usize;
    while let Some(relative) = bytes[cursor..].iter().position(|byte| *byte == b'&') {
        let name_start = cursor + relative + 1;
        let scan_end = name_start
            .saturating_add(MAX_ENTITY_NAME_SCAN_BYTES)
            .min(bytes.len());
        if let Some(relative_end) = bytes[name_start..scan_end]
            .iter()
            .position(|byte| *byte == b';')
        {
            let name_end = name_start + relative_end;
            if entities.contains_key(&value[name_start..name_end]) {
                return true;
            }
            cursor = name_end + 1;
        } else {
            cursor = name_start;
        }
    }
    false
}

fn expand_entity_references_into(
    value: &str,
    entities: &HashMap<String, String>,
    depth: usize,
    references: &mut usize,
    meter: &mut EntityExpansionMeter,
    output: &mut String,
) -> Result<()> {
    const MAX_ENTITY_NAME_SCAN_BYTES: usize = 1_024;
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
            meter.append(output, &tail[..length])?;
            cursor += length;
            continue;
        }
        if tail.starts_with('<')
            && let Some(length) = xml_markup_len(tail)
        {
            meter.append(output, &tail[..length])?;
            cursor += length;
            continue;
        }
        if tail.starts_with('&')
            && let Some(end) = tail.as_bytes()[..tail.len().min(MAX_ENTITY_NAME_SCAN_BYTES)]
                .iter()
                .position(|byte| *byte == b';')
            && let name = &tail[1..end]
            && let Some(replacement) = entities.get(name)
        {
            *references += 1;
            if depth >= ENTITY_EXPANSION_DEPTH_CEILING || *references > ENTITY_REFERENCE_CEILING {
                return Err(Error::Xml(format!(
                    "entity reference expansion limit exceeded at `{name}`"
                )));
            }
            expand_entity_references_into(
                replacement,
                entities,
                depth + 1,
                references,
                meter,
                output,
            )?;
            cursor += end + 1;
            continue;
        }
        let plain_end = tail
            .char_indices()
            .find_map(|(offset, ch)| matches!(ch, '<' | '&').then_some(offset))
            .filter(|offset| *offset > 0)
            .unwrap_or_else(|| {
                if matches!(tail.as_bytes().first(), Some(b'<' | b'&')) {
                    tail.chars()
                        .next()
                        .expect("cursor remains before the string end")
                        .len_utf8()
                } else {
                    tail.len()
                }
            });
        meter.append(output, &tail[..plain_end])?;
        cursor += plain_end;
    }
    Ok(())
}

struct EntityExpansionMeter {
    limit: usize,
    used: usize,
}

impl EntityExpansionMeter {
    const fn new(limit: usize) -> Self {
        Self { limit, used: 0 }
    }

    fn append(&mut self, output: &mut String, value: &str) -> Result<()> {
        self.charge(value.len())?;
        output.push_str(value);
        Ok(())
    }

    fn charge(&mut self, amount: usize) -> Result<()> {
        let actual = self.used.saturating_add(amount);
        crate::budget::ensure(crate::BudgetKind::OwnedBytes, self.limit, actual)?;
        self.used = actual;
        Ok(())
    }
}

fn xml_markup_len(source: &str) -> Option<usize> {
    let mut quote = None;
    for (offset, byte) in source.bytes().enumerate().skip(1) {
        match (quote, byte) {
            (None, b'\'' | b'"') => quote = Some(byte),
            (Some(delimiter), current) if delimiter == current => quote = None,
            (None, b'>') => return Some(offset + 1),
            _ => {}
        }
    }
    None
}

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
mod parser_boundary_tests {
    use std::collections::HashMap;
    use std::fmt::Write as _;

    use super::{
        Document, EntityExpansionMeter, Result, doctype_span, expand_document_entities,
        expand_entity_references, expand_parameter_entity_references, internal_general_entities,
        normalize_predefined_entity_declaration,
    };
    use crate::budget::ENTITY_EXPANSION_BYTE_CEILING;

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
    fn oracle_and_iterative_parsers_have_identical_boundary_semantics() {
        // Attacker-controlled depth must not select a different namespace, ID, or node model.
        for depth in (62..=66).chain(126..=130) {
            let xml = nested_xml(
                depth,
                r#"<p:leaf xmlns:p="urn:leaf" xml:id="target" p:value="ok">text</p:leaf>"#,
            );
            let tree = parse_tree_with_oracle_stack(&xml, Some("memory:source.xml"))
                .expect("tree parser accepts boundary document");
            let iterative = Document::parse_iterative(&xml, Some("memory:source.xml"))
                .expect("iterative parser accepts boundary document");
            assert_eq!(tree, iterative, "parser models differ at depth {depth}");
        }
    }

    #[test]
    fn empty_xml_base_preserves_a_path_like_document_uri() {
        // RFC 3986 empty references retain the current document path while
        // removing its fragment; treating the base as a directory moves it.
        let document = Document::parse(
            r#"<root xml:base=""><child/></root>"#,
            Some("/tmp/styles/main.xml#source"),
        )
        .expect("path-like base parses");
        let root = document
            .nodes()
            .find_map(|(_, node)| {
                matches!(node.kind, super::NodeKind::Element { .. }).then_some(node)
            })
            .expect("document element exists");
        assert_eq!(root.base_uri.as_deref(), Some("/tmp/styles/main.xml"));
    }

    #[test]
    fn oracle_and_iterative_parsers_coalesce_adjacent_character_data() {
        // Tokenizer event boundaries are not XPath text-node boundaries: text, references and
        // CDATA in one character-data run must project as one semantic text node.
        for depth in 126..=130 {
            let xml = nested_xml(depth, "<leaf>a&amp;b&#x21;<![CDATA[c]]>d</leaf>");
            let tree = parse_tree_with_oracle_stack(&xml, None)
                .expect("tree parser accepts adjacent character data");
            let iterative = Document::parse_iterative(&xml, None)
                .expect("iterative parser accepts adjacent character data");
            assert_eq!(tree, iterative, "text projection differs at depth {depth}");
        }
    }

    #[test]
    fn iterative_parser_excludes_the_pi_separator_from_data() {
        // XML's mandatory S between PITarget and data is syntax, not part of
        // the processing-instruction value exposed by the semantic model.
        let document = Document::parse_iterative("<root><?target   value ?></root>", None)
            .expect("processing instruction parses");
        let value = document.nodes().find_map(|(_, node)| match &node.kind {
            super::NodeKind::ProcessingInstruction { value, .. } => value.as_deref(),
            _ => None,
        });
        assert_eq!(value, Some("value "));
    }

    #[test]
    fn iterative_parser_bounds_entity_references_across_the_document() {
        // Sibling references share one expansion allowance; resetting the
        // counter per sibling makes total expanded output attacker-controlled.
        let body = format!("<leaf>{}</leaf>", "&e;".repeat(256));
        let xml = format!(r#"<!DOCTYPE n [<!ENTITY e "x">]>{}"#, nested_xml(65, &body));

        let error = Document::parse_iterative(&xml, None)
            .expect_err("the document-wide entity-reference ceiling must reject sibling fanout");
        assert!(
            error
                .to_string()
                .contains("entity reference expansion limit")
        );
    }

    #[test]
    fn iterative_parser_bounds_aggregate_text_entity_expansion_bytes() {
        // A bounded reference count is insufficient when each permitted
        // reference materializes a large replacement into document text.
        let replacement = "x".repeat(70_000);
        let body = "&large;".repeat(255);
        let xml = format!("<!DOCTYPE root [<!ENTITY large \"{replacement}\">]><root>{body}</root>");

        let error = Document::parse_iterative(&xml, None)
            .expect_err("aggregate expanded text must remain bounded");
        assert!(matches!(error, crate::Error::Budget { .. }));
    }

    #[test]
    fn iterative_parser_bounds_aggregate_attribute_entity_expansion_bytes() {
        // Attribute expansion happens after the document-level lexical pass
        // and must consume the same document-wide materialization budget.
        let replacement = "x".repeat(70_000);
        let mut attributes = String::new();
        for index in 0..255 {
            write!(attributes, " a{index}=\"&large;\"")
                .expect("writing attributes to String cannot fail");
        }
        let xml = format!("<!DOCTYPE root [<!ENTITY large \"{replacement}\">]><root{attributes}/>");

        let error = Document::parse_iterative(&xml, None)
            .expect_err("aggregate expanded attributes must remain bounded");
        assert!(matches!(error, crate::Error::Budget { .. }));
    }

    #[test]
    fn oracle_and_iterative_parsers_reject_the_same_boundary_malformations() {
        // Namespace and document-well-formedness failures cannot depend on document depth.
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
                let iterative_ok = Document::parse_iterative(&xml, None).is_ok();
                assert!(
                    !tree_ok,
                    "tree parser accepted malformed input at depth {depth}: {leaf}"
                );
                assert_eq!(
                    tree_ok, iterative_ok,
                    "parser acceptance differs at depth {depth} for {leaf}"
                );
            }
        }
    }

    #[test]
    fn iterative_parser_rejects_mismatched_closing_names() {
        // Deep documents select the iterative parser, which must enforce the
        // same lexical element nesting invariant as the regular parser.
        let xml = nested_xml(65, "<expected></different>");
        assert!(parse_tree_with_oracle_stack(&xml, None).is_err());
        assert!(
            Document::parse_iterative(&xml, None).is_err(),
            "iterative parser accepted a mismatched closing element"
        );
    }

    #[test]
    fn iterative_parser_expands_entities_inside_attribute_value_context() {
        // Entity replacement text is interpreted inside the attribute value;
        // a quote in that text must not terminate the source-level delimiter.
        let xml = r#"<!DOCTYPE root [<!ENTITY quote "'">]><root value='&quote;'/>"#;
        let iterative = Document::parse_iterative(xml, None)
            .expect("iterative parser must preserve attribute quoting");
        let value = iterative.nodes().find_map(|(_, node)| match &node.kind {
            super::NodeKind::Element { attributes, .. } => attributes
                .iter()
                .find(|attribute| attribute.name.local == "value")
                .map(|attribute| attribute.value.as_str()),
            _ => None,
        });
        assert_eq!(value, Some("'"));
    }

    #[test]
    fn oracle_and_iterative_parsers_reject_misplaced_and_duplicate_doctypes() {
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
                Document::parse_iterative(&xml, None).is_err(),
                "iterative parser accepted malformed doctype placement"
            );
        }
    }

    #[test]
    fn every_parser_rejects_a_doctype_for_another_document_element() {
        // Document depth must not select a parser with weaker DOCTYPE well-formedness checks.
        let shallow = "<!DOCTYPE expected><actual/>";
        assert!(Document::parse(shallow, None).is_err());
        assert!(Document::parse_iterative(shallow, None).is_err());

        let deep = format!("<!DOCTYPE expected>{}", nested_xml(130, "<actual/>"));
        assert!(Document::parse(&deep, None).is_err());
        assert!(Document::parse_iterative(&deep, None).is_err());
    }

    #[test]
    fn doctype_discovery_is_limited_to_the_document_prolog() {
        // Lexical lookalikes in comments and character data are not declarations.
        for xml in [
            "<!-- <!DOCTYPE fake [<!ENTITY e 'bad'>]> --><root/>",
            "<root><![CDATA[<!DOCTYPE fake [<!ENTITY e 'bad'>]>]]></root>",
        ] {
            assert_eq!(doctype_span(xml).expect("doctype scan succeeds"), None);
            Document::parse_iterative(xml, None).expect("document parses without a doctype");
        }
    }

    #[test]
    fn dtd_processing_instructions_cannot_declare_entities() {
        // Processing-instruction content is a protected DTD region. Markup-shaped text inside it
        // must not become a declaration consumed by the entity-expansion pass.
        let xml = r#"<!DOCTYPE r [<?pi <!ENTITY e "evil">?>]><r>&e;</r>"#;
        assert!(Document::parse_iterative(xml, None).is_err());
    }

    #[test]
    fn duplicate_entity_declarations_retain_the_first_binding() {
        // XML binds the first declaration of an entity; later declarations neither replace it
        // nor make an otherwise well-formed document invalid.
        let document = Document::parse_iterative(
            r#"<!DOCTYPE r [<!ENTITY e "first"><!ENTITY e "second">]><r>&e;</r>"#,
            None,
        )
        .expect("duplicate entity declarations are well-formed");
        assert_eq!(document.string_value(document.root()), "first");
    }

    #[test]
    fn predefined_entity_redeclarations_preserve_xml_builtins() {
        // XML permits only the normative replacement forms for predefined entities. A malformed
        // declaration must not replace a builtin before the document reaches the XML parser.
        for invalid in [
            r#"<!DOCTYPE r [<!ENTITY amp "evil">]><r>&amp;</r>"#,
            r#"<!DOCTYPE r [<!ENTITY amp "&#38;">]><r>&amp;</r>"#,
            r#"<!DOCTYPE r [<!ENTITY lt "&#60;">]><r>&lt;</r>"#,
        ] {
            assert!(Document::parse_iterative(invalid, None).is_err());
        }

        let valid = r#"<!DOCTYPE r [
            <!ENTITY amp "&#38;#38;">
            <!ENTITY apos "&#39;">
            <!ENTITY gt "&#62;">
            <!ENTITY lt "&#38;#60;">
            <!ENTITY quot "&#34;">
        ]><r>&amp;&lt;&gt;&apos;&quot;</r>"#;
        let document = Document::parse_iterative(valid, None)
            .expect("normative predefined-entity redeclarations remain well-formed");
        assert_eq!(document.string_value(document.root()), "&<>'\"");
    }

    #[test]
    fn predefined_amp_and_lt_require_double_escaped_declarations() {
        // XML 1.0 requires the replacement text for amp and lt to remain a character reference
        // after the declaration's first entity-replacement pass.
        assert!(normalize_predefined_entity_declaration("amp", "&#38;".into()).is_err());
        assert!(normalize_predefined_entity_declaration("lt", "&#60;".into()).is_err());
        assert_eq!(
            normalize_predefined_entity_declaration("amp", "&#38;#38;".into())
                .expect("normative amp declaration"),
            "&#38;"
        );
        assert_eq!(
            normalize_predefined_entity_declaration("lt", "&#38;#60;".into())
                .expect("normative lt declaration"),
            "&#60;"
        );
    }

    #[test]
    fn internal_parameter_entities_contribute_markup_declarations() {
        // Parameter entities in the internal subset can expand to declarations consumed by the
        // document. The parser must process that declaration before resolving general entities.
        let xml = r#"<!DOCTYPE r [<!ENTITY % defs '<!ENTITY e "ok">'> %defs;]><r>&e;</r>"#;
        let mut references = 0;
        let mut meter = EntityExpansionMeter::new(ENTITY_EXPANSION_BYTE_CEILING);
        let (prepared, entities) = internal_general_entities(xml, &mut references, &mut meter)
            .expect("parameter entity subset is prepared");
        assert_eq!(prepared, r#"<!DOCTYPE r [ <!ENTITY e "ok">]><r>&e;</r>"#);
        assert_eq!(entities.get("e").map(String::as_str), Some("ok"));

        let document =
            Document::parse_iterative(xml, None).expect("parameter entity declaration expands");
        assert_eq!(document.string_value(document.root()), "ok");
    }

    #[test]
    fn parameter_entity_expansion_enforces_recursive_aggregate_limits() {
        // Parameter entities share the bounded expansion path used by document entities: cycles,
        // aggregate references, and materialized bytes must all fail before parser allocation.
        let recursive = HashMap::from([("loop".into(), "%loop;".into())]);
        assert!(
            expand_parameter_entity_references(
                "%loop;",
                &recursive,
                &[],
                0,
                &mut 0,
                &mut EntityExpansionMeter::new(ENTITY_EXPANSION_BYTE_CEILING),
            )
            .is_err()
        );

        let leaf = HashMap::from([("leaf".into(), "x".into())]);
        let references = "%leaf;".repeat(256);
        assert!(
            expand_parameter_entity_references(
                &references,
                &leaf,
                &[],
                0,
                &mut 0,
                &mut EntityExpansionMeter::new(ENTITY_EXPANSION_BYTE_CEILING),
            )
            .is_err()
        );
        assert!(
            expand_parameter_entity_references(
                "%leaf;",
                &leaf,
                &[],
                0,
                &mut 0,
                &mut EntityExpansionMeter::new(0),
            )
            .is_err()
        );
    }

    #[test]
    fn attribute_normalization_preserves_referenced_whitespace() {
        // Literal XML whitespace normalizes to spaces, while character references append their
        // referenced scalar after normalization and therefore retain tab/newline characters.
        let document = Document::parse_iterative("<r a=\"\t&#x9;&#xA;&#xD;\"/>", None)
            .expect("attribute whitespace parses");
        let value = document
            .nodes()
            .find_map(|(_, node)| match &node.kind {
                super::NodeKind::Element { attributes, .. } => {
                    attributes.first().map(|attribute| attribute.value.as_str())
                }
                _ => None,
            })
            .expect("attribute exists");
        assert_eq!(value, " \t\n\r");
    }

    #[test]
    fn entity_name_lookup_has_a_fixed_lexical_window() {
        // A distant semicolon cannot turn one ampersand into an unbounded linear scan.
        let name = "a".repeat(1_100);
        let source = format!("&{name};");
        let entities = HashMap::from([(name, "expanded".into())]);
        assert_eq!(
            expand_entity_references(
                &source,
                &entities,
                0,
                &mut 0,
                &mut EntityExpansionMeter::new(ENTITY_EXPANSION_BYTE_CEILING),
            )
            .expect("bounded entity scan succeeds"),
            source
        );
    }

    #[test]
    fn unused_entity_declarations_keep_the_source_borrowed() {
        // Declaring an entity must not force a full document or attribute copy when no
        // replacement is required on the parsed path.
        let xml = "<!DOCTYPE root [<!ENTITY unused 'value'>]><root plain='text'/>";
        let entities = HashMap::from([("unused".to_owned(), "value".to_owned())]);
        let mut references = 0;
        let mut meter = EntityExpansionMeter::new(ENTITY_EXPANSION_BYTE_CEILING);
        assert!(matches!(
            expand_document_entities(xml, &entities, &mut references, &mut meter)
                .expect("unused declaration is accepted"),
            std::borrow::Cow::Borrowed(_)
        ));
        assert!(matches!(
            expand_entity_references("text", &entities, 0, &mut references, &mut meter,)
                .expect("plain attribute is accepted"),
            std::borrow::Cow::Borrowed(_)
        ));
    }

    #[test]
    fn entity_name_window_never_slices_inside_utf8() {
        // The byte-bounded semicolon search must not turn a multibyte scalar
        // crossing the ceiling into a char-boundary panic.
        let source = format!("&{}é", "a".repeat(1_022));
        let entities = HashMap::from([("x".to_owned(), "expanded".to_owned())]);
        assert_eq!(
            expand_entity_references(
                &source,
                &entities,
                0,
                &mut 0,
                &mut EntityExpansionMeter::new(ENTITY_EXPANSION_BYTE_CEILING),
            )
            .expect("bounded entity scan succeeds"),
            source
        );
    }
}
