use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{Error, Result};

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
        if lexical_nesting_depth(xml) > 128 {
            return Self::parse_deep_streaming(xml, base_uri);
        }
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
                let attributes = source
                    .attributes()
                    .map(|attribute| Attribute {
                        name: ExpandedName::new(attribute.namespace(), attribute.name()),
                        prefix: attribute_prefix(source, attribute),
                        value: attribute.value().to_owned(),
                    })
                    .collect();
                let mut namespaces = source
                    .namespaces()
                    .map(|namespace| Namespace {
                        prefix: namespace.name().map(str::to_owned),
                        uri: namespace.uri().to_owned(),
                    })
                    .collect::<Vec<_>>();
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
            let id = document.push(parent, kind, inherited_base);
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

        let mut document = Self::empty(base_uri.map(str::to_owned));
        document.source_xml = Some(xml.to_owned());
        let mut reader = Reader::from_str(xml);
        let mut elements = vec![(
            document.root,
            vec![Namespace {
                prefix: Some("xml".into()),
                uri: "http://www.w3.org/XML/1998/namespace".into(),
            }],
        )];
        loop {
            match reader
                .read_event()
                .map_err(|error| Error::Xml(error.to_string()))?
            {
                Event::Start(start) => {
                    push_stream_element(&mut document, &mut elements, &start, false)?
                }
                Event::Empty(start) => {
                    push_stream_element(&mut document, &mut elements, &start, true)?
                }
                Event::End(_) => {
                    if elements.len() == 1 {
                        return Err(Error::Xml("unmatched closing element".into()));
                    }
                    elements.pop();
                }
                Event::Text(text) => {
                    let value = text.xml10_content().into_owned();
                    if elements.len() > 1 && !value.is_empty() {
                        push_parsed_text(&mut document, &elements, value);
                    }
                }
                Event::CData(text) => {
                    push_parsed_text(&mut document, &elements, text.xml10_content().into_owned());
                }
                Event::Comment(comment) => {
                    let parent = elements.last().expect("document frame remains present").0;
                    let inherited_base =
                        document.node(parent).and_then(|node| node.base_uri.clone());
                    document.push(
                        parent,
                        NodeKind::Comment(comment.xml10_content().into_owned()),
                        inherited_base,
                    );
                }
                Event::PI(pi) => {
                    let parent = elements.last().expect("document frame remains present").0;
                    let inherited_base =
                        document.node(parent).and_then(|node| node.base_uri.clone());
                    document.push(
                        parent,
                        NodeKind::ProcessingInstruction {
                            target: pi.target().to_owned(),
                            value: (!pi.content().is_empty()).then(|| pi.content().to_owned()),
                        },
                        inherited_base,
                    );
                }
                Event::GeneralRef(reference) => {
                    let reference = reference.as_ref();
                    let value = match reference {
                        "amp" => "&".into(),
                        "apos" => "'".into(),
                        "gt" => ">".into(),
                        "lt" => "<".into(),
                        "quot" => "\"".into(),
                        value if value.starts_with("#x") => u32::from_str_radix(&value[2..], 16)
                            .ok()
                            .and_then(char::from_u32)
                            .map(String::from)
                            .ok_or_else(|| Error::Xml("invalid character reference".into()))?,
                        value if value.starts_with('#') => value[1..]
                            .parse::<u32>()
                            .ok()
                            .and_then(char::from_u32)
                            .map(String::from)
                            .ok_or_else(|| Error::Xml("invalid character reference".into()))?,
                        name => {
                            return Err(Error::Xml(format!(
                                "unresolved entity reference &{name};"
                            )));
                        }
                    };
                    push_parsed_text(&mut document, &elements, value);
                }
                Event::Eof => break,
                Event::Decl(_) | Event::DocType(_) => {}
            }
        }
        if elements.len() != 1 {
            return Err(Error::Xml("unclosed element".into()));
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

    pub(crate) fn retain_nodes(&mut self, mut keep: impl FnMut(NodeId, &Node) -> bool) {
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
    }
}

fn push_stream_element(
    document: &mut Document,
    elements: &mut Vec<(NodeId, Vec<Namespace>)>,
    start: &quick_xml::events::BytesStart<'_>,
    empty: bool,
) -> Result<()> {
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
            set_namespace(&mut namespaces, None, value);
        } else if let Some(prefix) = name.strip_prefix("xmlns:") {
            set_namespace(&mut namespaces, Some(prefix.into()), value);
        } else {
            raw_attributes.push((name.to_owned(), value));
        }
    }
    let binding = start.name();
    let lexical_name = binding.as_ref();
    let (prefix, local) = split_lexical_name(lexical_name);
    let namespace = namespace_for(&namespaces, prefix.as_deref());
    let attributes = raw_attributes
        .into_iter()
        .map(|(lexical, value)| {
            let (prefix, local) = split_lexical_name(&lexical);
            let namespace = prefix
                .as_deref()
                .and_then(|prefix| namespace_for(&namespaces, Some(prefix)));
            Attribute {
                name: ExpandedName::new(namespace, local),
                prefix,
                value,
            }
        })
        .collect();
    let inherited_base = document.node(parent).and_then(|node| node.base_uri.clone());
    let projected = document.push(
        parent,
        NodeKind::Element {
            name: ExpandedName::new(namespace, local),
            prefix,
            attributes,
            namespaces: namespaces.clone(),
        },
        inherited_base,
    );
    if !empty {
        elements.push((projected, namespaces));
    }
    Ok(())
}

fn push_parsed_text(document: &mut Document, elements: &[(NodeId, Vec<Namespace>)], value: String) {
    let parent = elements.last().expect("document frame remains present").0;
    let inherited_base = document.node(parent).and_then(|node| node.base_uri.clone());
    document.push(
        parent,
        NodeKind::Text {
            value,
            disable_output_escaping: false,
        },
        inherited_base,
    );
}

fn split_lexical_name(name: &str) -> (Option<String>, String) {
    name.split_once(':').map_or_else(
        || (None, name.to_owned()),
        |(prefix, local)| (Some(prefix.to_owned()), local.to_owned()),
    )
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
    node: roxmltree::Node<'_, '_>,
    attribute: roxmltree::Attribute<'_, '_>,
) -> Option<String> {
    let namespace = attribute.namespace()?;
    if namespace == "http://www.w3.org/XML/1998/namespace" {
        return Some("xml".into());
    }
    node.namespaces()
        .find(|entry| entry.uri() == namespace && entry.name().is_some())
        .and_then(|entry| entry.name())
        .map(str::to_owned)
}
