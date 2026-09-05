use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use xml_sec_xml_input::lexical::{Event, Scanner};

use crate::budget::{
    ENTITY_EXPANSION_BYTE_CEILING, ENTITY_EXPANSION_DEPTH_CEILING, ENTITY_REFERENCE_CEILING, Meter,
    NAMESPACE_SCOPE_BYTE_CEILING, ensure, reserve_temporary_vec_slot,
};
use crate::{BudgetKind, Error, ParseBudget, Result};

const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
const XMLNS_NS: &str = "http://www.w3.org/2000/xmlns/";

pub(crate) fn parser_workspace_bytes(xml: &str) -> usize {
    let (node_slots, attribute_slots) =
        xml.bytes()
            .fold((0usize, 0usize), |(nodes, attributes), byte| {
                (
                    nodes.saturating_add(usize::from(byte == b'<')),
                    attributes.saturating_add(usize::from(byte == b'=')),
                )
            });
    let word = std::mem::size_of::<usize>();
    let node_bytes = 12usize.saturating_mul(word);
    let attribute_bytes = 10usize.saturating_mul(word);
    let namespace_bytes = 6usize.saturating_mul(word);
    let traversal_bytes = 3usize.saturating_mul(word);
    let fixed_workspace = 16usize
        .saturating_mul(attribute_bytes)
        .saturating_add(8usize.saturating_mul(word));

    // The lexical and semantic frontends derive their attacker-controlled capacities from tag and
    // attribute delimiters. Machine-word bounds conservatively cover their private arenas and
    // traversal stacks without coupling budget enforcement to allocator-specific capacities.
    xml.len()
        .saturating_add(fixed_workspace)
        .saturating_add(node_slots.saturating_mul(node_bytes.saturating_add(traversal_bytes)))
        .saturating_add(
            attribute_slots.saturating_mul(attribute_bytes.saturating_add(namespace_bytes)),
        )
}

/// Stable, document-bound index of a node inside one owned document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub usize, u64);

impl NodeId {
    pub(crate) const fn document_identity(self) -> u64 {
        self.1
    }

    #[cfg(test)]
    pub(crate) const fn test(index: usize) -> Self {
        Self(index, 1)
    }
}

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
        namespaces: Arc<Vec<Namespace>>,
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
        let nodes_equal = self.nodes.len() == other.nodes.len()
            && self.nodes.iter().zip(&other.nodes).all(|(left, right)| {
                left.kind == right.kind
                    && left.parent.map(|id| id.0) == right.parent.map(|id| id.0)
                    && left
                        .children
                        .iter()
                        .map(|id| id.0)
                        .eq(right.children.iter().map(|id| id.0))
                    && left.base_uri == right.base_uri
                    && left.source_line == right.source_line
            });
        let ids_equal = self.ids.len() == other.ids.len()
            && self.ids.iter().all(|((root, value), owner)| {
                other
                    .ids
                    .iter()
                    .any(|((other_root, other_value), other_owner)| {
                        root.0 == other_root.0 && value == other_value && owner.0 == other_owner.0
                    })
            });
        let entities_equal = self.unparsed_entities.len() == other.unparsed_entities.len()
            && self.unparsed_entities.iter().all(|((root, name), value)| {
                other
                    .unparsed_entities
                    .iter()
                    .any(|((other_root, other_name), other_value)| {
                        root.0 == other_root.0 && name == other_name && value == other_value
                    })
            });
        nodes_equal
            && self.root.0 == other.root.0
            && self
                .logical_roots
                .iter()
                .map(|id| id.0)
                .eq(other.logical_roots.iter().map(|id| id.0))
            && self.source_bytes == other.source_bytes
            && ids_equal
            && entities_equal
    }
}

impl Eq for Document {}

fn estimated_node_clone_bytes(node: &Node) -> usize {
    std::mem::size_of::<Node>()
        .saturating_add(
            node.children
                .len()
                .saturating_mul(std::mem::size_of::<NodeId>()),
        )
        .saturating_add(node.base_uri.as_deref().map_or(0, str::len))
        .saturating_add(match &node.kind {
            NodeKind::Root => 0,
            NodeKind::Text { value, .. } | NodeKind::Comment(value) => value.len(),
            NodeKind::ProcessingInstruction { target, value } => target
                .len()
                .saturating_add(value.as_deref().map_or(0, str::len)),
            NodeKind::Element {
                name,
                prefix,
                attributes,
                namespaces: _,
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
                })),
        })
}

impl Document {
    /// Parse trusted, caller-decoded XML without a caller-selected resource budget.
    ///
    /// Use [`Self::parse_with_budget`] for untrusted input.
    pub fn parse(xml: &str, base_uri: Option<&str>) -> Result<Self> {
        Self::parse_iterative(xml, base_uri)
    }

    /// Parse caller-decoded XML while bounding input bytes, nodes, and element depth.
    pub fn parse_with_budget(
        xml: &str,
        base_uri: Option<&str>,
        budget: ParseBudget,
    ) -> Result<Self> {
        ensure(BudgetKind::SourceBytes, budget.source_bytes, xml.len())?;
        Self::parse_iterative_bounded(xml, base_uri, budget)
    }

    /// Decode and parse trusted XML bytes without a caller-selected resource budget.
    ///
    /// Use [`Self::parse_bytes_with_budget`] for untrusted input.
    pub fn parse_bytes(bytes: &[u8], base_uri: Option<&str>) -> Result<Self> {
        let xml =
            xml_sec_xml_input::decode_xml(bytes, None).map_err(crate::error::decoded_xml_error)?;
        Self::parse_iterative(&xml, base_uri)
    }

    /// Decode and parse XML bytes while bounding decoded bytes, nodes, and element depth.
    pub fn parse_bytes_with_budget(
        bytes: &[u8],
        base_uri: Option<&str>,
        budget: ParseBudget,
    ) -> Result<Self> {
        let xml = xml_sec_xml_input::decode_xml_bounded(bytes, None, budget.source_bytes).map_err(
            |error| match error {
                xml_sec_xml_input::Error::DecodedLimit { actual, .. } => Error::Budget {
                    kind: BudgetKind::SourceBytes,
                    limit: budget.source_bytes,
                    actual,
                },
                error => Error::Xml(error.to_string()),
            },
        )?;
        Self::parse_iterative_bounded(&xml, base_uri, budget)
    }

    // Account for heap storage materialized by Clone before duplicating the source document.
    pub(crate) fn estimated_clone_bytes(&self) -> usize {
        let mut bytes = self
            .logical_roots
            .len()
            .saturating_mul(std::mem::size_of::<NodeId>());
        for node in &self.nodes {
            bytes = bytes.saturating_add(estimated_node_clone_bytes(node));
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

    pub(crate) fn estimated_subtree_projection(&self, root: NodeId) -> (usize, usize) {
        let mut node_count = 1usize;
        let mut bytes = std::mem::size_of::<Node>()
            .saturating_add(std::mem::size_of::<NodeId>())
            .saturating_add(
                self.node(self.root)
                    .and_then(|node| node.base_uri.as_deref())
                    .map_or(0, str::len),
            );
        let mut current = root;
        loop {
            let Some(node) = self.node(current) else {
                return (node_count, bytes);
            };
            node_count = node_count.saturating_add(1);
            bytes = bytes.saturating_add(estimated_node_clone_bytes(node));
            let Some(next) = self.next_descendant(root, current) else {
                break;
            };
            current = next;
        }
        let id_entry_bytes = std::mem::size_of::<((NodeId, String), NodeId)>()
            .saturating_add(std::mem::size_of::<u64>());
        for ((_, name), owner) in &self.ids {
            if self.node_is_in_subtree(root, *owner) {
                bytes = bytes
                    .saturating_add(id_entry_bytes)
                    .saturating_add(name.len());
            }
        }
        let entity_entry_bytes = std::mem::size_of::<((NodeId, String), String)>()
            .saturating_add(std::mem::size_of::<u64>());
        bytes = bytes.saturating_add(self.unparsed_entities.iter().fold(
            0usize,
            |total, ((_, name), value)| {
                total
                    .saturating_add(entity_entry_bytes)
                    .saturating_add(name.len())
                    .saturating_add(value.len())
            },
        ));
        (node_count, bytes)
    }

    fn node_is_in_subtree(&self, root: NodeId, mut candidate: NodeId) -> bool {
        loop {
            if candidate == root {
                return true;
            }
            let Some(parent) = self.node(candidate).and_then(|node| node.parent) else {
                return false;
            };
            candidate = parent;
        }
    }

    // Conservatively includes namespace arenas owned by a freshly parsed document. Shared
    // namespace scopes may be counted more than once, which is preferable to under-reserving an
    // attacker-controlled parse before it is projected into the execution DOM.
    pub(crate) fn estimated_owned_bytes(&self) -> usize {
        self.nodes
            .iter()
            .fold(self.estimated_clone_bytes(), |total, node| {
                let NodeKind::Element { namespaces, .. } = &node.kind else {
                    return total;
                };
                total
                    .saturating_add(
                        namespaces
                            .len()
                            .saturating_mul(std::mem::size_of::<Namespace>()),
                    )
                    .saturating_add(namespaces.iter().fold(0usize, |bytes, namespace| {
                        bytes
                            .saturating_add(namespace.prefix.as_deref().map_or(0, str::len))
                            .saturating_add(namespace.uri.len())
                    }))
            })
    }

    pub(crate) fn retained_namespace_arena_bytes(
        &self,
        selected_root: Option<NodeId>,
        meter: &mut Meter,
    ) -> Result<usize> {
        let root = selected_root.unwrap_or(self.root);
        let mut arenas = Vec::new();
        let mut reserved_bytes = 0usize;
        let result = (|| {
            let mut current = root;
            loop {
                let node = self
                    .node(current)
                    .ok_or_else(|| Error::Xml("namespace projection root is stale".into()))?;
                if let NodeKind::Element { namespaces, .. } = &node.kind {
                    reserve_temporary_vec_slot(&mut arenas, meter, &mut reserved_bytes)?;
                    arenas.push((Arc::as_ptr(namespaces) as usize, namespaces));
                }
                let Some(next) = self.next_descendant(root, current) else {
                    break;
                };
                current = next;
            }
            arenas.sort_unstable_by_key(|(identity, _)| *identity);
            arenas.dedup_by_key(|(identity, _)| *identity);
            Ok(arenas.iter().fold(0usize, |total, (_, namespaces)| {
                total
                    .saturating_add(
                        namespaces
                            .capacity()
                            .saturating_mul(std::mem::size_of::<Namespace>()),
                    )
                    .saturating_add(namespaces.iter().fold(0usize, |bytes, namespace| {
                        bytes
                            .saturating_add(namespace.prefix.as_deref().map_or(0, str::len))
                            .saturating_add(namespace.uri.len())
                    }))
            }))
        })();
        drop(arenas);
        meter.release_owned_bytes(reserved_bytes);
        result
    }

    #[cfg(test)]
    fn parse_tree(xml: &str, base_uri: Option<&str>) -> Result<Self> {
        let parsed =
            roxmltree::Document::parse(xml).map_err(|error| Error::Xml(error.to_string()))?;
        let mut document = Self::empty(base_uri.map(str::to_owned));
        document.source_bytes = xml.len();
        let line_starts = xml_line_starts(xml);
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
                let mut namespaces = Arc::new(Vec::new());
                let mut namespace_index = HashMap::new();
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
                        &mut namespace_index,
                        namespace.name().map(str::to_owned),
                        namespace.uri().to_owned(),
                    );
                }
                if !namespaces.iter().any(|namespace| {
                    namespace.prefix.as_deref() == Some("xml")
                        && namespace.uri == "http://www.w3.org/XML/1998/namespace"
                }) {
                    Arc::make_mut(&mut namespaces).insert(
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
        Self::parse_iterative_bounded(xml, base_uri, ParseBudget::UNBOUNDED)
    }

    fn parse_iterative_bounded(
        xml: &str,
        base_uri: Option<&str>,
        budget: ParseBudget,
    ) -> Result<Self> {
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum DocumentPhase {
            Start,
            Prolog,
            Content,
            Epilog,
        }

        ensure(BudgetKind::SourceBytes, budget.source_bytes, xml.len())?;
        ensure(BudgetKind::SourceNodes, budget.source_nodes, 1)?;
        let mut document = Self::empty(base_uri.map(str::to_owned));
        document.source_bytes = xml.len();
        let mut meter = StreamParseMeter {
            budget,
            nodes: 1,
            entity_references: 0,
            entity_expansion: EntityExpansionMeter::new(ENTITY_EXPANSION_BYTE_CEILING),
            namespace_scope_bytes: 0,
        };
        let (parameter_expanded_xml, declarations) = internal_general_entities(
            xml,
            &mut meter.entity_references,
            &mut meter.entity_expansion,
        )?;
        let expanded_xml = expand_document_entities(
            parameter_expanded_xml.as_ref(),
            &declarations.general,
            &mut meter.entity_references,
            &mut meter.entity_expansion,
        )?;
        let mut reader = Scanner::new(expanded_xml.as_ref());
        let mut previous_event_offset = 0usize;
        let mut source_line = 1usize;
        let mut phase = DocumentPhase::Start;
        // XML 1.0 section 2.8 makes matching the DOCTYPE and document-element names a validity
        // constraint; section 5.1 does not require this non-validating parser to enforce it.
        // https://www.w3.org/TR/xml/#sec-prolog-dtd
        let mut saw_doctype = false;
        let mut elements = vec![StreamElementFrame {
            node: document.root,
            lexical_name: None,
        }];
        while let Some(event) = reader
            .next_event()
            .map_err(|error| Error::Xml(error.to_string()))?
        {
            let event_offset = event_range_start(&event);
            source_line = source_line.saturating_add(xml_line_endings(
                &expanded_xml.as_bytes()[previous_event_offset..event_offset],
            ));
            previous_event_offset = event_offset;
            match event {
                Event::Start(start) => {
                    if elements.len() == 1 {
                        if phase == DocumentPhase::Epilog {
                            return Err(Error::Xml("multiple document elements".into()));
                        }
                        phase = DocumentPhase::Content;
                    }
                    let id = push_stream_element(
                        &mut document,
                        &mut elements,
                        &start,
                        false,
                        &declarations,
                        &mut meter,
                    )?;
                    document.nodes[id.0].source_line = Some(source_line);
                }
                Event::Empty(start) => {
                    if elements.len() == 1 {
                        if phase == DocumentPhase::Epilog {
                            return Err(Error::Xml("multiple document elements".into()));
                        }
                        phase = DocumentPhase::Epilog;
                    }
                    let id = push_stream_element(
                        &mut document,
                        &mut elements,
                        &start,
                        true,
                        &declarations,
                        &mut meter,
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
                        let id = push_parsed_text(&mut document, &elements, value, &mut meter)?;
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
                        &mut meter,
                    )?;
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
                    meter.reserve_node()?;
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
                    meter.reserve_node()?;
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
                    let id = push_parsed_text(&mut document, &elements, value, &mut meter)?;
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
                Event::DocType { .. } => {
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
        for (name, system_identifier) in declarations.unparsed {
            let uri = crate::resolver::resolve_uri_reference(base_uri, &system_identifier)?;
            document.register_unparsed_entity(name, uri)?;
        }
        document.register_xml_ids()?;
        Ok(document)
    }

    #[must_use]
    pub fn empty(base_uri: Option<String>) -> Self {
        static NEXT_DOCUMENT_IDENTITY: AtomicU64 = AtomicU64::new(1);
        let identity = NEXT_DOCUMENT_IDENTITY.fetch_add(1, Ordering::Relaxed);
        Self {
            identity,
            nodes: vec![Node {
                kind: NodeKind::Root,
                parent: None,
                children: Vec::new(),
                base_uri,
                source_line: None,
            }],
            root: NodeId(0, identity),
            logical_roots: vec![NodeId(0, identity)],
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
        if id.document_identity() != self.identity {
            return None;
        }
        self.nodes.get(id.0)
    }

    pub(crate) fn node_mut(&mut self, id: NodeId) -> Option<&mut Node> {
        if id.document_identity() != self.identity {
            return None;
        }
        self.nodes.get_mut(id.0)
    }

    pub(crate) const fn source_bytes(&self) -> usize {
        self.source_bytes
    }

    pub(crate) fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub(crate) fn retained_tree_container_bytes(&self) -> usize {
        self.nodes
            .capacity()
            .saturating_mul(std::mem::size_of::<Node>())
            .saturating_add(
                self.logical_roots
                    .capacity()
                    .saturating_mul(std::mem::size_of::<NodeId>()),
            )
            .saturating_add(self.nodes.iter().fold(0usize, |total, node| {
                total.saturating_add(
                    node.children
                        .capacity()
                        .saturating_mul(std::mem::size_of::<NodeId>()),
                )
            }))
    }

    pub(crate) fn retained_identity_index_bytes(&self) -> usize {
        self.ids
            .capacity()
            .saturating_mul(
                std::mem::size_of::<((NodeId, String), NodeId)>()
                    .saturating_add(std::mem::size_of::<u64>()),
            )
            .saturating_add(self.ids.keys().fold(0usize, |total, (_, value)| {
                total.saturating_add(value.capacity())
            }))
    }

    pub(crate) fn reserve_metered_push_containers(
        &mut self,
        parent: NodeId,
        meter: &mut Meter,
    ) -> Result<()> {
        let mut nodes_reservation = self
            .nodes
            .capacity()
            .saturating_mul(std::mem::size_of::<Node>());
        reserve_temporary_vec_slot(&mut self.nodes, meter, &mut nodes_reservation)?;
        if let Some(parent) = self.nodes.get_mut(parent.0) {
            let mut children_reservation = parent
                .children
                .capacity()
                .saturating_mul(std::mem::size_of::<NodeId>());
            reserve_temporary_vec_slot(&mut parent.children, meter, &mut children_reservation)?;
        }
        Ok(())
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
        let remap = |id: NodeId| NodeId(offset + id.0, self.identity);
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

    fn register_dtd_id_value(&mut self, owner: NodeId, value: String) -> Result<()> {
        let logical_root = self
            .logical_root_for(&NodeReference::Node(owner))
            .ok_or_else(|| Error::Xml("DTD ID attribute is outside a logical document".into()))?;
        // XML 1.0 sections 3.3.1 and 5.1 make lexical validity and uniqueness of DTD IDs
        // validity constraints. This non-validating parser retains the first owner in its
        // deterministic id() index instead of turning either violation into a parse error.
        // https://www.w3.org/TR/xml/#id
        // https://www.w3.org/TR/xml/#proc-types
        self.ids.entry((logical_root, value)).or_insert(owner);
        Ok(())
    }

    fn register_id_for_root(
        &mut self,
        logical_root: NodeId,
        owner: NodeId,
        value: String,
    ) -> Result<()> {
        match self.ids.entry((logical_root, value)) {
            std::collections::hash_map::Entry::Occupied(entry) if *entry.get() == owner => Ok(()),
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
        if name.is_empty() {
            return Err(Error::Xml("unparsed entity name must not be empty".into()));
        }
        // XML 1.0 production [11] uses `*`, so an empty SystemLiteral is valid metadata.
        // https://www.w3.org/TR/xml/#NT-SystemLiteral
        let key = (self.root, name.clone());
        match self.unparsed_entities.entry(key) {
            std::collections::hash_map::Entry::Occupied(_) => {
                Err(Error::Xml(format!("duplicate unparsed entity `{name}`")))
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(uri);
                Ok(())
            }
        }
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
            let normalized = normalized_xml_id(&value.value)?.into_owned();
            if value.value != normalized {
                value.value.clone_from(&normalized);
            }
            self.register_id_value(owner, normalized)?;
        }
        Ok(())
    }

    pub(crate) fn finalize_xml_ids(&mut self, meter: &mut Meter) -> Result<()> {
        let (count, value_bytes) = self.nodes().fold((0usize, 0usize), |totals, (_, node)| {
            let NodeKind::Element { attributes, .. } = &node.kind else {
                return totals;
            };
            let Some(attribute) = attributes.iter().find(|attribute| {
                attribute.name.namespace.as_deref() == Some(XML_NS) && attribute.name.local == "id"
            }) else {
                return totals;
            };
            (
                totals.0.saturating_add(1),
                totals.1.saturating_add(attribute.value.len()),
            )
        });
        if count == 0 {
            return Ok(());
        }
        let map_upper_bound = count.saturating_mul(4).saturating_mul(
            std::mem::size_of::<((NodeId, String), NodeId)>()
                .saturating_add(std::mem::size_of::<u64>()),
        );
        let uniqueness_count = self.ids.len().saturating_add(count);
        let uniqueness_upper_bound = uniqueness_count
            .saturating_mul(4)
            .saturating_mul(std::mem::size_of::<(NodeId, &str)>());
        let workspace_upper_bound = count
            .saturating_mul(std::mem::size_of::<(NodeId, usize, NodeId, String)>())
            .saturating_add(uniqueness_upper_bound)
            .saturating_add(value_bytes)
            .saturating_add(map_upper_bound);
        let peak_upper_bound = workspace_upper_bound.saturating_add(value_bytes);
        meter.charge(BudgetKind::OwnedBytes, peak_upper_bound)?;

        let prepared = (|| {
            let mut prepared = Vec::new();
            prepared.try_reserve_exact(count).map_err(|error| {
                Error::Dynamic(format!(
                    "failed to reserve xml:id finalization storage: {error}"
                ))
            })?;
            for (owner, node) in self.nodes() {
                let NodeKind::Element { attributes, .. } = &node.kind else {
                    continue;
                };
                let Some((index, attribute)) =
                    attributes.iter().enumerate().find(|(_, attribute)| {
                        attribute.name.namespace.as_deref() == Some(XML_NS)
                            && attribute.name.local == "id"
                    })
                else {
                    continue;
                };
                let normalized = normalized_xml_id(&attribute.value)?.into_owned();
                let logical_root = self
                    .logical_root_for(&NodeReference::Node(owner))
                    .ok_or_else(|| Error::Xml("xml:id is outside a logical document".into()))?;
                prepared.push((owner, index, logical_root, normalized));
            }
            let mut unique = HashSet::new();
            unique.try_reserve(uniqueness_count).map_err(|error| {
                Error::Dynamic(format!(
                    "failed to reserve xml:id uniqueness storage: {error}"
                ))
            })?;
            unique.extend(self.ids.keys().map(|(root, value)| (*root, value.as_str())));
            for (_, _, root, value) in &prepared {
                if !unique.insert((*root, value.as_str())) {
                    return Err(Error::Xml(format!("duplicate XML ID `{value}`")));
                }
            }
            Ok(prepared)
        })();
        let mut prepared = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                meter.release_owned_bytes(peak_upper_bound);
                return Err(error);
            }
        };
        let retained_before = self.retained_identity_index_bytes();
        if let Err(error) = self.ids.try_reserve(count) {
            meter.release_owned_bytes(peak_upper_bound);
            return Err(Error::Dynamic(format!(
                "failed to reserve xml:id index storage: {error}"
            )));
        }
        for (owner, index, logical_root, value) in prepared.drain(..) {
            let attribute = self
                .node_mut(owner)
                .and_then(|node| match &mut node.kind {
                    NodeKind::Element { attributes, .. } => attributes.get_mut(index),
                    _ => None,
                })
                .expect("prepared xml:id attribute remains present");
            if attribute.value != value {
                attribute.value.clone_from(&value);
            }
            self.ids.insert((logical_root, value), owner);
        }
        let retained = self
            .retained_identity_index_bytes()
            .saturating_sub(retained_before);
        debug_assert!(retained <= peak_upper_bound);
        meter.release_owned_bytes(peak_upper_bound.saturating_sub(retained));
        Ok(())
    }

    #[must_use]
    pub fn nodes(&self) -> impl ExactSizeIterator<Item = (NodeId, &Node)> {
        self.nodes
            .iter()
            .enumerate()
            .map(|(index, node)| (NodeId(index, self.identity), node))
    }

    pub(crate) fn push(
        &mut self,
        parent: NodeId,
        kind: NodeKind,
        base_uri: Option<String>,
    ) -> NodeId {
        let id = NodeId(self.nodes.len(), self.identity);
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

    pub(crate) fn push_coalesced(
        &mut self,
        parent: NodeId,
        kind: NodeKind,
        base_uri: Option<String>,
    ) -> Option<NodeId> {
        let NodeKind::Text {
            value,
            disable_output_escaping,
        } = kind
        else {
            return Some(self.push(parent, kind, base_uri));
        };
        if value.is_empty() {
            return None;
        }
        if let Some(last_child) = self.coalescible_text_child(parent, disable_output_escaping) {
            let NodeKind::Text {
                value: existing, ..
            } = &mut self.nodes[last_child.0].kind
            else {
                unreachable!("coalescible_text_child returns only text nodes");
            };
            existing.push_str(&value);
            return Some(last_child);
        }
        Some(self.push(
            parent,
            NodeKind::Text {
                value,
                disable_output_escaping,
            },
            base_uri,
        ))
    }

    pub(crate) fn append_node_from(&mut self, parent: NodeId, source: &Node) -> Option<NodeId> {
        if let NodeKind::Text {
            value,
            disable_output_escaping,
        } = &source.kind
        {
            if value.is_empty() {
                return None;
            }
            if let Some(last_child) = self.coalescible_text_child(parent, *disable_output_escaping)
            {
                let NodeKind::Text {
                    value: existing, ..
                } = &mut self.nodes[last_child.0].kind
                else {
                    unreachable!("coalescible_text_child returns only text nodes");
                };
                existing.push_str(value);
                return Some(last_child);
            }
        }
        let target = self.push(parent, source.kind.clone(), source.base_uri.clone());
        self.nodes[target.0].source_line = source.source_line;
        Some(target)
    }

    fn coalescible_text_child(
        &self,
        parent: NodeId,
        disable_output_escaping: bool,
    ) -> Option<NodeId> {
        let child = self.node(parent)?.children.last().copied()?;
        matches!(
            self.node(child)?.kind,
            NodeKind::Text {
                disable_output_escaping: current,
                ..
            } if current == disable_output_escaping
        )
        .then_some(child)
    }

    pub(crate) fn append_subtree_from(
        &mut self,
        parent: NodeId,
        source: &Self,
        source_id: NodeId,
        mapping: &mut HashMap<NodeId, NodeId>,
        meter: &mut Meter,
    ) -> Result<NodeId> {
        let source_node = source.node(source_id).expect("source subtree node exists");
        let root = self
            .append_node_from(parent, source_node)
            .expect("source documents contain no empty text nodes");
        mapping.insert(source_id, root);
        let mut pending = Vec::new();
        let mut pending_owned_bytes = 0usize;
        let copied = (|| {
            for child in source_node.children.iter().rev() {
                reserve_temporary_vec_slot(&mut pending, meter, &mut pending_owned_bytes)?;
                pending.push((*child, root));
            }
            while let Some((source_id, target_parent)) = pending.pop() {
                let source_node = source.node(source_id).expect("source subtree node exists");
                let target = self
                    .append_node_from(target_parent, source_node)
                    .expect("source documents contain no empty text nodes");
                mapping.insert(source_id, target);
                for child in source_node.children.iter().rev() {
                    reserve_temporary_vec_slot(&mut pending, meter, &mut pending_owned_bytes)?;
                    pending.push((*child, target));
                }
            }
            Ok(root)
        })();
        meter.release_owned_bytes(pending_owned_bytes);
        copied
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

    pub(crate) fn merge_unparsed_entities_from(
        &mut self,
        source: &Self,
        logical_root: NodeId,
    ) -> Result<()> {
        for (name, uri, _) in source.unparsed_entities() {
            let key = (logical_root, name.to_owned());
            match self.unparsed_entities.entry(key) {
                std::collections::hash_map::Entry::Occupied(entry) if entry.get() == uri => {}
                std::collections::hash_map::Entry::Occupied(_) => {
                    // XInclude 1.0 section 4.5.1 rejects same-name entities that are not
                    // duplicates: https://www.w3.org/TR/xinclude/#unparsed-entities
                    return Err(Error::Xml(format!(
                        "conflicting unparsed entity `{name}` during XInclude processing"
                    )));
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(uri.to_owned());
                }
            }
        }
        Ok(())
    }

    pub(crate) fn string_value(&self, id: NodeId) -> String {
        self.string_value_with_capacity(id, 0)
    }

    pub(crate) fn string_value_with_capacity(&self, id: NodeId, capacity: usize) -> String {
        let mut output = String::with_capacity(capacity);
        self.visit_string_value(id, |value| output.push_str(value));
        output
    }

    pub(crate) fn string_value_len(&self, id: NodeId) -> usize {
        let mut length = 0usize;
        self.visit_string_value(id, |value| {
            debug_assert!(length.checked_add(value.len()).is_some());
            length += value.len();
        });
        length
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
                let Some(mut current_id) = node.children.first().copied() else {
                    return;
                };
                loop {
                    let Some(current) = self.node(current_id) else {
                        return;
                    };
                    if let NodeKind::Text { value, .. } = &current.kind {
                        visit(value);
                    }
                    let Some(next) = self.next_descendant(id, current_id) else {
                        return;
                    };
                    current_id = next;
                }
            }
        }
    }

    pub(crate) fn descendants(&self, root: NodeId) -> impl Iterator<Item = (NodeId, &Node)> {
        let first = self
            .node(root)
            .and_then(|node| node.children.first().copied());
        std::iter::successors(first, move |current| self.next_descendant(root, *current))
            .filter_map(|id| self.node(id).map(|node| (id, node)))
    }

    fn next_descendant(&self, boundary: NodeId, mut current: NodeId) -> Option<NodeId> {
        if let Some(child) = self.node(current)?.children.first() {
            return Some(*child);
        }
        while current != boundary {
            let parent = self.node(current)?.parent?;
            let siblings = &self.node(parent)?.children;
            // Arena nodes are created monotonically and children are only appended, so their
            // stable IDs preserve sibling order and permit an allocation-free binary lookup.
            let index = siblings.binary_search(&current).ok()?;
            if let Some(sibling) = siblings.get(index + 1) {
                return Some(*sibling);
            }
            current = parent;
        }
        None
    }

    pub(crate) fn retain_nodes(
        &mut self,
        meter: &mut Meter,
        mut keep: impl FnMut(&Document, NodeId, &Node) -> bool,
    ) -> Result<(HashMap<NodeId, NodeId>, usize)> {
        let mut temporary_bytes = 0usize;
        let mut remap_by_index = Vec::new();
        for _ in 0..self.nodes.len() {
            if let Err(error) =
                reserve_temporary_vec_slot(&mut remap_by_index, meter, &mut temporary_bytes)
            {
                meter.release_owned_bytes(temporary_bytes);
                return Err(error);
            }
            remap_by_index.push(None);
        }
        let mut pending = Vec::new();
        if let Err(error) = reserve_temporary_vec_slot(&mut pending, meter, &mut temporary_bytes) {
            meter.release_owned_bytes(temporary_bytes);
            return Err(error);
        }
        pending.push(self.root);
        let mut retained_count = 0usize;
        while let Some(id) = pending.pop() {
            remap_by_index[id.0] = Some(NodeId(retained_count, self.identity));
            retained_count += 1;
            for child in self.nodes[id.0].children.iter().rev() {
                if keep(self, *child, &self.nodes[child.0]) {
                    if let Err(error) =
                        reserve_temporary_vec_slot(&mut pending, meter, &mut temporary_bytes)
                    {
                        meter.release_owned_bytes(temporary_bytes);
                        return Err(error);
                    }
                    pending.push(*child);
                }
            }
        }

        let map_entry_bytes =
            std::mem::size_of::<(NodeId, NodeId)>().saturating_add(std::mem::size_of::<usize>());
        let requested_map_bytes = retained_count.saturating_mul(map_entry_bytes);
        if let Err(error) = meter.charge(BudgetKind::OwnedBytes, requested_map_bytes) {
            meter.release_owned_bytes(temporary_bytes);
            return Err(error);
        }
        let mut remap = HashMap::new();
        if let Err(error) = remap.try_reserve(retained_count) {
            meter.release_owned_bytes(requested_map_bytes);
            meter.release_owned_bytes(temporary_bytes);
            return Err(Error::Dynamic(format!(
                "failed to reserve whitespace node remap: {error}"
            )));
        }
        let retained_map_bytes = remap.capacity().saturating_mul(map_entry_bytes);
        if retained_map_bytes < requested_map_bytes {
            meter.release_owned_bytes(requested_map_bytes - retained_map_bytes);
        } else if retained_map_bytes > requested_map_bytes
            && let Err(error) = meter.charge(
                BudgetKind::OwnedBytes,
                retained_map_bytes - requested_map_bytes,
            )
        {
            meter.release_owned_bytes(requested_map_bytes);
            meter.release_owned_bytes(temporary_bytes);
            return Err(error);
        }
        for (old, new) in remap_by_index.iter().copied().enumerate() {
            if let Some(new) = new {
                remap.insert(NodeId(old, self.identity), new);
            }
        }

        let rebuilt_map_bytes = self
            .ids
            .capacity()
            .saturating_mul(
                std::mem::size_of::<((NodeId, String), NodeId)>()
                    .saturating_add(std::mem::size_of::<u64>()),
            )
            .saturating_add(
                self.unparsed_entities.capacity().saturating_mul(
                    std::mem::size_of::<((NodeId, String), String)>()
                        .saturating_add(std::mem::size_of::<u64>()),
                ),
            );
        if let Err(error) = meter.charge(BudgetKind::OwnedBytes, rebuilt_map_bytes) {
            meter.release_owned_bytes(retained_map_bytes);
            meter.release_owned_bytes(temporary_bytes);
            return Err(error);
        }
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
        let mut old_index = 0usize;
        self.nodes.retain_mut(|node| {
            let retained = remap_by_index[old_index].is_some();
            old_index += 1;
            if !retained {
                return false;
            }
            node.parent = node.parent.and_then(|parent| remap_by_index[parent.0]);
            let mut write = 0usize;
            for read in 0..node.children.len() {
                if let Some(child) = remap_by_index[node.children[read].0] {
                    node.children[write] = child;
                    write += 1;
                }
            }
            node.children.truncate(write);
            true
        });
        self.root = NodeId(0, self.identity);
        self.logical_roots.clear();
        self.logical_roots.push(self.root);
        self.source_bytes = 0;
        meter.release_owned_bytes(rebuilt_map_bytes);
        meter.release_owned_bytes(temporary_bytes);
        Ok((remap, retained_map_bytes))
    }
}

fn normalized_xml_id(value: &str) -> Result<Cow<'_, str>> {
    let normalized = collapse_xml_whitespace(value);
    // xml:id 1.0 section 4 requires validation after whitespace normalization.
    // https://www.w3.org/TR/xml-id/#processing
    if !crate::lexical::is_ncname(&normalized) {
        return Err(Error::Xml(format!(
            "xml:id value `{normalized}` is not a valid NCName"
        )));
    }
    Ok(normalized)
}

pub(crate) fn prepare_xml_frontend_bounded(xml: &str, limit: usize) -> Result<Cow<'_, str>> {
    let mut entity_references = 0;
    let mut entity_expansion = EntityExpansionMeter::new(limit.min(ENTITY_EXPANSION_BYTE_CEILING));
    let (parameter_expanded_xml, declarations) =
        internal_general_entities(xml, &mut entity_references, &mut entity_expansion)?;
    let expanded_xml = expand_document_entities(
        parameter_expanded_xml.as_ref(),
        &declarations.general,
        &mut entity_references,
        &mut entity_expansion,
    )?;
    let Some(doctype) = doctype_span(expanded_xml.as_ref())? else {
        return Ok(match expanded_xml {
            Cow::Borrowed(_) => parameter_expanded_xml,
            Cow::Owned(expanded) => Cow::Owned(expanded),
        });
    };

    let mut edits = Vec::<(std::ops::Range<usize>, String)>::new();
    let mut scanner = Scanner::new(expanded_xml.as_ref());
    while let Some(event) = scanner
        .next_event()
        .map_err(|error| Error::Xml(error.to_string()))?
    {
        let start = match event {
            Event::Start(start) | Event::Empty(start) => start,
            _ => continue,
        };
        let defaults = declarations
            .attributes
            .get(start.name.qualified().as_ref())
            .map_or(&[][..], Vec::as_slice);
        for attribute in &start.attributes {
            if !contains_expandable_entity_reference(attribute.value, &declarations.general) {
                continue;
            }
            let name = attribute.name.qualified();
            let is_cdata = defaults
                .iter()
                .find(|declaration| declaration.name == name)
                .is_none_or(|declaration| declaration.attribute_type.is_cdata());
            let value = prepare_attribute_value(
                name.as_ref(),
                attribute.value,
                &declarations.general,
                is_cdata,
                &mut entity_references,
                &mut entity_expansion,
            )?;
            let replacement_len = escaped_xml_attribute_value_len(&value)
                .and_then(|length| length.checked_add(name.len()))
                .and_then(|length| length.checked_add(3))
                .ok_or_else(|| Error::Xml("expanded attribute output is too large".into()))?;
            entity_expansion.charge(replacement_len)?;
            let mut replacement = String::with_capacity(replacement_len);
            replacement.push_str(name.as_ref());
            replacement.push_str("=\"");
            push_escaped_xml_attribute_value(&mut replacement, &value);
            replacement.push('"');
            edits.push((attribute.range.clone(), replacement));
        }
        // XML 1.0 section 3.3.2 requires a non-validating processor to report defaulted
        // attributes when it reads their declarations from the internal subset.
        // https://www.w3.org/TR/xml/#sec-attr-defaults
        let mut insertion = String::new();
        for declaration in defaults {
            let Some(default) = declaration.default.as_deref() else {
                continue;
            };
            if start
                .attributes
                .iter()
                .any(|attribute| attribute.name.is_qualified(&declaration.name))
            {
                continue;
            }
            let value = prepare_attribute_value(
                &declaration.name,
                default,
                &declarations.general,
                declaration.attribute_type.is_cdata(),
                &mut entity_references,
                &mut entity_expansion,
            )?;
            let insertion_len = escaped_xml_attribute_value_len(&value)
                .and_then(|length| length.checked_add(declaration.name.len()))
                .and_then(|length| length.checked_add(4))
                .ok_or_else(|| Error::Xml("DTD default attribute output is too large".into()))?;
            // The insertion strings coexist with the final prepared document. Charge them before
            // reserving so defaults cannot hide temporary allocation outside the XML budget.
            entity_expansion.charge(insertion_len)?;
            insertion.reserve(insertion_len);
            insertion.push(' ');
            insertion.push_str(&declaration.name);
            insertion.push_str("=\"");
            push_escaped_xml_attribute_value(&mut insertion, &value);
            insertion.push('"');
        }
        if !insertion.is_empty() {
            let before_close = if expanded_xml.as_bytes().get(start.range.end - 2) == Some(&b'/') {
                start.range.end - 2
            } else {
                start.range.end - 1
            };
            edits.push((before_close..before_close, insertion));
        }
    }

    edits.sort_by_key(|(range, _)| range.start);
    let removed = edits.iter().fold(0usize, |bytes, (range, _)| {
        bytes.saturating_add(range.end.saturating_sub(range.start))
    });
    let added = edits.iter().fold(0usize, |bytes, (_, value)| {
        bytes.saturating_add(value.len())
    });
    let capacity = expanded_xml
        .len()
        .saturating_sub(doctype.end.saturating_sub(doctype.start))
        .saturating_sub(removed)
        .saturating_add(added);
    entity_expansion.charge(capacity)?;
    let mut prepared = String::with_capacity(capacity);
    prepared.push_str(&expanded_xml[..doctype.start]);
    let mut cursor = doctype.end;
    for (range, replacement) in edits {
        prepared.push_str(&expanded_xml[cursor..range.start]);
        prepared.push_str(&replacement);
        cursor = range.end;
    }
    prepared.push_str(&expanded_xml[cursor..]);
    Ok(Cow::Owned(prepared))
}

fn escaped_xml_attribute_value_len(value: &str) -> Option<usize> {
    value.chars().try_fold(0usize, |length, character| {
        length.checked_add(match character {
            '&' => "&amp;".len(),
            '<' => "&lt;".len(),
            '"' => "&quot;".len(),
            _ => character.len_utf8(),
        })
    })
}

fn push_escaped_xml_attribute_value(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '"' => output.push_str("&quot;"),
            _ => output.push(character),
        }
    }
}

fn decode_xml_character_reference(digits: &str, radix: u32) -> Result<String> {
    u32::from_str_radix(digits, radix)
        .ok()
        .and_then(char::from_u32)
        .filter(|character| crate::lexical::is_xml10_character(*character))
        .map(String::from)
        .ok_or_else(|| Error::Xml("invalid character reference".into()))
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

struct StreamParseMeter {
    budget: ParseBudget,
    nodes: usize,
    entity_references: usize,
    entity_expansion: EntityExpansionMeter,
    namespace_scope_bytes: usize,
}

impl StreamParseMeter {
    fn reserve_node(&mut self) -> Result<()> {
        let actual = self.nodes.saturating_add(1);
        ensure(BudgetKind::SourceNodes, self.budget.source_nodes, actual)?;
        self.nodes = actual;
        Ok(())
    }

    fn element_depth(&self, depth: usize) -> Result<()> {
        ensure(
            BudgetKind::RecursionDepth,
            self.budget.recursion_depth,
            depth,
        )
    }
}

fn push_stream_element(
    document: &mut Document,
    elements: &mut Vec<StreamElementFrame>,
    start: &xml_sec_xml_input::lexical::StartTag<'_>,
    empty: bool,
    declarations: &InternalEntityDeclarations,
    meter: &mut StreamParseMeter,
) -> Result<NodeId> {
    meter.element_depth(elements.len())?;
    meter.reserve_node()?;
    let parent = elements
        .last()
        .map(|frame| frame.node)
        .expect("document frame remains present");
    let mut namespaces = match document.node(parent).map(|node| &node.kind) {
        Some(NodeKind::Element { namespaces, .. }) => Arc::clone(namespaces),
        _ => Arc::new(vec![Namespace {
            prefix: Some("xml".into()),
            uri: "http://www.w3.org/XML/1998/namespace".into(),
        }]),
    };
    let mut namespace_index_bytes = namespace_index_owned_bytes(&namespaces);
    ensure(
        BudgetKind::OwnedBytes,
        NAMESPACE_SCOPE_BYTE_CEILING,
        meter
            .namespace_scope_bytes
            .saturating_add(namespace_index_bytes),
    )?;
    let mut namespace_index = namespace_index(&namespaces);
    let lexical_name = start.name.qualified();
    let declared_attributes = declarations
        .attributes
        .get(lexical_name.as_ref())
        .map_or(&[][..], Vec::as_slice);
    let mut raw_attributes = Vec::new();
    for attribute in &start.attributes {
        let name = attribute.name.qualified();
        let attribute_type = declared_attributes
            .iter()
            .find(|declaration| declaration.name == name)
            .map_or(InternalAttributeType::Cdata, |declaration| {
                declaration.attribute_type
            });
        let value = prepare_attribute_value(
            name.as_ref(),
            attribute.value,
            &declarations.general,
            attribute_type.is_cdata(),
            &mut meter.entity_references,
            &mut meter.entity_expansion,
        )?;
        if name == "xmlns" {
            validate_namespace_binding(None, &value)?;
            set_namespace_bounded(
                &mut namespaces,
                &mut namespace_index,
                None,
                value,
                &mut namespace_index_bytes,
                &mut meter.namespace_scope_bytes,
            )?;
        } else if let Some(prefix) = name.strip_prefix("xmlns:") {
            if !crate::lexical::is_ncname(prefix) {
                return Err(Error::Xml(format!("invalid namespace prefix {prefix}")));
            }
            validate_namespace_binding(Some(prefix), &value)?;
            set_namespace_bounded(
                &mut namespaces,
                &mut namespace_index,
                Some(prefix.into()),
                value,
                &mut namespace_index_bytes,
                &mut meter.namespace_scope_bytes,
            )?;
        } else {
            raw_attributes.push((name.into_owned(), value, attribute_type));
        }
    }
    for declaration in declared_attributes {
        let Some(default) = declaration.default.as_deref() else {
            continue;
        };
        if start
            .attributes
            .iter()
            .any(|attribute| attribute.name.is_qualified(&declaration.name))
        {
            continue;
        }
        let value = prepare_attribute_value(
            &declaration.name,
            default,
            &declarations.general,
            declaration.attribute_type.is_cdata(),
            &mut meter.entity_references,
            &mut meter.entity_expansion,
        )?;
        if declaration.name == "xmlns" {
            validate_namespace_binding(None, &value)?;
            set_namespace_bounded(
                &mut namespaces,
                &mut namespace_index,
                None,
                value,
                &mut namespace_index_bytes,
                &mut meter.namespace_scope_bytes,
            )?;
        } else if let Some(prefix) = declaration.name.strip_prefix("xmlns:") {
            validate_namespace_binding(Some(prefix), &value)?;
            set_namespace_bounded(
                &mut namespaces,
                &mut namespace_index,
                Some(prefix.into()),
                value,
                &mut namespace_index_bytes,
                &mut meter.namespace_scope_bytes,
            )?;
        } else {
            raw_attributes.push((declaration.name.clone(), value, declaration.attribute_type));
        }
    }
    let prefix = start.name.prefix().map(str::to_owned);
    let local = start.name.local().to_owned();
    let namespace = namespace_for(&namespaces, &namespace_index, prefix.as_deref());
    if prefix.is_some() && namespace.is_none() {
        return Err(Error::Xml(format!(
            "undeclared namespace prefix in element {lexical_name}"
        )));
    }
    let mut first_id_attribute = None;
    let mut additional_id_attributes = Vec::new();
    let attributes = raw_attributes
        .into_iter()
        .enumerate()
        .map(|(index, (lexical, value, attribute_type))| {
            let (prefix, local) = split_lexical_name(&lexical)?;
            let namespace = prefix
                .as_deref()
                .and_then(|prefix| namespace_for(&namespaces, &namespace_index, Some(prefix)));
            if prefix.is_some() && namespace.is_none() {
                return Err(Error::Xml(format!(
                    "undeclared namespace prefix in attribute {lexical}"
                )));
            }
            if attribute_type.is_id() {
                if first_id_attribute.is_none() {
                    first_id_attribute = Some(index);
                } else {
                    additional_id_attributes.push(index);
                }
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
    for index in first_id_attribute
        .into_iter()
        .chain(additional_id_attributes)
    {
        let value = document
            .node(projected)
            .and_then(|node| match &node.kind {
                NodeKind::Element { attributes, .. } => attributes.get(index),
                _ => None,
            })
            .map(|attribute| collapse_xml_whitespace(&attribute.value).into_owned())
            .ok_or_else(|| Error::Xml("DTD ID attribute reference is stale".into()))?;
        document.register_dtd_id_value(projected, value)?;
    }
    if !empty {
        elements.push(StreamElementFrame {
            node: projected,
            lexical_name: Some(lexical_name.into_owned()),
        });
    }
    Ok(projected)
}

fn prepare_attribute_value(
    name: &str,
    raw: &str,
    entities: &HashMap<String, String>,
    is_cdata: bool,
    entity_references: &mut usize,
    entity_expansion: &mut EntityExpansionMeter,
) -> Result<String> {
    let value = expand_entity_references(raw, entities, 0, entity_references, entity_expansion)?;
    if value.contains('<') {
        return Err(Error::Xml(format!(
            "attribute `{name}` entity replacement contains a literal `<`"
        )));
    }
    let value = normalize_xml_attribute_value(value);
    let value = xml_sec_xml_input::lexical::decode_references(&value)
        .map_err(|error| Error::Xml(error.to_string()))?;
    Ok(if is_cdata {
        value.into_owned()
    } else {
        collapse_xml_whitespace(&value).into_owned()
    })
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

fn xml_line_endings(bytes: &[u8]) -> usize {
    // XML 1.0 section 2.11 treats CR, CRLF, and LF as one logical line ending.
    // https://www.w3.org/TR/xml/#sec-line-ends
    let mut lines = 0usize;
    let mut previous_cr = false;
    for byte in bytes {
        if *byte == b'\r' {
            lines += 1;
            previous_cr = true;
        } else {
            if *byte == b'\n' && !previous_cr {
                lines += 1;
            }
            previous_cr = false;
        }
    }
    lines
}

#[cfg(test)]
fn xml_line_starts(xml: &str) -> Vec<usize> {
    let bytes = xml.as_bytes();
    let mut starts = Vec::with_capacity(xml_line_endings(bytes).saturating_add(1));
    starts.push(0);
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        if bytes[cursor] == b'\r' {
            cursor += 1;
            if bytes.get(cursor) == Some(&b'\n') {
                cursor += 1;
            }
            starts.push(cursor);
        } else if bytes[cursor] == b'\n' {
            cursor += 1;
            starts.push(cursor);
        } else {
            cursor += 1;
        }
    }
    starts
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
    meter: &mut StreamParseMeter,
) -> Result<NodeId> {
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
        return Ok(last_child);
    }
    meter.reserve_node()?;
    let inherited_base = document.node(parent).and_then(|node| node.base_uri.clone());
    Ok(document.push(
        parent,
        NodeKind::Text {
            value,
            disable_output_escaping: false,
        },
        inherited_base,
    ))
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

fn namespace_for(
    namespaces: &[Namespace],
    index: &HashMap<String, usize>,
    prefix: Option<&str>,
) -> Option<String> {
    index
        .get(prefix.unwrap_or_default())
        .and_then(|index| namespaces.get(*index))
        .map(|namespace| namespace.uri.clone())
        .filter(|namespace| !namespace.is_empty())
}

fn namespace_index(namespaces: &[Namespace]) -> HashMap<String, usize> {
    let mut index = HashMap::with_capacity(namespaces.len());
    for (position, namespace) in namespaces.iter().enumerate() {
        index.insert(namespace.prefix.clone().unwrap_or_default(), position);
    }
    index
}

fn namespace_index_owned_bytes(namespaces: &[Namespace]) -> usize {
    namespaces
        .len()
        .saturating_mul(std::mem::size_of::<(String, usize)>())
        .saturating_mul(2)
        .saturating_add(namespaces.iter().fold(0usize, |total, namespace| {
            total.saturating_add(namespace.prefix.as_deref().map_or(0, str::len))
        }))
}

fn set_namespace(
    namespaces: &mut Arc<Vec<Namespace>>,
    index: &mut HashMap<String, usize>,
    prefix: Option<String>,
    uri: String,
) {
    let namespaces = Arc::make_mut(namespaces);
    if let Some(position) = index.get(prefix.as_deref().unwrap_or_default()).copied() {
        namespaces[position].uri = uri;
    } else {
        index.insert(prefix.clone().unwrap_or_default(), namespaces.len());
        namespaces.push(Namespace { prefix, uri });
    }
}

fn set_namespace_bounded(
    namespaces: &mut Arc<Vec<Namespace>>,
    index: &mut HashMap<String, usize>,
    prefix: Option<String>,
    uri: String,
    namespace_index_bytes: &mut usize,
    materialized_bytes: &mut usize,
) -> Result<()> {
    let inherited_copy = (Arc::strong_count(namespaces) > 1).then(|| {
        namespaces.iter().fold(0usize, |total, namespace| {
            total
                .saturating_add(std::mem::size_of::<Namespace>())
                .saturating_add(namespace.prefix.as_deref().map_or(0, str::len))
                .saturating_add(namespace.uri.len())
        })
    });
    let declaration_bytes = std::mem::size_of::<Namespace>()
        .saturating_add(prefix.as_deref().map_or(0, str::len))
        .saturating_add(uri.len());
    let additional_index_bytes = if index.contains_key(prefix.as_deref().unwrap_or_default()) {
        0
    } else {
        std::mem::size_of::<(String, usize)>()
            .saturating_mul(2)
            .saturating_add(prefix.as_deref().map_or(0, str::len))
    };
    let next_index_bytes = namespace_index_bytes.saturating_add(additional_index_bytes);
    let next = materialized_bytes
        .saturating_add(next_index_bytes)
        .saturating_add(inherited_copy.unwrap_or(0))
        .saturating_add(declaration_bytes);
    if next > NAMESPACE_SCOPE_BYTE_CEILING {
        return Err(Error::Xml(
            "cumulative namespace scope allocation limit exceeded".into(),
        ));
    }
    set_namespace(namespaces, index, prefix, uri);
    *namespace_index_bytes = next_index_bytes;
    *materialized_bytes = next.saturating_sub(next_index_bytes);
    Ok(())
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
) -> Result<(Cow<'a, str>, InternalEntityDeclarations)> {
    let Some(doctype) = doctype_span(xml)? else {
        return Ok((Cow::Borrowed(xml), InternalEntityDeclarations::default()));
    };
    let Some((subset_start, subset_end)) = doctype.internal_subset else {
        return Ok((Cow::Borrowed(xml), InternalEntityDeclarations::default()));
    };
    let subset = &xml[subset_start..subset_end];
    let mut expanded_subset = Cow::Borrowed(subset);
    let mut changed = false;
    let mut rounds = 0usize;
    let declarations = loop {
        let declarations = collect_internal_entity_declarations(expanded_subset.as_ref())?;
        let next = expand_parameter_entity_references(
            expanded_subset.as_ref(),
            &declarations.parameter,
            &declarations.parameter_spans,
            0,
            references,
            meter,
        )?;
        match next {
            Cow::Borrowed(_) => break declarations,
            Cow::Owned(next) => {
                changed = true;
                rounds += 1;
                if rounds > ENTITY_EXPANSION_DEPTH_CEILING {
                    return Err(Error::Xml(
                        "parameter entity declaration depth limit exceeded".into(),
                    ));
                }
                expanded_subset = Cow::Owned(next);
                if *references > ENTITY_REFERENCE_CEILING {
                    return Err(Error::Xml(
                        "parameter entity expansion limit exceeded".into(),
                    ));
                }
            }
        }
    };
    validate_attribute_default_entities(&declarations)?;
    if !changed {
        return Ok((Cow::Borrowed(xml), declarations));
    }
    let capacity = xml
        .len()
        .saturating_sub(subset.len())
        .saturating_add(expanded_subset.len());
    meter.charge(capacity)?;
    let mut expanded_xml = String::with_capacity(capacity);
    expanded_xml.push_str(&xml[..subset_start]);
    expanded_xml.push_str(expanded_subset.as_ref());
    expanded_xml.push_str(&xml[subset_end..]);
    Ok((Cow::Owned(expanded_xml), declarations))
}

fn validate_attribute_default_entities(declarations: &InternalEntityDeclarations) -> Result<()> {
    for declaration in declarations.attributes.values().flatten() {
        let Some(default) = declaration.default.as_deref() else {
            continue;
        };
        let mut cursor = 0usize;
        while let Some(offset) = default.as_bytes()[cursor..]
            .iter()
            .position(|byte| *byte == b'&')
        {
            let start = cursor + offset;
            let (name, consumed) =
                general_entity_reference(&default[start..]).ok_or_else(|| {
                    Error::Xml("ATTLIST default value has an invalid reference".into())
                })?;
            if !name.starts_with('#')
                && !matches!(name, "amp" | "apos" | "gt" | "lt" | "quot")
                && !declarations.general.contains_key(name)
            {
                // XML 1.0 section 4.1 applies Entity Declared even when a default is unused.
                // https://www.w3.org/TR/xml/#wf-entdeclared
                return Err(Error::Xml(format!(
                    "ATTLIST default references undeclared entity `&{name};`"
                )));
            }
            cursor = start + consumed;
        }
    }
    Ok(())
}

#[derive(Default)]
struct InternalEntityDeclarations {
    general: HashMap<String, String>,
    parameter: HashMap<String, String>,
    parameter_spans: Vec<(usize, usize)>,
    attributes: HashMap<String, Vec<InternalAttributeDeclaration>>,
    unparsed: HashMap<String, String>,
    declared_general: HashSet<String>,
}

struct InternalAttributeDeclaration {
    name: String,
    attribute_type: InternalAttributeType,
    default: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InternalAttributeType {
    Cdata,
    Id,
    Tokenized,
}

impl InternalAttributeType {
    const fn is_cdata(self) -> bool {
        matches!(self, Self::Cdata)
    }

    const fn is_id(self) -> bool {
        matches!(self, Self::Id)
    }
}

fn collect_internal_entity_declarations(subset: &str) -> Result<InternalEntityDeclarations> {
    let mut declarations = InternalEntityDeclarations::default();
    let mut cursor = 0;
    while cursor < subset.len() {
        if subset[cursor..]
            .chars()
            .next()
            .is_some_and(crate::lexical::is_xml_whitespace)
        {
            skip_xml_whitespace(subset, &mut cursor);
            continue;
        }
        if subset[cursor..].starts_with("<!--") {
            let content_start = cursor + 4;
            let content_end = subset[content_start..]
                .find("-->")
                .map(|offset| content_start + offset)
                .ok_or_else(|| Error::Xml("unterminated DTD comment".into()))?;
            let content = &subset[content_start..content_end];
            if content.contains("--") || content.ends_with('-') {
                return Err(Error::Xml(
                    "DTD comment contains an invalid `--` sequence".into(),
                ));
            }
            cursor = content_end + 3;
            continue;
        }
        if subset[cursor..].starts_with("<?") {
            cursor = parse_dtd_processing_instruction(subset, cursor)?;
            continue;
        }
        if subset[cursor..].starts_with("<!ATTLIST") {
            cursor = collect_internal_attribute_list(subset, cursor, &mut declarations.attributes)?;
            continue;
        }
        if subset[cursor..].starts_with("<!ELEMENT") {
            cursor = parse_dtd_element_declaration(subset, cursor)?;
            continue;
        }
        if subset[cursor..].starts_with("<!NOTATION") {
            cursor = parse_dtd_notation_declaration(subset, cursor)?;
            continue;
        }
        if subset.as_bytes().get(cursor) == Some(&b'%') {
            parse_dtd_parameter_reference(subset, &mut cursor)?;
            continue;
        }
        if !subset[cursor..].starts_with("<!ENTITY") {
            return Err(Error::Xml(
                "internal DTD subset contains invalid markup or character data".into(),
            ));
        }
        let declaration_start = cursor;
        cursor += "<!ENTITY".len();
        let spacing_start = cursor;
        skip_xml_whitespace(subset, &mut cursor);
        if cursor == spacing_start {
            return Err(Error::Xml(
                "internal entity declaration requires XML whitespace after <!ENTITY".into(),
            ));
        }
        let parameter = subset[cursor..].starts_with('%');
        if parameter {
            cursor += 1;
            let spacing_start = cursor;
            skip_xml_whitespace(subset, &mut cursor);
            if cursor == spacing_start {
                return Err(Error::Xml(
                    "parameter entity declaration requires XML whitespace after %".into(),
                ));
            }
        }
        let name = parse_dtd_name(subset, &mut cursor, "internal entity declaration")?;
        let spacing_start = cursor;
        skip_xml_whitespace(subset, &mut cursor);
        if cursor == spacing_start {
            return Err(Error::Xml(format!(
                "internal entity declaration `{name}` requires XML whitespace before its definition"
            )));
        }
        let Some(quote) = subset.as_bytes().get(cursor).copied() else {
            return Err(Error::Xml(
                "unterminated internal entity declaration".into(),
            ));
        };
        if !matches!(quote, b'\'' | b'"') {
            let (end, system_identifier) =
                parse_external_entity_declaration(subset, cursor, parameter)?;
            if !parameter
                && declarations.declared_general.insert(name.to_owned())
                && let Some(system_identifier) = system_identifier
            {
                declarations
                    .unparsed
                    .insert(name.to_owned(), system_identifier.to_owned());
            }
            cursor = end;
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
        validate_entity_value(name, &value, parameter)?;
        if parameter {
            // XML 1.0 Fifth Edition section 4.2, production [72], permits only optional XML S
            // between PEDef and `>`: https://www.w3.org/TR/xml/#sec-entity-decl
            skip_xml_whitespace(subset, &mut cursor);
            if subset.as_bytes().get(cursor) != Some(&b'>') {
                return Err(Error::Xml(format!(
                    "parameter entity declaration `{name}` has content after its definition"
                )));
            }
            cursor += 1;
        } else {
            cursor = declaration_end(subset, cursor)?;
        }
        if parameter {
            declarations
                .parameter_spans
                .push((declaration_start, cursor));
        }
        if !parameter {
            value = normalize_predefined_entity_declaration(name, value)?;
        }
        if parameter {
            declarations
                .parameter
                .entry(name.to_owned())
                .or_insert(value);
        } else if declarations.declared_general.insert(name.to_owned()) {
            declarations.general.insert(name.to_owned(), value);
        }
    }
    Ok(declarations)
}

fn parse_dtd_processing_instruction(subset: &str, mut cursor: usize) -> Result<usize> {
    cursor += 2;
    let target = parse_dtd_name(subset, &mut cursor, "DTD processing instruction target")?;
    if target.eq_ignore_ascii_case("xml") {
        return Err(Error::Xml(
            "DTD processing instruction target must not be XML".into(),
        ));
    }
    if subset[cursor..].starts_with("?>") {
        return Ok(cursor + 2);
    }
    require_dtd_whitespace(
        subset,
        &mut cursor,
        "after DTD processing instruction target",
    )?;
    let end = subset[cursor..]
        .find("?>")
        .map(|offset| cursor + offset)
        .ok_or_else(|| Error::Xml("unterminated DTD processing instruction".into()))?;
    Ok(end + 2)
}

fn parse_dtd_parameter_reference(subset: &str, cursor: &mut usize) -> Result<()> {
    *cursor += 1;
    parse_dtd_name(subset, cursor, "DTD parameter entity reference")?;
    if subset.as_bytes().get(*cursor) != Some(&b';') {
        return Err(Error::Xml(
            "DTD parameter entity reference must end with `;`".into(),
        ));
    }
    *cursor += 1;
    Ok(())
}

fn parse_dtd_element_declaration(subset: &str, mut cursor: usize) -> Result<usize> {
    // XML 1.0 sections 3.2-3.2.2 productions [45]-[51] define the complete element content
    // grammar. The lexical document scanner exposes the internal subset as one token, so this
    // parser must validate declarations before discarding their validation-only content model.
    // https://www.w3.org/TR/xml/#elemdecls
    cursor += "<!ELEMENT".len();
    require_dtd_whitespace(subset, &mut cursor, "after <!ELEMENT")?;
    parse_dtd_name(subset, &mut cursor, "ELEMENT declaration")?;
    require_dtd_whitespace(subset, &mut cursor, "before ELEMENT content specification")?;
    if dtd_keyword_at(subset, cursor, "EMPTY") {
        cursor += "EMPTY".len();
    } else if dtd_keyword_at(subset, cursor, "ANY") {
        cursor += "ANY".len();
    } else if subset.as_bytes().get(cursor) == Some(&b'(') {
        cursor = parse_dtd_parenthesized_content(subset, cursor)?;
    } else {
        return Err(Error::Xml(
            "ELEMENT declaration has an invalid content specification".into(),
        ));
    }
    skip_xml_whitespace(subset, &mut cursor);
    if subset.as_bytes().get(cursor) != Some(&b'>') {
        return Err(Error::Xml(
            "ELEMENT declaration has trailing or unterminated content".into(),
        ));
    }
    Ok(cursor + 1)
}

fn dtd_keyword_at(subset: &str, cursor: usize, keyword: &str) -> bool {
    subset[cursor..].starts_with(keyword)
        && subset[cursor + keyword.len()..]
            .chars()
            .next()
            .is_none_or(|character| {
                crate::lexical::is_xml_whitespace(character) || character == '>'
            })
}

fn parse_dtd_parenthesized_content(subset: &str, mut cursor: usize) -> Result<usize> {
    cursor += 1;
    skip_xml_whitespace(subset, &mut cursor);
    if subset[cursor..].starts_with("#PCDATA") {
        return parse_dtd_mixed_content(subset, cursor + "#PCDATA".len());
    }
    parse_dtd_children_content(subset, cursor)
}

fn parse_dtd_mixed_content(subset: &str, mut cursor: usize) -> Result<usize> {
    let mut named = false;
    loop {
        skip_xml_whitespace(subset, &mut cursor);
        match subset.as_bytes().get(cursor) {
            Some(b'|') => {
                cursor += 1;
                skip_xml_whitespace(subset, &mut cursor);
                parse_dtd_name(subset, &mut cursor, "mixed ELEMENT content")?;
                named = true;
            }
            Some(b')') => {
                cursor += 1;
                let repeated = subset.as_bytes().get(cursor) == Some(&b'*');
                if repeated {
                    cursor += 1;
                }
                if named && !repeated {
                    return Err(Error::Xml(
                        "mixed ELEMENT content with names must end with `*`".into(),
                    ));
                }
                return Ok(cursor);
            }
            _ => {
                return Err(Error::Xml(
                    "mixed ELEMENT content expects `|` or `)`".into(),
                ));
            }
        }
    }
}

struct DtdContentGroup {
    connector: Option<u8>,
    items: usize,
    expects_item: bool,
}

fn parse_dtd_children_content(subset: &str, mut cursor: usize) -> Result<usize> {
    let mut groups = vec![DtdContentGroup {
        connector: None,
        items: 0,
        expects_item: true,
    }];
    loop {
        skip_xml_whitespace(subset, &mut cursor);
        let expects_item = groups
            .last()
            .expect("the outer content group remains present")
            .expects_item;
        if expects_item {
            if subset.as_bytes().get(cursor) == Some(&b'(') {
                cursor += 1;
                groups.push(DtdContentGroup {
                    connector: None,
                    items: 0,
                    expects_item: true,
                });
                continue;
            }
            parse_dtd_name(subset, &mut cursor, "ELEMENT content particle")?;
            parse_dtd_occurrence_indicator(subset, &mut cursor);
            let group = groups
                .last_mut()
                .expect("the current content group remains present");
            group.items += 1;
            group.expects_item = false;
            continue;
        }

        match subset.as_bytes().get(cursor).copied() {
            Some(connector @ (b'|' | b',')) => {
                let group = groups
                    .last_mut()
                    .expect("the current content group remains present");
                if group
                    .connector
                    .is_some_and(|existing| existing != connector)
                {
                    return Err(Error::Xml(
                        "ELEMENT content group mixes choice and sequence connectors".into(),
                    ));
                }
                group.connector = Some(connector);
                group.expects_item = true;
                cursor += 1;
            }
            Some(b')') => {
                let group = groups.pop().expect("the current content group exists");
                if group.items == 0
                    || group.expects_item
                    || group.connector == Some(b'|') && group.items < 2
                {
                    return Err(Error::Xml("ELEMENT content group is incomplete".into()));
                }
                cursor += 1;
                parse_dtd_occurrence_indicator(subset, &mut cursor);
                let Some(parent) = groups.last_mut() else {
                    return Ok(cursor);
                };
                parent.items += 1;
                parent.expects_item = false;
            }
            _ => {
                return Err(Error::Xml(
                    "ELEMENT content group expects a connector or `)`".into(),
                ));
            }
        }
    }
}

fn parse_dtd_occurrence_indicator(subset: &str, cursor: &mut usize) {
    if subset
        .as_bytes()
        .get(*cursor)
        .is_some_and(|byte| matches!(byte, b'?' | b'*' | b'+'))
    {
        *cursor += 1;
    }
}

fn parse_dtd_notation_declaration(subset: &str, mut cursor: usize) -> Result<usize> {
    // XML 1.0 section 4.7 productions [82]-[83] require a notation name followed by a complete
    // SYSTEM external ID or PUBLIC ID, with an optional system literal only for PUBLIC.
    // https://www.w3.org/TR/xml/#Notations
    cursor += "<!NOTATION".len();
    require_dtd_whitespace(subset, &mut cursor, "after <!NOTATION")?;
    parse_dtd_name(subset, &mut cursor, "NOTATION declaration")?;
    require_dtd_whitespace(subset, &mut cursor, "before NOTATION identifier")?;
    if subset[cursor..].starts_with("SYSTEM") {
        cursor += "SYSTEM".len();
        require_dtd_whitespace(subset, &mut cursor, "after NOTATION SYSTEM")?;
        parse_dtd_system_literal(subset, &mut cursor, "NOTATION system identifier")?;
    } else if subset[cursor..].starts_with("PUBLIC") {
        cursor += "PUBLIC".len();
        require_dtd_whitespace(subset, &mut cursor, "after NOTATION PUBLIC")?;
        parse_dtd_public_identifier(subset, &mut cursor, "NOTATION public identifier")?;
        let before_spacing = cursor;
        skip_xml_whitespace(subset, &mut cursor);
        if subset
            .as_bytes()
            .get(cursor)
            .is_some_and(|byte| matches!(byte, b'\'' | b'"'))
        {
            if cursor == before_spacing {
                return Err(Error::Xml(
                    "XML whitespace is required before NOTATION system identifier".into(),
                ));
            }
            parse_dtd_system_literal(subset, &mut cursor, "NOTATION system identifier")?;
        }
    } else {
        return Err(Error::Xml(
            "NOTATION declaration requires SYSTEM or PUBLIC".into(),
        ));
    }
    skip_xml_whitespace(subset, &mut cursor);
    if subset.as_bytes().get(cursor) != Some(&b'>') {
        return Err(Error::Xml(
            "NOTATION declaration has trailing or unterminated content".into(),
        ));
    }
    Ok(cursor + 1)
}

fn parse_dtd_public_identifier(subset: &str, cursor: &mut usize, context: &str) -> Result<()> {
    // XML 1.0 productions [12]-[13] restrict PubidLiteral to PubidChar in every PUBLIC external
    // identifier, including entity declarations in section 4.2.2.
    // https://www.w3.org/TR/xml/#NT-PubidLiteral
    // https://www.w3.org/TR/xml/#sec-external-ent
    let value = parse_dtd_quoted_literal(subset, cursor, context)?;
    if value.chars().all(|character| {
        character.is_ascii_alphanumeric()
            || matches!(
                character,
                ' ' | '\r'
                    | '\n'
                    | '-'
                    | '\''
                    | '('
                    | ')'
                    | '+'
                    | ','
                    | '.'
                    | '/'
                    | ':'
                    | '='
                    | '?'
                    | ';'
                    | '!'
                    | '*'
                    | '#'
                    | '@'
                    | '$'
                    | '_'
                    | '%'
            )
    }) {
        Ok(())
    } else {
        Err(Error::Xml(format!(
            "{context} contains an invalid PubidChar"
        )))
    }
}

fn collect_internal_attribute_list(
    subset: &str,
    mut cursor: usize,
    declarations: &mut HashMap<String, Vec<InternalAttributeDeclaration>>,
) -> Result<usize> {
    cursor += "<!ATTLIST".len();
    require_dtd_whitespace(subset, &mut cursor, "after <!ATTLIST")?;
    let element_name = parse_dtd_name(subset, &mut cursor, "ATTLIST element")?.to_owned();
    loop {
        let spacing_start = cursor;
        skip_xml_whitespace(subset, &mut cursor);
        if subset.as_bytes().get(cursor) == Some(&b'>') {
            return Ok(cursor + 1);
        }
        if cursor == spacing_start {
            return Err(Error::Xml(
                "XML whitespace is required before an ATTLIST attribute".into(),
            ));
        }
        let name = parse_dtd_name(subset, &mut cursor, "ATTLIST attribute")?.to_owned();
        require_dtd_whitespace(subset, &mut cursor, "after ATTLIST attribute name")?;
        let attribute_type = parse_dtd_attribute_type(subset, &mut cursor)?;
        require_dtd_whitespace(subset, &mut cursor, "before ATTLIST default declaration")?;
        let default = parse_dtd_attribute_default(subset, &mut cursor)?;
        let element_declarations = declarations.entry(element_name.clone()).or_default();
        if !element_declarations
            .iter()
            .any(|declaration| declaration.name == name)
        {
            element_declarations.push(InternalAttributeDeclaration {
                name,
                attribute_type,
                default,
            });
        }
    }
}

fn parse_dtd_attribute_type(subset: &str, cursor: &mut usize) -> Result<InternalAttributeType> {
    if subset[*cursor..].starts_with("NOTATION")
        && subset[*cursor + "NOTATION".len()..]
            .chars()
            .next()
            .is_some_and(crate::lexical::is_xml_whitespace)
    {
        *cursor += "NOTATION".len();
        require_dtd_whitespace(subset, cursor, "after NOTATION")?;
        parse_dtd_enumeration(subset, cursor, DtdEnumerationToken::Name)?;
        return Ok(InternalAttributeType::Tokenized);
    }
    if subset.as_bytes().get(*cursor) == Some(&b'(') {
        parse_dtd_enumeration(subset, cursor, DtdEnumerationToken::Nmtoken)?;
        return Ok(InternalAttributeType::Tokenized);
    }
    let attribute_type = parse_dtd_name(subset, cursor, "ATTLIST attribute type")?;
    match attribute_type {
        "CDATA" => Ok(InternalAttributeType::Cdata),
        "ID" => Ok(InternalAttributeType::Id),
        "IDREF" | "IDREFS" | "ENTITY" | "ENTITIES" | "NMTOKEN" | "NMTOKENS" => {
            Ok(InternalAttributeType::Tokenized)
        }
        _ => Err(Error::Xml(format!(
            "unsupported ATTLIST attribute type `{attribute_type}`"
        ))),
    }
}

#[derive(Clone, Copy)]
enum DtdEnumerationToken {
    Name,
    Nmtoken,
}

fn parse_dtd_enumeration(
    subset: &str,
    cursor: &mut usize,
    token: DtdEnumerationToken,
) -> Result<()> {
    // XML 1.0 section 3.3.1 productions [58] and [59] require one or more Name/Nmtoken
    // entries separated by `|`; merely finding the closing delimiter is insufficient.
    // https://www.w3.org/TR/xml/#sec-attribute-types
    if subset.as_bytes().get(*cursor) != Some(&b'(') {
        return Err(Error::Xml("ATTLIST enumeration must start with `(`".into()));
    }
    *cursor += 1;
    skip_xml_whitespace(subset, cursor);
    loop {
        match token {
            DtdEnumerationToken::Name => {
                parse_dtd_name(subset, cursor, "ATTLIST notation token")?;
            }
            DtdEnumerationToken::Nmtoken => parse_dtd_nmtoken(subset, cursor)?,
        }
        skip_xml_whitespace(subset, cursor);
        match subset.as_bytes().get(*cursor) {
            Some(b')') => {
                *cursor += 1;
                return Ok(());
            }
            Some(b'|') => {
                *cursor += 1;
                skip_xml_whitespace(subset, cursor);
            }
            _ => {
                return Err(Error::Xml(
                    "ATTLIST enumeration token must be followed by `|` or `)`".into(),
                ));
            }
        }
    }
}

fn parse_dtd_nmtoken(subset: &str, cursor: &mut usize) -> Result<()> {
    let start = *cursor;
    while let Some(character) = subset[*cursor..].chars().next()
        && (character == ':' || crate::lexical::is_ncname_char(character))
    {
        *cursor += character.len_utf8();
    }
    if *cursor == start {
        Err(Error::Xml(
            "ATTLIST enumeration has an invalid XML Nmtoken".into(),
        ))
    } else {
        Ok(())
    }
}

fn parse_dtd_attribute_default(subset: &str, cursor: &mut usize) -> Result<Option<String>> {
    if subset[*cursor..].starts_with("#REQUIRED") {
        *cursor += "#REQUIRED".len();
        return Ok(None);
    }
    if subset[*cursor..].starts_with("#IMPLIED") {
        *cursor += "#IMPLIED".len();
        return Ok(None);
    }
    if subset[*cursor..].starts_with("#FIXED") {
        *cursor += "#FIXED".len();
        require_dtd_whitespace(subset, cursor, "after #FIXED")?;
    }
    let value = parse_dtd_quoted_literal(subset, cursor, "ATTLIST default value")?;
    if value.contains('<') {
        return Err(Error::Xml(
            "ATTLIST default value must not contain `<`".into(),
        ));
    }
    validate_attribute_value_references(value)?;
    Ok(Some(value.to_owned()))
}

fn validate_attribute_value_references(value: &str) -> Result<()> {
    // XML 1.0 productions [10] and [41] require every ampersand in an AttValue to begin a
    // complete Reference, even when that default is never applied to an element.
    // https://www.w3.org/TR/xml/#NT-AttValue
    let mut cursor = 0usize;
    while let Some(offset) = value[cursor..].find('&') {
        cursor += offset + 1;
        let end = value[cursor..]
            .find(';')
            .map(|offset| cursor + offset)
            .ok_or_else(|| {
                Error::Xml("ATTLIST default value has an unterminated reference".into())
            })?;
        let reference = &value[cursor..end];
        let valid = if let Some(digits) = reference.strip_prefix("#x") {
            valid_xml_character_reference(digits, 16)
        } else if let Some(digits) = reference.strip_prefix('#') {
            valid_xml_character_reference(digits, 10)
        } else {
            crate::lexical::is_xml_name(reference)
        };
        if !valid {
            return Err(Error::Xml(
                "ATTLIST default value has an invalid reference".into(),
            ));
        }
        cursor = end + 1;
    }
    Ok(())
}

fn parse_external_entity_declaration(
    subset: &str,
    mut cursor: usize,
    parameter: bool,
) -> Result<(usize, Option<&str>)> {
    let system_identifier = if subset[cursor..].starts_with("SYSTEM") {
        cursor += "SYSTEM".len();
        require_dtd_whitespace(subset, &mut cursor, "after SYSTEM")?;
        parse_dtd_system_literal(subset, &mut cursor, "entity system identifier")?
    } else if subset[cursor..].starts_with("PUBLIC") {
        cursor += "PUBLIC".len();
        require_dtd_whitespace(subset, &mut cursor, "after PUBLIC")?;
        parse_dtd_public_identifier(subset, &mut cursor, "entity public identifier")?;
        require_dtd_whitespace(subset, &mut cursor, "before entity system identifier")?;
        parse_dtd_system_literal(subset, &mut cursor, "entity system identifier")?
    } else {
        return Ok((declaration_end(subset, cursor)?, None));
    };
    let spacing_start = cursor;
    skip_xml_whitespace(subset, &mut cursor);
    let unparsed = if subset[cursor..].starts_with("NDATA") {
        if parameter {
            return Err(Error::Xml(
                "parameter entity declaration must not contain NDATA".into(),
            ));
        }
        if cursor == spacing_start {
            return Err(Error::Xml("XML whitespace is required before NDATA".into()));
        }
        cursor += "NDATA".len();
        require_dtd_whitespace(subset, &mut cursor, "after NDATA")?;
        parse_dtd_name(subset, &mut cursor, "NDATA notation")?;
        skip_xml_whitespace(subset, &mut cursor);
        true
    } else {
        false
    };
    if subset.as_bytes().get(cursor) != Some(&b'>') {
        return Err(Error::Xml(
            "external entity declaration has trailing content".into(),
        ));
    }
    Ok((cursor + 1, unparsed.then_some(system_identifier)))
}

fn parse_dtd_system_literal<'a>(
    subset: &'a str,
    cursor: &mut usize,
    context: &str,
) -> Result<&'a str> {
    let value = parse_dtd_quoted_literal(subset, cursor, context)?;
    // XML 1.0 section 4.2.2 makes a fragment identifier in a system identifier an error:
    // https://www.w3.org/TR/xml/#sec-external-ent
    if value.contains('#') {
        return Err(Error::Xml(format!(
            "{context} must not contain a fragment identifier"
        )));
    }
    Ok(value)
}

fn parse_dtd_name<'a>(subset: &'a str, cursor: &mut usize, context: &str) -> Result<&'a str> {
    let start = *cursor;
    while let Some(character) = subset[*cursor..].chars().next()
        && (character == ':' || crate::lexical::is_ncname_char(character))
    {
        *cursor += character.len_utf8();
    }
    let name = &subset[start..*cursor];
    if crate::lexical::is_xml_name(name) {
        Ok(name)
    } else {
        Err(Error::Xml(format!("{context} has an invalid XML Name")))
    }
}

fn parse_dtd_quoted_literal<'a>(
    subset: &'a str,
    cursor: &mut usize,
    context: &str,
) -> Result<&'a str> {
    let quote = subset
        .as_bytes()
        .get(*cursor)
        .copied()
        .filter(|quote| matches!(quote, b'\'' | b'"'))
        .ok_or_else(|| Error::Xml(format!("{context} must be quoted")))?;
    *cursor += 1;
    let start = *cursor;
    while subset
        .as_bytes()
        .get(*cursor)
        .is_some_and(|byte| *byte != quote)
    {
        *cursor += 1;
    }
    if *cursor == subset.len() {
        return Err(Error::Xml(format!("unterminated {context}")));
    }
    let value = &subset[start..*cursor];
    *cursor += 1;
    Ok(value)
}

fn require_dtd_whitespace(subset: &str, cursor: &mut usize, context: &str) -> Result<()> {
    let start = *cursor;
    skip_xml_whitespace(subset, cursor);
    if *cursor == start {
        return Err(Error::Xml(format!("XML whitespace is required {context}")));
    }
    Ok(())
}

fn validate_entity_value(name: &str, value: &str, parameter: bool) -> Result<()> {
    // XML 1.0 production [9] applies to both general and parameter entity declarations. Validate
    // it before preprocessing erases the declaration from the downstream tokenizer:
    // https://www.w3.org/TR/xml/#NT-EntityValue
    let declaration_kind = if parameter { "parameter" } else { "general" };
    let mut cursor = 0usize;
    while cursor < value.len() {
        let character = value[cursor..]
            .chars()
            .next()
            .expect("cursor is before the end of the entity value");
        if !crate::lexical::is_xml10_character(character) {
            return Err(Error::Xml(format!(
                "{declaration_kind} entity declaration `{name}` has an invalid EntityValue"
            )));
        }
        if matches!(character, '&' | '%') {
            let end = value[cursor + 1..]
                .find(';')
                .map(|offset| cursor + 1 + offset)
                .ok_or_else(|| {
                    Error::Xml(format!(
                        "{declaration_kind} entity declaration `{name}` has an unterminated reference"
                    ))
                })?;
            let reference = &value[cursor + 1..end];
            let valid = if character == '%' {
                crate::lexical::is_xml_name(reference)
            } else if let Some(digits) = reference.strip_prefix("#x") {
                valid_xml_character_reference(digits, 16)
            } else if let Some(digits) = reference.strip_prefix('#') {
                valid_xml_character_reference(digits, 10)
            } else {
                crate::lexical::is_xml_name(reference)
            };
            if !valid {
                return Err(Error::Xml(format!(
                    "{declaration_kind} entity declaration `{name}` has an invalid reference"
                )));
            }
            cursor = end + 1;
            continue;
        }
        cursor += character.len_utf8();
    }
    Ok(())
}

fn valid_xml_character_reference(digits: &str, radix: u32) -> bool {
    u32::from_str_radix(digits, radix)
        .ok()
        .and_then(char::from_u32)
        .is_some_and(crate::lexical::is_xml10_character)
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
    if excluded_declarations.is_empty() && !value.as_bytes().contains(&b'%') {
        return Ok(Cow::Borrowed(value));
    }
    let reject_unresolved = excluded_declarations.is_empty() && entities.is_empty();
    meter.check(value.len())?;
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
            reject_unresolved,
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
        reject_unresolved,
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
    reject_unresolved: bool,
) -> Result<()> {
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
        if let Some(after_percent) = tail.strip_prefix('%') {
            if after_percent
                .chars()
                .next()
                .is_some_and(crate::lexical::is_xml_whitespace)
            {
                // In PEDecl, `%` followed by XML S marks a parameter-entity declaration rather
                // than a PEReference. XML 1.0 production [72]: https://www.w3.org/TR/xml/#NT-PEDecl
                meter.append(output, "%")?;
                cursor += 1;
                continue;
            }
            // XML 1.0 section 4.1 WFC Entity Declared requires every PEReference to resolve;
            // preserving an unknown reference would defer it into a parser path that may discard
            // DTD tokens. https://www.w3.org/TR/xml/#wf-entdeclared
            let end = after_percent
                .as_bytes()
                .iter()
                .position(|byte| *byte == b';')
                .ok_or_else(|| Error::Xml("unterminated parameter entity reference".into()))?;
            let name = &after_percent[..end];
            if !crate::lexical::is_xml_name(name) {
                return Err(Error::Xml("invalid parameter entity reference name".into()));
            }
            if let Some(replacement) = entities.get(name) {
                *references += 1;
                if depth >= ENTITY_EXPANSION_DEPTH_CEILING || *references > ENTITY_REFERENCE_CEILING
                {
                    return Err(Error::Xml(format!(
                        "entity reference expansion limit exceeded at `%{name};`"
                    )));
                }
                let replacement = decode_parameter_character_references(replacement, meter)?;
                expand_parameter_entity_references_into(
                    replacement.as_ref(),
                    entities,
                    depth + 1,
                    references,
                    meter,
                    output,
                    reject_unresolved,
                )?;
                cursor += end + 2;
                continue;
            }
            if reject_unresolved {
                return Err(Error::Xml(format!(
                    "undeclared parameter entity `%{name};`"
                )));
            }
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

fn decode_parameter_character_references<'a>(
    value: &'a str,
    meter: &EntityExpansionMeter,
) -> Result<Cow<'a, str>> {
    if !value.as_bytes().windows(2).any(|bytes| bytes == b"&#") {
        return Ok(Cow::Borrowed(value));
    }
    meter.check(value.len())?;
    let mut output = String::with_capacity(value.len());
    let mut cursor = 0usize;
    while let Some(relative) = value[cursor..].find("&#") {
        let start = cursor + relative;
        output.push_str(&value[cursor..start]);
        let end = value[start + 2..]
            .find(';')
            .map(|relative| start + 2 + relative)
            .ok_or_else(|| {
                Error::Xml("unterminated parameter entity character reference".into())
            })?;
        let reference = &value[start + 2..end];
        let (digits, radix) = reference
            .strip_prefix('x')
            .map_or((reference, 10), |digits| (digits, 16));
        let character = u32::from_str_radix(digits, radix)
            .ok()
            .and_then(char::from_u32)
            .filter(|character| crate::lexical::is_xml10_character(*character))
            .ok_or_else(|| Error::Xml("invalid parameter entity character reference".into()))?;
        output.push(character);
        cursor = end + 1;
    }
    output.push_str(&value[cursor..]);
    Ok(Cow::Owned(output))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DoctypeSpan {
    start: usize,
    end: usize,
    internal_subset: Option<(usize, usize)>,
}

fn doctype_span(xml: &str) -> Result<Option<DoctypeSpan>> {
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
        let (length, internal_subset) = scan_doctype_end(tail)?;
        return Ok(Some(DoctypeSpan {
            start: cursor,
            end: cursor + length,
            internal_subset: internal_subset.map(|(start, end)| (cursor + start, cursor + end)),
        }));
    }
}

fn scan_doctype_end(doctype: &str) -> Result<(usize, Option<(usize, usize)>)> {
    let mut cursor = "<!DOCTYPE".len();
    let mut quote = None;
    let mut internal_subset_depth = 0usize;
    let mut internal_subset_start = None;
    let mut internal_subset_end = None;
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
            '[' => {
                if internal_subset_depth == 0 && internal_subset_start.is_none() {
                    internal_subset_start = Some(cursor);
                }
                internal_subset_depth += 1;
            }
            ']' => {
                if internal_subset_depth > 0 {
                    internal_subset_depth -= 1;
                    if internal_subset_depth == 0 {
                        internal_subset_end = Some(cursor - character.len_utf8());
                    }
                }
            }
            '>' if internal_subset_depth == 0 => {
                return Ok((cursor, internal_subset_start.zip(internal_subset_end)));
            }
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
    while let Some(character) = value[*cursor..].chars().next()
        && crate::lexical::is_xml_whitespace(character)
    {
        *cursor += character.len_utf8();
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
    let Some(doctype) = doctype_span(xml)? else {
        return Ok(Cow::Borrowed(xml));
    };
    let doctype_end = doctype.end;
    if !contains_expandable_entity_reference(&xml[doctype_end..], entities) {
        return Ok(Cow::Borrowed(xml));
    }
    meter.check(xml.len())?;
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
    meter.check(value.len())?;
    let mut output = String::with_capacity(value.len());
    expand_entity_references_into(value, entities, depth, references, meter, &mut output)?;
    Ok(Cow::Owned(output))
}

fn contains_expandable_entity_reference(value: &str, entities: &HashMap<String, String>) -> bool {
    let bytes = value.as_bytes();
    let mut cursor = 0usize;
    while let Some(relative) = bytes[cursor..].iter().position(|byte| *byte == b'&') {
        let reference_start = cursor + relative;
        if let Some((name, consumed)) = general_entity_reference(&value[reference_start..]) {
            if entities.contains_key(name) {
                return true;
            }
            cursor = reference_start + consumed;
        } else {
            cursor = reference_start + 1;
        }
    }
    false
}

fn general_entity_reference(value: &str) -> Option<(&str, usize)> {
    let after_ampersand = value.strip_prefix('&')?;
    let end = after_ampersand
        .as_bytes()
        .iter()
        .position(|byte| matches!(byte, b';' | b'&'))?;
    (after_ampersand.as_bytes()[end] == b';').then(|| (&after_ampersand[..end], end + 2))
}

fn expand_entity_references_into(
    value: &str,
    entities: &HashMap<String, String>,
    depth: usize,
    references: &mut usize,
    meter: &mut EntityExpansionMeter,
    output: &mut String,
) -> Result<()> {
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
        if let Some((name, consumed)) = general_entity_reference(tail)
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
            cursor += consumed;
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

    fn check(&self, amount: usize) -> Result<()> {
        crate::budget::ensure(
            crate::BudgetKind::OwnedBytes,
            self.limit,
            self.used.saturating_add(amount),
        )
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
    use std::sync::Arc;

    use super::{
        Attribute, Document, EntityExpansionMeter, Error, ExpandedName, Namespace, NodeKind,
        Result, doctype_span, expand_document_entities, expand_entity_references,
        expand_parameter_entity_references, internal_general_entities, namespace_for,
        namespace_index, normalize_predefined_entity_declaration, parser_workspace_bytes,
        prepare_xml_frontend_bounded, set_namespace,
    };
    use crate::budget::{ENTITY_EXPANSION_BYTE_CEILING, Meter};
    use crate::{BudgetKind, ExecutionBudget, ParseBudget};

    fn nested_xml(depth: usize, leaf: &str) -> String {
        format!("{}{}{}", "<n>".repeat(depth), leaf, "</n>".repeat(depth))
    }

    #[test]
    fn fragment_xml_id_index_is_preflighted_before_mutation() {
        let mut document = Document::empty(None);
        document.push(
            document.root(),
            NodeKind::Element {
                name: ExpandedName::new(None::<String>, "item"),
                prefix: None,
                attributes: vec![Attribute {
                    name: ExpandedName::new(Some("http://www.w3.org/XML/1998/namespace"), "id"),
                    prefix: Some("xml".into()),
                    value: " target ".into(),
                }],
                namespaces: Arc::new(Vec::new()),
            },
            None,
        );
        let mut meter = Meter::new(
            ExecutionBudget {
                source_bytes: usize::MAX,
                external_documents: usize::MAX,
                recursion_depth: usize::MAX,
                xpath_evaluations: usize::MAX,
                extension_operations: usize::MAX,
                pattern_evaluations: usize::MAX,
                template_applications: usize::MAX,
                sort_comparisons: usize::MAX,
                key_entries: usize::MAX,
                result_nodes: usize::MAX,
                serialized_bytes: usize::MAX,
                messages: usize::MAX,
                owned_bytes: 0,
            },
            0,
        )
        .expect("zero-byte meter initializes");

        assert!(matches!(
            document.finalize_xml_ids(&mut meter),
            Err(Error::Budget {
                kind: BudgetKind::OwnedBytes,
                ..
            })
        ));
        assert_eq!(document.ids().count(), 0);
    }

    #[test]
    fn subtree_copy_stack_crosses_the_execution_owned_bytes_gate() {
        // The copied nodes and remap are retained separately by the caller; this test isolates
        // the additional DFS stack that exists only while a wide subtree is being copied.
        let source =
            Document::parse("<root><a/><b/><c/><d/><e/></root>", None).expect("source parses");
        let source_root = source
            .node(source.root())
            .and_then(|root| root.children.first())
            .copied()
            .expect("source has a document element");
        let mut target = Document::empty(None);
        let mut mapping = HashMap::new();
        let mut meter = Meter::new(
            ExecutionBudget {
                source_bytes: usize::MAX,
                external_documents: usize::MAX,
                recursion_depth: usize::MAX,
                xpath_evaluations: usize::MAX,
                extension_operations: usize::MAX,
                pattern_evaluations: usize::MAX,
                template_applications: usize::MAX,
                sort_comparisons: usize::MAX,
                key_entries: usize::MAX,
                result_nodes: usize::MAX,
                serialized_bytes: usize::MAX,
                messages: usize::MAX,
                owned_bytes: 0,
            },
            0,
        )
        .expect("zero-byte meter initializes");

        assert!(matches!(
            target.append_subtree_from(
                target.root(),
                &source,
                source_root,
                &mut mapping,
                &mut meter,
            ),
            Err(Error::Budget {
                kind: BudgetKind::OwnedBytes,
                ..
            })
        ));
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
    fn xinclude_entity_merge_accepts_duplicates_and_rejects_conflicts() {
        // XInclude 1.0 section 4.5.1 collapses duplicate entity metadata but makes a
        // same-name, different-identity entity fatal.
        // https://www.w3.org/TR/xinclude/#unparsed-entities
        let mut output = Document::empty(None);
        output
            .register_unparsed_entity("logo", "memory:logo.png")
            .expect("result entity registers");
        let mut duplicate = Document::empty(None);
        duplicate
            .register_unparsed_entity("logo", "memory:logo.png")
            .expect("duplicate source entity registers");
        output
            .merge_unparsed_entities_from(&duplicate, output.root())
            .expect("identical entity metadata coalesces");

        let mut conflicting = Document::empty(None);
        conflicting
            .register_unparsed_entity("logo", "memory:other.png")
            .expect("conflicting source entity registers");
        assert!(
            output
                .merge_unparsed_entities_from(&conflicting, output.root())
                .is_err()
        );
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
    fn nested_elements_share_unchanged_namespace_scopes() {
        let document = Document::parse(
            r#"<root xmlns:p="urn:test"><first><second/></first></root>"#,
            None,
        )
        .expect("nested namespace document parses");
        let scopes = document.nodes.iter().filter_map(|node| match &node.kind {
            NodeKind::Element { namespaces, .. } => Some(namespaces),
            _ => None,
        });
        let scopes = scopes.collect::<Vec<_>>();
        assert_eq!(scopes.len(), 3);
        assert!(Arc::ptr_eq(scopes[0], scopes[1]));
        assert!(Arc::ptr_eq(scopes[1], scopes[2]));
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
    fn iterative_parser_registers_dtd_declared_id_attributes() {
        // XML 1.0 section 3.3.1 assigns ID semantics to attributes declared with type ID;
        // XPath id() must therefore resolve them without caller-supplied metadata.
        // https://www.w3.org/TR/xml/#sec-attribute-types
        let document = Document::parse_iterative(
            r#"<!DOCTYPE root [<!ATTLIST item key ID #REQUIRED>]><root><item key="target"/></root>"#,
            None,
        )
        .expect("DTD-declared ID parses");
        let owner = document
            .nodes()
            .find_map(|(id, node)| match &node.kind {
                NodeKind::Element { name, .. } if name.local == "item" => Some(id),
                _ => None,
            })
            .expect("ID owner exists");

        assert!(
            document
                .ids()
                .any(|(value, root, registered_owner)| value == "target"
                    && root == document.root()
                    && registered_owner == owner)
        );
    }

    #[test]
    fn iterative_parser_does_not_enforce_dtd_id_validity() {
        // XML 1.0 sections 3.3.1 and 5.1 make the ID Name rule a validity constraint, not a
        // well-formedness constraint required of this non-validating parser.
        // https://www.w3.org/TR/xml/#id
        // https://www.w3.org/TR/xml/#proc-types
        let document = Document::parse_iterative(
            r#"<!DOCTYPE r [<!ATTLIST r id ID #IMPLIED>]><r id="1bad"/>"#,
            None,
        )
        .expect("a non-validating parser accepts a validity-constraint violation");

        assert!(document.ids().any(|(value, _, _)| value == "1bad"));
    }

    #[test]
    fn iterative_parser_coalesces_dtd_and_xml_id_registration() {
        // xml:id 1.0 section 4 gives xml:id ID semantics independently of the DTD. If the DTD
        // declares that same attribute as ID, both mechanisms identify one attribute rather than
        // two competing IDs: https://www.w3.org/TR/xml-id/#processing
        let document = Document::parse_iterative(
            r#"<!DOCTYPE root [<!ATTLIST item xml:id ID #REQUIRED>]><root><item xml:id="target"/></root>"#,
            None,
        )
        .expect("the same xml:id registration is idempotent");

        assert_eq!(
            document
                .ids()
                .filter(|(value, _, _)| *value == "target")
                .count(),
            1
        );

        let error = Document::parse_iterative(
            r#"<!DOCTYPE root [<!ATTLIST item xml:id ID #REQUIRED>]><root><item xml:id="same"/><item xml:id="same"/></root>"#,
            None,
        )
        .expect_err("the same ID on distinct owners remains invalid");
        assert!(error.to_string().contains("duplicate XML ID"));
    }

    #[test]
    fn iterative_parser_does_not_enforce_dtd_id_uniqueness() {
        // XML 1.0 sections 3.3.1 and 5.1 make ID uniqueness a validity constraint that this
        // non-validating parser must not turn into a fatal well-formedness error.
        // https://www.w3.org/TR/xml/#id
        // https://www.w3.org/TR/xml/#proc-types
        let document = Document::parse_iterative(
            r#"<!DOCTYPE root [<!ATTLIST item key ID #REQUIRED>]><root><item key="same"/><item key="same"/></root>"#,
            None,
        )
        .expect("duplicate DTD-declared ID values remain parseable");

        assert_eq!(
            document
                .ids()
                .filter(|(value, _, _)| *value == "same")
                .count(),
            1,
            "the deterministic ID index keeps its first declaration"
        );
    }

    #[test]
    fn iterative_parser_does_not_enforce_one_dtd_id_per_element_type() {
        // XML 1.0 sections 3.3.1 and 5.1 classify the one-ID-per-element-type rule as validity,
        // while both declarations still provide ID typing to a non-validating processor.
        // https://www.w3.org/TR/xml/#one-id-per-el
        // https://www.w3.org/TR/xml/#proc-types
        let document = Document::parse_iterative(
            r#"<!DOCTYPE root [<!ATTLIST item first ID #IMPLIED second ID #IMPLIED>]><root><item first="one" second="two"/></root>"#,
            None,
        )
        .expect("multiple DTD-declared ID attributes remain parseable");

        assert!(document.ids().any(|(value, _, _)| value == "one"));
        assert!(document.ids().any(|(value, _, _)| value == "two"));
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
    fn every_parser_accepts_a_doctype_for_another_document_element() {
        // XML 1.0 section 2.8 defines the name match as a validity constraint; section 5.1 does
        // not require a non-validating processor to enforce it.
        let shallow = "<!DOCTYPE expected><actual/>";
        Document::parse(shallow, None).expect("shallow non-validating parse accepts the document");
        Document::parse_iterative(shallow, None)
            .expect("iterative non-validating parse accepts the document");

        let deep = format!("<!DOCTYPE expected>{}", nested_xml(130, "<actual/>"));
        Document::parse(&deep, None).expect("deep dispatch accepts the validity-only mismatch");
        Document::parse_iterative(&deep, None)
            .expect("iterative parser accepts the validity-only mismatch");
    }

    #[test]
    fn parser_paths_count_xml_line_endings_identically() {
        // XML 1.0 section 2.11 normalizes CR, CRLF, and LF to one logical line ending.
        for separator in ["\n", "\r", "\r\n"] {
            let xml = format!("<root>{separator}<child/></root>");
            for document in [
                Document::parse_tree(&xml, None).expect("tree parser accepts line ending"),
                Document::parse_iterative(&xml, None)
                    .expect("iterative parser accepts line ending"),
            ] {
                let child = document
                    .nodes()
                    .find_map(|(_, node)| match &node.kind {
                        NodeKind::Element { name, .. } if name.local == "child" => Some(node),
                        _ => None,
                    })
                    .expect("child exists");
                assert_eq!(child.source_line, Some(2), "separator {separator:?}");
            }
        }
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
    fn external_identifier_brackets_do_not_form_an_internal_subset() {
        // XML 1.0 only permits the internal subset after the external identifier, outside its
        // quoted SystemLiteral: https://www.w3.org/TR/xml/#NT-doctypedecl
        let xml = r#"<!DOCTYPE r SYSTEM "[<!ENTITY e 'ok'>]"><r>&e;</r>"#;
        assert!(Document::parse_iterative(xml, None).is_err());
    }

    #[test]
    fn external_entity_system_literals_reject_fragment_identifiers() {
        // XML 1.0 section 4.2.2 makes a fragment identifier in a system identifier an error:
        // https://www.w3.org/TR/xml/#sec-external-ent
        for declaration in [
            r#"<!ENTITY logo SYSTEM "image.bin#part" NDATA png>"#,
            r#"<!ENTITY logo PUBLIC "image" "image.bin#part" NDATA png>"#,
            r#"<!NOTATION png SYSTEM "image.bin#part">"#,
            r#"<!NOTATION png PUBLIC "image" "image.bin#part">"#,
        ] {
            let xml = format!("<!DOCTYPE root [{declaration}]><root/>");
            assert!(Document::parse(&xml, None).is_err());
            assert!(Document::parse_iterative(&xml, None).is_err());
        }

        let valid = r#"<!DOCTYPE root [<!NOTATION png SYSTEM "image/png"><!ENTITY logo SYSTEM "image.bin" NDATA png>]><root/>"#;
        Document::parse(valid, None).expect("fragment-free system identifier is valid");
        Document::parse_iterative(valid, None)
            .expect("fragment-free system identifier is valid in the iterative parser");
    }

    #[test]
    fn unparsed_entities_accept_empty_system_literals() {
        // XML 1.0 production [11] permits an empty SystemLiteral. Both parser paths must retain
        // that empty URI as unparsed-entity metadata instead of rejecting the document.
        // https://www.w3.org/TR/xml/#NT-SystemLiteral
        let xml = r#"<!DOCTYPE root [<!NOTATION png SYSTEM "image/png"><!ENTITY logo SYSTEM "" NDATA png>]><root/>"#;
        for document in [
            Document::parse(xml, None).expect("empty system identifier is well-formed"),
            Document::parse_iterative(xml, None)
                .expect("iterative parser accepts an empty system identifier"),
        ] {
            assert_eq!(
                document
                    .unparsed_entities()
                    .map(|(name, uri, _)| (name, uri))
                    .collect::<Vec<_>>(),
                vec![("logo", "")]
            );
        }
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
    fn rejected_unparsed_entity_registration_preserves_the_first_binding() {
        // A failed public mutation must leave the accepted document metadata unchanged.
        let mut document = Document::parse_iterative("<root/>", None).expect("document parses");
        document
            .register_unparsed_entity("logo", "memory:first")
            .expect("first entity is accepted");
        let error = document
            .register_unparsed_entity("logo", "memory:rejected")
            .expect_err("duplicate entity is rejected");
        assert!(matches!(error, super::Error::Xml(message) if message.contains("duplicate")));
        assert_eq!(
            document
                .unparsed_entities()
                .map(|(name, uri, _)| (name, uri))
                .collect::<Vec<_>>(),
            vec![("logo", "memory:first")]
        );
    }

    #[test]
    fn internal_dtd_declaration_boundaries_are_enforced() {
        // XML 1.0 productions [52] and [71] permit an empty ATTLIST but require S before each
        // attribute definition and before NDATA.
        // https://www.w3.org/TR/xml/#NT-AttlistDecl
        // https://www.w3.org/TR/xml/#NT-GEDecl
        Document::parse_iterative("<!DOCTYPE r [<!ATTLIST r>]><r/>", None)
            .expect("an empty ATTLIST is well-formed");
        for malformed in [
            r#"<!DOCTYPE r [<!ATTLIST r a CDATA "x"b CDATA "y">]><r/>"#,
            r#"<!DOCTYPE r [<!ENTITY logo SYSTEM "logo.png"NDATA png>]><r/>"#,
        ] {
            Document::parse_iterative(malformed, None)
                .expect_err("missing DTD declaration whitespace must be rejected");
        }
    }

    #[test]
    fn every_attlist_default_validates_reference_grammar() {
        // XML 1.0 production [10] applies while parsing the declaration, regardless of whether
        // an explicit attribute later prevents the default from being used.
        // https://www.w3.org/TR/xml/#NT-AttValue
        for malformed in [
            r#"<!DOCTYPE r [<!ATTLIST r a CDATA "&broken">]><r a="explicit"/>"#,
            r#"<!DOCTYPE r [<!ATTLIST unused a CDATA "&#x110000;">]><r/>"#,
        ] {
            Document::parse_iterative(malformed, None)
                .expect_err("malformed unused ATTLIST defaults must be rejected");
        }
    }

    #[test]
    fn internal_dtd_enumerations_follow_xml_token_grammar() {
        for valid in [
            r#"<!DOCTYPE r [<!ATTLIST r mode (1 | a:b | x-y) "1">]><r/>"#,
            r#"<!DOCTYPE r [<!ATTLIST r format NOTATION (png | jpeg) "png">]><r/>"#,
        ] {
            Document::parse_iterative(valid, None)
                .expect("well-formed enumeration tokens must be accepted");
        }

        for malformed in [
            r#"<!DOCTYPE r [<!ATTLIST r mode () "a">]><r/>"#,
            r#"<!DOCTYPE r [<!ATTLIST r mode ( ) "a">]><r/>"#,
            r#"<!DOCTYPE r [<!ATTLIST r mode (a||b) "a">]><r/>"#,
            r#"<!DOCTYPE r [<!ATTLIST r mode (|a) "a">]><r/>"#,
            r#"<!DOCTYPE r [<!ATTLIST r mode (a|) "a">]><r/>"#,
            r#"<!DOCTYPE r [<!ATTLIST r mode (a b) "a">]><r/>"#,
            r#"<!DOCTYPE r [<!ATTLIST r format NOTATION (png||jpeg) "png">]><r/>"#,
            r#"<!DOCTYPE r [<!ATTLIST r format NOTATION (1png|jpeg) "jpeg">]><r/>"#,
        ] {
            Document::parse_iterative(malformed, None)
                .expect_err("malformed enumeration grammar must be rejected");
        }
    }

    #[test]
    fn internal_dtd_markup_declarations_follow_xml_grammar() {
        for valid in [
            r#"<!DOCTYPE r [<!ELEMENT r (head, (body | note)*, tail?)>]><r/>"#,
            r#"<!DOCTYPE r [<!ELEMENT r (#PCDATA | item)*>]><r/>"#,
            r#"<!DOCTYPE r [<!NOTATION png SYSTEM "image/png">]><r/>"#,
            r#"<!DOCTYPE r [<!NOTATION png PUBLIC "image/png">]><r/>"#,
            r#"<!DOCTYPE r [<!NOTATION png PUBLIC "image/png" "png.viewer">]><r/>"#,
            r#"<!DOCTYPE r [<!ENTITY % p "parameter"><!ENTITY e "%p; &amp; &#37;">]><r>&e;</r>"#,
        ] {
            Document::parse_iterative(valid, None)
                .expect("well-formed markup declaration must be accepted");
        }

        for malformed in [
            r#"<!DOCTYPE r [<!ELEMENT r (a||b)>]><r/>"#,
            r#"<!DOCTYPE r [<!ELEMENT r (a,b|c)>]><r/>"#,
            r#"<!DOCTYPE r [<!ELEMENT r (#PCDATA|item)>]><r/>"#,
            r#"<!DOCTYPE r [<!ELEMENT r EMPTY extra>]><r/>"#,
            r#"<!DOCTYPE r [<!NOTATION png SYSTEM>]><r/>"#,
            r#"<!DOCTYPE r [<!NOTATION png PUBLIC "image/png" extra>]><r/>"#,
            r#"<!DOCTYPE r [<!ENTITY e PUBLIC "[bad" "urn:example">]><r/>"#,
            r#"<!DOCTYPE r [<!ENTITY e "%">]><r>&e;</r>"#,
            r#"<!DOCTYPE r [<!ENTITY e "&bad">]><r>&e;</r>"#,
            r#"<!DOCTYPE r [<!UNKNOWN r ANY>]><r/>"#,
        ] {
            Document::parse_iterative(malformed, None)
                .expect_err("malformed markup declaration must be rejected");
        }
    }

    #[test]
    fn parameter_attributes_and_duplicate_unparsed_entities_keep_xml_semantics() {
        // Parameter entities can contribute declarations, while XML 1.0 section 4.2 binds the
        // first general-entity declaration and ignores later duplicates.
        // https://www.w3.org/TR/xml/#sec-entity-decl
        let document = Document::parse_iterative(
            r#"<!DOCTYPE r [
              <!ENTITY % attrs '<!ATTLIST r status NMTOKENS "  ready   now  ">'>
              %attrs;
              <!NOTATION png SYSTEM "image/png">
              <!ENTITY logo SYSTEM "first.png" NDATA png>
              <!ENTITY logo SYSTEM "second.png" NDATA png>
            ]><r/>"#,
            Some("https://example.test/source.xml"),
        )
        .expect("parameter-provided attributes and duplicate entities parse");
        let status = document.nodes().find_map(|(_, node)| match &node.kind {
            super::NodeKind::Element { attributes, .. } => attributes
                .iter()
                .find(|attribute| attribute.name.local == "status")
                .map(|attribute| attribute.value.as_str()),
            _ => None,
        });
        assert_eq!(status, Some("ready now"));
        assert_eq!(
            document
                .unparsed_entities()
                .map(|(name, uri, _)| (name, uri))
                .collect::<Vec<_>>(),
            vec![("logo", "https://example.test/first.png")]
        );
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
        let (prepared, declarations) = internal_general_entities(xml, &mut references, &mut meter)
            .expect("parameter entity subset is prepared");
        assert_eq!(prepared, r#"<!DOCTYPE r [ <!ENTITY e "ok">]><r>&e;</r>"#);
        assert_eq!(
            declarations.general.get("e").map(String::as_str),
            Some("ok")
        );

        let document =
            Document::parse_iterative(xml, None).expect("parameter entity declaration expands");
        assert_eq!(document.string_value(document.root()), "ok");
    }

    #[test]
    fn staged_parameter_entities_contribute_markup_declarations() {
        // XML 1.0 sections 4.4.8 and 4.5 allow replacement text to contribute declarations;
        // every newly exposed parameter declaration must therefore join the same bounded pass.
        // https://www.w3.org/TR/xml/#included-in-literal
        let xml = r#"<!DOCTYPE r [<!ENTITY % first '<!ENTITY &#37; second "<!ENTITY e &#39;ok&#39;>">'> %first; %second;]><r>&e;</r>"#;
        let document = Document::parse_iterative(xml, None)
            .expect("staged parameter entity declarations expand");
        assert_eq!(document.string_value(document.root()), "ok");
    }

    #[test]
    fn malformed_parameter_entity_declarations_are_not_stripped() {
        // A declaration may be removed from the subset only after the complete PEDecl grammar
        // has been recognized; otherwise preprocessing can hide malformed XML from the parser.
        for malformed in [
            r#"<!DOCTYPE r [<!ENTITY % p "x" BOGUS>]><r/>"#,
            r#"<!DOCTYPE r [<!ENTITY % p "x &broken">]><r/>"#,
            r#"<!DOCTYPE r [<!ENTITY % p "x %broken">]><r/>"#,
            r#"<!DOCTYPE r [<!ENTITY % p "&#0;">]><r/>"#,
            "<!DOCTYPE r [<!ENTITY % p \"x\"\u{000b}>]><r/>",
            "<!DOCTYPE r [<!ENTITY % p \"x\"\u{000c}>]><r/>",
        ] {
            assert!(Document::parse_iterative(malformed, None).is_err());
        }

        Document::parse_iterative("<!DOCTYPE r [<!ENTITY % p \"x\" \t\r\n>]><r/>", None)
            .expect("XML S before the declaration terminator remains valid");
    }

    #[test]
    fn undeclared_parameter_entity_references_are_rejected() {
        // XML 1.0 section 4.1 requires every parameter-entity reference to name a declared
        // entity; preprocessing must not leave an unknown reference for the DTD scanner to hide.
        // https://www.w3.org/TR/xml/#wf-entdeclared
        let error = Document::parse_iterative("<!DOCTYPE r [%missing;]><r/>", None)
            .expect_err("an undeclared parameter entity is not well-formed XML");
        assert!(
            matches!(&error, Error::Xml(message) if message.contains("parameter entity")),
            "unexpected rejection: {error:?}"
        );
        Document::parse_iterative(
            "<!DOCTYPE r [<!ENTITY % declared '<!ELEMENT r EMPTY>'>%declared;]><r/>",
            None,
        )
        .expect("a declared parameter entity remains valid");
    }

    #[test]
    fn undeclared_entities_in_unused_attribute_defaults_are_rejected() {
        // XML 1.0 section 4.1 applies the Entity Declared well-formedness constraint to entity
        // references in every declared default, whether or not an element uses that attribute.
        // https://www.w3.org/TR/xml/#wf-entdeclared
        let error = Document::parse_iterative(
            r#"<!DOCTYPE r [<!ATTLIST unused value CDATA "&missing;">]><r/>"#,
            None,
        )
        .expect_err("an undeclared entity in an unused default is not well-formed XML");
        assert!(
            matches!(&error, Error::Xml(message) if message.contains("undeclared entity")),
            "unexpected rejection: {error:?}"
        );

        Document::parse_iterative(
            r#"<!DOCTYPE r [<!ENTITY declared "ok"><!ATTLIST unused value CDATA "&declared;">]><r/>"#,
            None,
        )
        .expect("a forward-resolved default entity remains valid");
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
    fn entity_expansion_accepts_source_bounded_long_names() {
        // XML 1.0 productions [4], [5], [68], and [69] impose no lexical byte ceiling on Name.
        // https://www.w3.org/TR/xml/#NT-Name
        let name = format!("entity{}", "a".repeat(1_025));
        let source = format!("&{name};");
        let entities = HashMap::from([(name.clone(), "expanded".into())]);
        assert_eq!(
            expand_entity_references(
                &source,
                &entities,
                0,
                &mut 0,
                &mut EntityExpansionMeter::new(ENTITY_EXPANSION_BYTE_CEILING),
            )
            .expect("source-bounded entity scan succeeds"),
            "expanded"
        );

        let parameter_source = format!("%{name};");
        assert_eq!(
            expand_parameter_entity_references(
                &parameter_source,
                &entities,
                &[],
                0,
                &mut 0,
                &mut EntityExpansionMeter::new(ENTITY_EXPANSION_BYTE_CEILING),
            )
            .expect("source-bounded parameter entity scan succeeds"),
            "expanded"
        );

        let general_xml = format!("<!DOCTYPE r [<!ENTITY {name} 'expanded'>]><r>&{name};</r>");
        let general = Document::parse_iterative(&general_xml, None)
            .expect("a long general entity name remains valid XML");
        assert_eq!(general.string_value(general.root()), "expanded");

        let parameter_xml =
            format!("<!DOCTYPE r [<!ENTITY % {name} ' '> %{name};]><r>expanded</r>");
        let parameter = Document::parse_iterative(&parameter_xml, None)
            .expect("a long parameter entity name remains valid XML");
        assert_eq!(parameter.string_value(parameter.root()), "expanded");
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
    fn shallow_and_iterative_frontends_expand_explicit_attribute_entities_identically() {
        // XML 1.0 section 3.3.3 requires general entity replacement while normalizing every
        // explicit attribute value: https://www.w3.org/TR/xml/#AVNormalize
        let xml =
            r#"<!DOCTYPE root [<!ENTITY quoted '&quot;value&quot;'>]><root attr="&quoted;"/>"#;
        let shallow = Document::parse(xml, None).expect("shallow frontend expands the entity");
        let iterative =
            Document::parse_iterative(xml, None).expect("iterative frontend expands the entity");
        assert_eq!(shallow, iterative);
        let root = shallow
            .node(shallow.root())
            .expect("document root exists")
            .children[0];
        let NodeKind::Element { attributes, .. } =
            &shallow.node(root).expect("element exists").kind
        else {
            panic!("document child is an element");
        };
        assert_eq!(attributes[0].value, "\"value\"");

        let prepared = prepare_xml_frontend_bounded(xml, ENTITY_EXPANSION_BYTE_CEILING)
            .expect("roxmltree frontend preparation expands the entity");
        let parsed = roxmltree::Document::parse(&prepared).expect("prepared XML parses");
        assert_eq!(parsed.root_element().attribute("attr"), Some("\"value\""));
    }

    #[test]
    fn unterminated_entity_names_with_utf8_remain_borrowed() {
        // Source-bounded scanning stops only at lexical delimiters and never slices through a
        // multibyte scalar when an entity reference is unterminated.
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

    #[test]
    fn wide_string_value_traversal_preserves_document_order() {
        // A wide element must not require a sibling-sized DFS frontier merely to find the text
        // nodes that contribute its XPath string-value.
        let mut document = Document::empty(None);
        let root = document.push(
            document.root(),
            NodeKind::Element {
                name: ExpandedName::new(None::<String>, "root"),
                prefix: None,
                attributes: Vec::new(),
                namespaces: Arc::new(Vec::new()),
            },
            None,
        );
        for _ in 0..4_096 {
            document.push(
                root,
                NodeKind::Element {
                    name: ExpandedName::new(None::<String>, "empty"),
                    prefix: None,
                    attributes: Vec::new(),
                    namespaces: Arc::new(Vec::new()),
                },
                None,
            );
        }
        document.push(
            root,
            NodeKind::Text {
                value: "tail".into(),
                disable_output_escaping: false,
            },
            None,
        );

        assert_eq!(document.string_value(root), "tail");
    }

    #[test]
    fn bounded_parse_rejects_source_before_building_the_tree() {
        // A caller-selected source limit is enforced before entity expansion or arena growth.
        let error = Document::parse_with_budget(
            "<root/>",
            None,
            ParseBudget::new(6, usize::MAX, usize::MAX),
        )
        .expect_err("oversized source must be rejected");
        assert!(matches!(
            error,
            Error::Budget {
                kind: BudgetKind::SourceBytes,
                limit: 6,
                actual: 7,
            }
        ));
    }

    #[test]
    fn parser_workspace_bound_covers_wide_retained_documents() {
        // External-resource parsing reserves this bound before scanning. A wide start tag is the
        // adversarial shape where attribute-vector and semantic-arena storage dominate input size.
        let attributes = (0..4096)
            .map(|index| format!(" a{index}='x'"))
            .collect::<String>();
        let xml = format!("<root{attributes}/>");
        let document = Document::parse(&xml, None).expect("wide document parses");
        assert!(parser_workspace_bytes(&xml) >= document.estimated_owned_bytes());
    }

    #[test]
    fn namespace_index_preserves_order_while_overriding_bindings() {
        // QName lookup needs constant-time prefix selection without changing namespace-node order.
        let mut namespaces = Arc::new(vec![
            Namespace {
                prefix: Some("a".into()),
                uri: "urn:old".into(),
            },
            Namespace {
                prefix: None,
                uri: "urn:default".into(),
            },
        ]);
        let mut index = namespace_index(&namespaces);
        set_namespace(
            &mut namespaces,
            &mut index,
            Some("a".into()),
            "urn:new".into(),
        );
        set_namespace(
            &mut namespaces,
            &mut index,
            Some("b".into()),
            "urn:added".into(),
        );

        assert_eq!(
            namespaces
                .iter()
                .map(|namespace| (namespace.prefix.as_deref(), namespace.uri.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (Some("a"), "urn:new"),
                (None, "urn:default"),
                (Some("b"), "urn:added"),
            ]
        );
        assert_eq!(
            namespace_for(&namespaces, &index, Some("a")).as_deref(),
            Some("urn:new")
        );
    }

    #[test]
    fn bounded_parse_rejects_node_and_depth_growth() {
        // The synthetic root counts as one node; each XML element must reserve its slot before
        // materializing attributes, namespace state, or arena storage.
        assert!(matches!(
            Document::parse_with_budget(
                "<root><child/></root>",
                None,
                ParseBudget::new(usize::MAX, 2, usize::MAX),
            ),
            Err(Error::Budget {
                kind: BudgetKind::SourceNodes,
                limit: 2,
                actual: 3,
            })
        ));
        assert!(matches!(
            Document::parse_with_budget(
                "<root><child/></root>",
                None,
                ParseBudget::new(usize::MAX, usize::MAX, 1),
            ),
            Err(Error::Budget {
                kind: BudgetKind::RecursionDepth,
                limit: 1,
                actual: 2,
            })
        ));
    }

    #[test]
    fn bounded_byte_parse_limits_decoded_output() {
        // UTF-16 input can expand after decoding; the decoded source budget remains authoritative.
        let mut bytes = vec![0xff, 0xfe];
        for unit in "<r>é</r>".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        assert!(matches!(
            Document::parse_bytes_with_budget(
                &bytes,
                None,
                ParseBudget::new(8, usize::MAX, usize::MAX),
            ),
            Err(Error::Budget {
                kind: BudgetKind::SourceBytes,
                limit: 8,
                actual,
            }) if actual > 8
        ));
    }
}
