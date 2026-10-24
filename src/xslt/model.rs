#[cfg(feature = "embedded")]
use crate::xml_input_shared as xml_sec_xml_input;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use xml_sec_xml_input::lexical::{Event, Scanner};

use super::budget::{
    ENTITY_EXPANSION_BYTE_CEILING, ENTITY_EXPANSION_DEPTH_CEILING, Meter, ParseWork,
    append_metered_string, ensure, reserve_temporary_vec_slot,
};
use super::{BudgetKind, Error, ParseBudget, ParseUsage, Reported, Result};

const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
const XMLNS_NS: &str = "http://www.w3.org/2000/xmlns/";

mod lexical_storage;

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

/// Stable identity of any `XPath` node in one owned document.
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

impl Node {
    fn xml_base_reference(&self) -> Option<&str> {
        let NodeKind::Element { attributes, .. } = &self.kind else {
            return None;
        };
        attributes.iter().find_map(|attribute| {
            (attribute.name.namespace.as_deref() == Some(XML_NS) && attribute.name.local == "base")
                .then_some(attribute.value.as_str())
        })
    }
}

/// Parser-independent owned XML tree.
#[derive(Debug, Clone)]
pub struct Document {
    identity: u64,
    nodes: Vec<Node>,
    root: NodeId,
    logical_roots: Vec<NodeId>,
    source_bytes: usize,
    retained_bytes: usize,
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
        .saturating_add(node_payload_bytes(&node.kind, node.base_uri.as_deref()))
}

/// Heap bytes a node's kind and base URI hold, apart from its arena slot,
/// child list and shared namespace scope.
fn node_payload_bytes(kind: &NodeKind, base_uri: Option<&str>) -> usize {
    base_uri.map_or(0, str::len).saturating_add(match kind {
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
                    .capacity()
                    .saturating_mul(std::mem::size_of::<Attribute>()),
            )
            .saturating_add(attributes.iter().fold(0usize, |total, attribute| {
                total
                    .saturating_add(attribute.name.local.len())
                    .saturating_add(attribute.name.namespace.as_deref().map_or(0, str::len))
                    .saturating_add(attribute.prefix.as_deref().map_or(0, str::len))
                    .saturating_add(attribute.value.capacity())
            })),
    })
}

fn retained_node_backing_bytes(node: &Node) -> usize {
    let mut bytes = node.base_uri.as_ref().map_or(0, String::capacity);
    bytes = bytes.saturating_add(match &node.kind {
        NodeKind::Root => 0,
        NodeKind::Text { value, .. } | NodeKind::Comment(value) => value.capacity(),
        NodeKind::ProcessingInstruction { target, value } => target
            .capacity()
            .saturating_add(value.as_ref().map_or(0, String::capacity)),
        NodeKind::Element {
            name,
            prefix,
            attributes,
            namespaces,
        } => name
            .local
            .capacity()
            .saturating_add(name.namespace.as_ref().map_or(0, String::capacity))
            .saturating_add(prefix.as_ref().map_or(0, String::capacity))
            .saturating_add(
                attributes
                    .capacity()
                    .saturating_mul(std::mem::size_of::<Attribute>()),
            )
            .saturating_add(attributes.iter().fold(0usize, |total, attribute| {
                total
                    .saturating_add(attribute.name.local.capacity())
                    .saturating_add(
                        attribute
                            .name
                            .namespace
                            .as_ref()
                            .map_or(0, String::capacity),
                    )
                    .saturating_add(attribute.prefix.as_ref().map_or(0, String::capacity))
                    .saturating_add(attribute.value.capacity())
            }))
            .saturating_add(std::mem::size_of::<Vec<Namespace>>())
            .saturating_add(2usize.saturating_mul(std::mem::size_of::<usize>()))
            .saturating_add(
                namespaces
                    .capacity()
                    .saturating_mul(std::mem::size_of::<Namespace>()),
            )
            .saturating_add(namespaces.iter().fold(0usize, |total, namespace| {
                total
                    .saturating_add(namespace.prefix.as_ref().map_or(0, String::capacity))
                    .saturating_add(namespace.uri.capacity())
            })),
    });
    bytes
}

impl Document {
    /// Parse trusted, caller-decoded XML without a caller-selected resource budget.
    ///
    /// Use [`Self::parse_with_budget`] for untrusted input.
    ///
    /// # Errors
    /// Returns XML syntax or entity expansion failures.
    pub fn parse(xml: &str, base_uri: Option<&str>) -> Result<Self> {
        Self::parse_iterative(xml, base_uri)
    }

    /// Parse caller-decoded XML with explicit structural and allocation limits.
    ///
    /// # Errors
    /// Returns XML syntax, entity expansion, structural or resource-budget failures.
    pub fn parse_with_budget(
        xml: &str,
        base_uri: Option<&str>,
        budget: ParseBudget,
    ) -> Result<Self> {
        Self::parse_with_budget_reported(xml, base_uri, budget).outcome
    }

    /// [`Self::parse_with_budget`], also reporting the parser work it admitted.
    #[must_use]
    pub fn parse_with_budget_reported(
        xml: &str,
        base_uri: Option<&str>,
        budget: ParseBudget,
    ) -> Reported<Self, ParseUsage> {
        let mut work = ParseWork::new(budget.parse_work_bytes);
        let outcome = ensure(BudgetKind::SourceBytes, budget.source_bytes, xml.len())
            .and_then(|()| Self::parse_iterative_bounded(xml, base_uri, budget, &mut work));
        Reported {
            outcome,
            usage: work.usage(),
        }
    }

    /// Bytes this tree retains, as its bounded parse charged them; zero for a
    /// document parsed without a budget.
    #[must_use]
    pub const fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    /// Decode and parse trusted XML bytes without a caller-selected resource budget.
    ///
    /// Use [`Self::parse_bytes_with_budget`] for untrusted input.
    ///
    /// # Errors
    /// Returns XML encoding, syntax or entity expansion failures.
    pub fn parse_bytes(bytes: &[u8], base_uri: Option<&str>) -> Result<Self> {
        let xml =
            xml_sec_xml_input::decode_xml(bytes, None).map_err(super::error::decoded_xml_error)?;
        Self::parse_iterative(&xml, base_uri)
    }

    /// Decode and parse XML bytes with explicit structural and allocation limits.
    ///
    /// # Errors
    /// Returns encoding, XML syntax, entity expansion, structural or resource-budget failures.
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
        Self::parse_iterative_bounded(
            &xml,
            base_uri,
            budget,
            &mut ParseWork::new(budget.parse_work_bytes),
        )
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

    // Count retained backing capacity rather than logical length: this reservation survives after
    // parser workspace is released. Shared namespace arenas may be counted more than once, which
    // is preferable to under-reserving an attacker-controlled external document.
    pub(crate) fn estimated_owned_bytes(&self) -> usize {
        self.nodes.iter().fold(
            self.retained_tree_container_bytes()
                .saturating_add(self.retained_identity_index_bytes())
                .saturating_add(
                    self.unparsed_entities.capacity().saturating_mul(
                        std::mem::size_of::<((NodeId, String), String)>()
                            .saturating_add(std::mem::size_of::<u64>()),
                    ),
                )
                .saturating_add(self.unparsed_entities.iter().fold(
                    0usize,
                    |total, ((_, name), value)| {
                        total
                            .saturating_add(name.capacity())
                            .saturating_add(value.capacity())
                    },
                )),
            |total, node| total.saturating_add(retained_node_backing_bytes(node)),
        )
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
                project_tree_element(xml, source)?
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
                Some(super::resolver::resolve_uri_reference(
                    inherited_base.as_deref(),
                    reference,
                ))
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
        document.register_xml_ids(None)?;
        Ok(document)
    }

    fn parse_iterative(xml: &str, base_uri: Option<&str>) -> Result<Self> {
        Self::parse_iterative_bounded(
            xml,
            base_uri,
            ParseBudget::UNBOUNDED,
            &mut ParseWork::new(usize::MAX),
        )
    }

    /// Parse within `budget`, charging each pass over the text to `work` first.
    pub(crate) fn parse_iterative_bounded(
        xml: &str,
        base_uri: Option<&str>,
        budget: ParseBudget,
        work: &mut ParseWork,
    ) -> Result<Self> {
        ensure(BudgetKind::SourceBytes, budget.source_bytes, xml.len())?;
        ensure(BudgetKind::SourceNodes, budget.source_nodes, 1)?;
        let initial_owned = std::mem::size_of::<Node>()
            .checked_add(std::mem::size_of::<NodeId>())
            .and_then(|bytes| bytes.checked_add(base_uri.map_or(0, str::len)))
            .ok_or(Error::Budget {
                kind: BudgetKind::OwnedBytes,
                limit: budget.owned_bytes,
                actual: usize::MAX,
            })?;
        ensure(BudgetKind::OwnedBytes, budget.owned_bytes, initial_owned)?;
        work.charge(base_uri.map_or(0, str::len))?;
        let mut document = Self::empty(base_uri.map(str::to_owned));
        document.source_bytes = xml.len();
        let mut meter = StreamParseMeter {
            budget,
            nodes: 1,
            entity_references: 0,
            entity_expansion: EntityExpansionMeter::with_parse_budget(budget),
            namespace_scope_bytes: 0,
            owned_bytes: initial_owned,
        };
        // Entity declarations and their expansion each take a pass over the
        // document only when an internal subset can declare entities.
        let subset = doctype_span(xml)?.is_some_and(|doctype| doctype.internal_subset.is_some());
        if subset {
            work.charge(xml.len())?;
        }
        meter.entity_expansion.parse_work = Some(work);
        meter.entity_expansion.workspace = budget.owned_bytes - initial_owned;
        let (parameter_expanded_xml, mut declarations) = internal_general_entities(
            xml,
            &mut meter.entity_references,
            &mut meter.entity_expansion,
        )?;
        if subset {
            meter
                .entity_expansion
                .charge_parse_work(parameter_expanded_xml.len())?;
        }
        let expanded_xml = expand_document_entities(
            parameter_expanded_xml.as_ref(),
            &declarations.general,
            &mut meter.entity_references,
            &mut meter.entity_expansion,
        )?;
        meter.entity_expansion.workspace = budget.owned_bytes;
        meter
            .entity_expansion
            .charge_parse_work(expanded_xml.len())?;
        let lexical_held = std::cell::Cell::new(0);
        let lexical_temporary = std::cell::Cell::new(0);
        let mut reader = Scanner::with_storage(
            expanded_xml.as_ref(),
            lexical_storage::Storage {
                limit: budget.owned_bytes,
                held: &lexical_held,
                temporary: &lexical_temporary,
            },
        );
        // XML 1.0 section 2.8 makes matching the DOCTYPE and document-element names a validity
        // constraint; section 5.1 does not require this non-validating parser to enforce it.
        // https://www.w3.org/TR/xml/#sec-prolog-dtd
        let mut elements = Vec::new();
        reserve_charged(&mut elements, 1, &mut meter)?;
        elements.push(StreamElementFrame {
            node: document.root,
            lexical_name: None,
        });
        let mut builder = StreamDocumentBuilder {
            document: &mut document,
            elements: &mut elements,
            declarations: &declarations,
            meter: &mut meter,
            phase: DocumentPhase::Start,
            saw_doctype: false,
        };
        builder.scan(&mut reader, expanded_xml.as_ref(), &lexical_held)?;
        let stack_bytes = elements.capacity() * std::mem::size_of::<StreamElementFrame>();
        drop(elements);
        drop(reader);
        drop(expanded_xml);
        meter.release_owned(stack_bytes);
        document.transfer_unparsed_entities(&mut declarations, base_uri, &mut meter)?;
        let declaration_bytes = declarations.owned_bytes;
        drop(declarations);
        meter
            .entity_expansion
            .release_declarations(declaration_bytes);
        document.register_xml_ids(Some(&mut meter))?;
        document.retained_bytes = meter.retained_bytes();
        Ok(document)
    }
    fn transfer_unparsed_entities(
        &mut self,
        declarations: &mut InternalEntityDeclarations,
        base_uri: Option<&str>,
        meter: &mut StreamParseMeter<'_>,
    ) -> Result<()> {
        let unparsed = std::mem::take(&mut declarations.unparsed);
        for (name, system_identifier) in unparsed {
            let uri = super::resolver::resolve_uri_reference(base_uri, &system_identifier);
            // Transfer the name's existing admission rather than charging its allocation twice.
            let name_bytes = name.capacity();
            meter.entity_expansion.release_declarations(name_bytes);
            declarations.owned_bytes -= name_bytes;
            meter.charge_owned(name_bytes)?;
            // Names are unique in `declarations`, so every entry is kept.
            reserve_index_entry(&mut self.unparsed_entities, uri.capacity(), meter)?;
            self.register_unparsed_entity(name, uri)?;
            let released = system_identifier.capacity();
            drop(system_identifier);
            meter.entity_expansion.release_declarations(released);
            declarations.owned_bytes -= released;
        }

        Ok(())
    }

    #[must_use]
    pub fn empty(base_uri: Option<String>) -> Self {
        static NEXT_DOCUMENT_IDENTITY: AtomicU64 = AtomicU64::new(1);
        #[cfg(test)]
        expansion_workspace_tests::CREATED_ROOTS.with(|count| count.set(count.get() + 1));
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
            retained_bytes: 0,
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
    ///
    /// # Errors
    /// Returns an error for a stale attribute, empty or duplicate ID, or missing logical document.
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
    ///
    /// # Errors
    /// Returns an error when the attribute is absent or its owner is not a current element.
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
    ///
    /// # Errors
    /// Returns an error for a stale or non-element owner, invalid `xml:id`, or conflicting ID.
    ///
    /// # Panics
    /// Panics if internal arena invariants change the validated owner during ID registration.
    pub fn add_default_attribute(&mut self, owner: NodeId, mut attribute: Attribute) -> Result<()> {
        let node = self
            .node(owner)
            .ok_or_else(|| Error::Xml("defaulted attribute owner is stale".into()))?;
        let NodeKind::Element { attributes, .. } = &node.kind else {
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
        let updated_bases = if attribute.name.namespace.as_deref() == Some(XML_NS)
            && attribute.name.local == "base"
        {
            Some(self.defaulted_xml_base_updates(owner, &attribute.value))
        } else {
            None
        };
        let xml_id = if attribute.name.namespace.as_deref() == Some(XML_NS)
            && attribute.name.local == "id"
        {
            // xml:id 1.0 section 4 applies ID normalization and assignment to every xml:id,
            // including attributes added to the infoset by default.
            // https://www.w3.org/TR/xml-id/#processing
            let normalized = normalized_xml_id(&attribute.value)?.into_owned();
            attribute.value.clone_from(&normalized);
            Some(normalized)
        } else {
            None
        };
        // Register before the infallible append so a rejected ID cannot partially mutate the DOM.
        if let Some(value) = xml_id {
            self.register_id_value(owner, value)?;
        }
        let NodeKind::Element { attributes, .. } = &mut self
            .node_mut(owner)
            .expect("defaulted attribute owner remains present")
            .kind
        else {
            unreachable!("defaulted attribute owner was checked as an element");
        };
        attributes.push(attribute);
        if let Some(updates) = updated_bases {
            for (node, base_uri) in updates {
                self.nodes[node.0].base_uri = base_uri;
            }
        }
        Ok(())
    }

    fn defaulted_xml_base_updates(
        &self,
        owner: NodeId,
        reference: &str,
    ) -> Vec<(NodeId, Option<String>)> {
        let inherited = self.node(owner).and_then(|node| node.base_uri.as_deref());
        let owner_base = Some(super::resolver::resolve_uri_reference(inherited, reference));
        let mut updates = vec![(owner, owner_base)];
        let mut cursor = 0;
        while cursor < updates.len() {
            let parent = updates[cursor].0;
            for child in self.nodes[parent.0].children.iter().copied() {
                let base_uri = {
                    let child_base = updates[cursor].1.as_deref();
                    self.nodes[child.0].xml_base_reference().map_or_else(
                        || child_base.map(str::to_owned),
                        |reference| {
                            Some(super::resolver::resolve_uri_reference(
                                child_base, reference,
                            ))
                        },
                    )
                };
                updates.push((child, base_uri));
            }
            cursor += 1;
        }
        updates
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
    ///
    /// # Errors
    /// Returns an error when the entity name is empty or already registered.
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

    /// Index every `xml:id`; a bounded parse passes its meter, which admits the
    /// index's storage and the list of owners before either is allocated.
    fn register_xml_ids(&mut self, mut meter: Option<&mut StreamParseMeter>) -> Result<()> {
        let is_xml_id = |attribute: &Attribute| {
            attribute.name.namespace.as_deref() == Some(XML_NS) && attribute.name.local == "id"
        };
        let owners = self
            .nodes()
            .filter(|(_, node)| match &node.kind {
                NodeKind::Element { attributes, .. } => attributes.iter().any(is_xml_id),
                _ => false,
            })
            .count();
        // One entry per element that already counts as a node, so this cannot overflow.
        let list_bytes = owners * std::mem::size_of::<(NodeId, usize)>();
        if let Some(meter) = meter.as_deref_mut() {
            meter.charge_owned(list_bytes)?;
        }
        let mut attributes = Vec::new();
        attributes.try_reserve_exact(owners).map_err(|error| {
            Error::Dynamic(format!("failed to reserve xml:id storage: {error}"))
        })?;
        attributes.extend(self.nodes().filter_map(|(owner, node)| {
            match &node.kind {
                NodeKind::Element { attributes, .. } => attributes
                    .iter()
                    .position(is_xml_id)
                    .map(|index| (owner, index)),
                _ => None,
            }
        }));
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
            let key_bytes = normalized.capacity();
            if let Some(meter) = meter.as_deref_mut() {
                reserve_index_entry(&mut self.ids, key_bytes, meter)?;
            }
            let indexed = self.ids.len();
            self.register_id_value(owner, normalized)?;
            if let Some(meter) = meter.as_deref_mut()
                && self.ids.len() == indexed
            {
                // The owner already held this ID; the key was dropped.
                meter.release_owned(key_bytes);
            }
        }
        if let Some(meter) = meter {
            meter.release_owned(list_bytes);
        }
        Ok(())
    }

    pub(crate) fn finalize_xml_ids(&mut self, meter: &mut Meter) -> Result<()> {
        let (count, value_bytes) = self.xml_id_summary();
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
    fn xml_id_summary(&self) -> (usize, usize) {
        self.nodes().fold((0usize, 0usize), |totals, (_, node)| {
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
        })
    }

    #[must_use = "iterate to inspect the document's nodes"]
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

    pub(crate) fn push_precharged_text_coalesced(
        &mut self,
        parent: NodeId,
        value: String,
        value_reservation: usize,
        base_uri: String,
        base_uri_reservation: usize,
        meter: &mut Meter,
    ) -> Result<usize> {
        debug_assert_eq!(value_reservation, value.capacity());
        debug_assert_eq!(base_uri_reservation, base_uri.capacity());
        let input_reservation = value_reservation.saturating_add(base_uri_reservation);
        if value.is_empty() {
            meter.release_owned_bytes(input_reservation);
            return Ok(0);
        }
        if let Some(last_child) = self.coalescible_text_child(parent, false) {
            let NodeKind::Text {
                value: existing, ..
            } = &mut self.nodes[last_child.0].kind
            else {
                unreachable!("coalescible_text_child returns only text nodes");
            };
            let old_capacity = existing.capacity();
            let appended = append_metered_string(existing, &value, meter);
            meter.release_owned_bytes(input_reservation);
            appended?;
            return Ok(existing.capacity().saturating_sub(old_capacity));
        }

        let containers_before = self.retained_tree_container_bytes();
        if let Err(error) = self.reserve_metered_push_containers(parent, meter) {
            meter.release_owned_bytes(input_reservation);
            return Err(error);
        }
        self.push(
            parent,
            NodeKind::Text {
                value,
                disable_output_escaping: false,
            },
            Some(base_uri),
        );
        Ok(input_reservation.saturating_add(
            self.retained_tree_container_bytes()
                .saturating_sub(containers_before),
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
        self.try_visit_string_value(id, |_| Ok::<_, core::convert::Infallible>(()), &mut visit)
            .unwrap_or_else(|never| match never {});
    }

    pub(crate) fn try_visit_string_value<E>(
        &self,
        id: NodeId,
        mut inspect: impl FnMut(usize) -> core::result::Result<(), E>,
        mut visit: impl FnMut(&str),
    ) -> core::result::Result<(), E> {
        let Some(node) = self.node(id) else {
            return Ok(());
        };
        inspect(1)?;
        match &node.kind {
            NodeKind::Text { value, .. } | NodeKind::Comment(value) => {
                inspect(value.len())?;
                visit(value);
            }
            NodeKind::ProcessingInstruction { value, .. } => {
                if let Some(value) = value {
                    inspect(value.len())?;
                    visit(value);
                }
            }
            NodeKind::Root | NodeKind::Element { .. } => {
                let Some(mut current_id) = node.children.first().copied() else {
                    return Ok(());
                };
                loop {
                    let Some(current) = self.node(current_id) else {
                        return Ok(());
                    };
                    inspect(1)?;
                    if let NodeKind::Text { value, .. } = &current.kind {
                        // Reserve lexical work before a consumer scans or copies this chunk.
                        inspect(value.len())?;
                        visit(value);
                    }
                    let Some(next) = self.next_descendant(id, current_id) else {
                        return Ok(());
                    };
                    current_id = next;
                }
            }
        }
        Ok(())
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
        self.remap_retained_nodes(&remap, &remap_by_index);
        meter.release_owned_bytes(rebuilt_map_bytes);
        meter.release_owned_bytes(temporary_bytes);
        Ok((remap, retained_map_bytes))
    }
    fn remap_retained_nodes(
        &mut self,
        remap: &HashMap<NodeId, NodeId>,
        remap_by_index: &[Option<NodeId>],
    ) {
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
    }
}

pub(crate) fn normalized_xml_id(value: &str) -> Result<Cow<'_, str>> {
    let normalized = collapse_xml_whitespace(value);
    // xml:id 1.0 section 4 requires validation after whitespace normalization.
    // https://www.w3.org/TR/xml-id/#processing
    if !super::lexical::is_ncname(&normalized) {
        return Err(Error::Xml(format!(
            "xml:id value `{normalized}` is not a valid NCName"
        )));
    }
    Ok(normalized)
}

/// Expand and strip the internal subset for the frontend parser, charging each
/// pass over the text to `work` first.
pub(crate) fn prepare_xml_frontend_bounded<'a>(
    xml: &'a str,
    limit: usize,
    recursion_depth: usize,
    work: &mut ParseWork,
) -> Result<Cow<'a, str>> {
    let mut entity_references = 0;
    let mut entity_expansion = EntityExpansionMeter::with_limits(
        BudgetKind::OwnedBytes,
        limit.min(ENTITY_EXPANSION_BYTE_CEILING),
        usize::MAX,
        recursion_depth.min(ENTITY_EXPANSION_DEPTH_CEILING),
    );
    entity_expansion.workspace = limit;
    entity_expansion.workspace_maximum = limit;
    // Without an internal subset there are no declarations to read or expand.
    let subset = doctype_span(xml)?.is_some_and(|doctype| doctype.internal_subset.is_some());
    if subset {
        work.charge(xml.len())?;
    }
    entity_expansion.parse_work = Some(work);
    let (parameter_expanded_xml, declarations) =
        internal_general_entities(xml, &mut entity_references, &mut entity_expansion)?;
    if subset {
        entity_expansion.charge_parse_work(parameter_expanded_xml.len())?;
    }
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
    entity_expansion.charge_parse_work(expanded_xml.len())?;

    let mut edits = Vec::<(std::ops::Range<usize>, String)>::new();
    let mut scanner = Scanner::new(expanded_xml.as_ref());
    while let Some(event) = scanner
        .next_event()
        .map_err(|error| Error::Xml(error.to_string()))?
    {
        let (Event::Start(start) | Event::Empty(start)) = event else {
            continue;
        };
        prepare_frontend_attribute_edits(
            expanded_xml.as_ref(),
            &start,
            &declarations,
            &mut entity_references,
            &mut entity_expansion,
            &mut edits,
        )?;
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
fn prepare_frontend_attribute_edits(
    xml: &str,
    start: &xml_sec_xml_input::lexical::StartTag<'_>,
    declarations: &InternalEntityDeclarations,
    entity_references: &mut usize,
    entity_expansion: &mut EntityExpansionMeter<'_>,
    edits: &mut Vec<(std::ops::Range<usize>, String)>,
) -> Result<()> {
    let defaults = declarations
        .attributes
        .get(start.name.qualified().as_ref())
        .map_or(&[][..], Vec::as_slice);

    for attribute in &start.attributes {
        let name = attribute.name.qualified();
        let is_cdata = defaults
            .iter()
            .find(|declaration| declaration.name == name)
            .is_none_or(|declaration| declaration.attribute_type.is_cdata());
        // XML 1.0 section 3.3.3 requires tokenized normalization even without
        // entity references; removing the DTD otherwise loses this type information.
        // https://www.w3.org/TR/xml/#AVNormalize
        if is_cdata && !contains_expandable_entity_reference(attribute.value, &declarations.general)
        {
            continue;
        }
        let value = prepare_attribute_value(
            name.as_ref(),
            attribute.value,
            &declarations.general,
            is_cdata,
            entity_references,
            entity_expansion,
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

    let insertion = frontend_default_attributes(
        start,
        defaults,
        declarations,
        entity_references,
        entity_expansion,
    )?;
    if !insertion.is_empty() {
        let before_close = if xml.as_bytes().get(start.range.end - 2) == Some(&b'/') {
            start.range.end - 2
        } else {
            start.range.end - 1
        };
        edits.push((before_close..before_close, insertion));
    }
    Ok(())
}

fn frontend_default_attributes(
    start: &xml_sec_xml_input::lexical::StartTag<'_>,
    defaults: &[InternalAttributeDeclaration],
    declarations: &InternalEntityDeclarations,
    entity_references: &mut usize,
    entity_expansion: &mut EntityExpansionMeter<'_>,
) -> Result<String> {
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
            entity_references,
            entity_expansion,
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

    Ok(insertion)
}

fn escaped_xml_attribute_value_len(value: &str) -> Option<usize> {
    value.chars().try_fold(0usize, |length, character| {
        length.checked_add(match character {
            '&' => "&amp;".len(),
            '<' => "&lt;".len(),
            '"' => "&quot;".len(),
            '\t' => "&#9;".len(),
            '\n' => "&#10;".len(),
            '\r' => "&#13;".len(),
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
            // Preserve the normalized value across reparsing: literal whitespace
            // would normalize again under XML 1.0 section 3.3.3.
            // https://www.w3.org/TR/xml/#AVNormalize
            '\t' => output.push_str("&#9;"),
            '\n' => output.push_str("&#10;"),
            '\r' => output.push_str("&#13;"),
            _ => output.push(character),
        }
    }
}

/// XML 1.0 section 2.11 normalizes source CR/CRLF before parsing; character
/// references are processed later and must retain a referenced CR (section 4.5).
/// <https://www.w3.org/TR/2008/REC-xml-20081126/#sec-line-ends>
fn append_normalized_xml_line_endings(output: &mut String, mut value: &str) {
    #[cfg(test)]
    expansion_workspace_tests::NORMALIZED_BYTES.with(|bytes| bytes.set(bytes.get() + value.len()));
    while let Some(index) = value.find('\r') {
        output.push_str(&value[..index]);
        output.push('\n');
        value = &value[index + 1..];
        if value.starts_with('\n') {
            value = &value[1..];
        }
    }
    output.push_str(value);
}

#[derive(Clone, Copy)]
enum ParsedText<'a> {
    Source(&'a str),
    Reference(char),
}

impl ParsedText<'_> {
    fn maximum_bytes(self) -> usize {
        match self {
            Self::Source(text) => text.len(),
            Self::Reference(character) => character.len_utf8(),
        }
    }
    fn append(self, output: &mut String, meter: &mut StreamParseMeter) -> Result<()> {
        // A source pass and its copy are admitted before either runs.
        meter
            .entity_expansion
            .charge_parse_work(2 * self.maximum_bytes())?;
        match self {
            Self::Source(text) => append_normalized_xml_line_endings(output, text),
            Self::Reference(character) => output.push(character),
        }
        Ok(())
    }
}

fn reserve_parsed_string(
    value: &mut String,
    additional: usize,
    meter: &mut StreamParseMeter,
) -> Result<()> {
    let limit = meter.budget.owned_bytes;
    let refused = || Error::Budget {
        kind: BudgetKind::OwnedBytes,
        limit,
        actual: usize::MAX,
    };
    let required = value.len().checked_add(additional).ok_or_else(refused)?;
    let old = value.capacity();
    if required <= old {
        return Ok(());
    }
    // Geometric growth avoids one realloc per character reference. The old
    // allocation remains admitted until the replacement and copy complete.
    let target = required.max(2 * old);
    meter.charge_owned(target)?;
    meter.entity_expansion.charge_parse_work(value.len())?;
    value
        .try_reserve_exact(target - value.len())
        .map_err(|_| refused())?;
    meter.charge_owned(value.capacity() - target)?;
    meter.release_owned(old);
    Ok(())
}

fn copy_parsed_text(value: ParsedText<'_>, meter: &mut StreamParseMeter) -> Result<String> {
    let mut output = String::new();
    reserve_parsed_string(&mut output, value.maximum_bytes(), meter)?;
    value.append(&mut output, meter)?;
    Ok(output)
}

fn copy_parsed_literal(value: &str, meter: &mut StreamParseMeter) -> Result<String> {
    let mut output = String::new();
    reserve_parsed_string(&mut output, value.len(), meter)?;
    meter.entity_expansion.charge_parse_work(value.len())?;
    output.push_str(value);
    Ok(output)
}

fn copy_base_uri(
    document: &Document,
    parent: NodeId,
    meter: &mut StreamParseMeter,
) -> Result<Option<String>> {
    document
        .node(parent)
        .and_then(|node| node.base_uri.as_deref())
        .map(|uri| copy_parsed_literal(uri, meter))
        .transpose()
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

#[cfg(test)]
fn project_tree_element(xml: &str, source: roxmltree::Node<'_, '_>) -> Result<NodeKind> {
    let prefix = lexical_prefix(xml, source.range().start, source.tag_name().name());
    if !super::lexical::is_ncname(source.tag_name().name())
        || prefix
            .as_deref()
            .is_some_and(|prefix| !super::lexical::is_ncname(prefix))
    {
        return Err(Error::Xml("invalid element QName".into()));
    }
    let attributes = source
        .attributes()
        .map(|attribute| {
            let prefix = attribute_prefix(xml, source, attribute);
            if !super::lexical::is_ncname(attribute.name())
                || prefix
                    .as_deref()
                    .is_some_and(|prefix| !super::lexical::is_ncname(prefix))
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
            .is_some_and(|prefix| !super::lexical::is_ncname(prefix))
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
    Ok(NodeKind::Element {
        name: ExpandedName::new(source.tag_name().namespace(), source.tag_name().name()),
        prefix,
        attributes,
        namespaces,
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DocumentPhase {
    Start,
    Prolog,
    Content,
    Epilog,
}

struct StreamDocumentBuilder<'borrow, 'input, 'work> {
    document: &'borrow mut Document,
    elements: &'borrow mut Vec<StreamElementFrame<'input>>,
    declarations: &'borrow InternalEntityDeclarations,
    meter: &'borrow mut StreamParseMeter<'work>,
    phase: DocumentPhase,
    saw_doctype: bool,
}

impl<'input> StreamDocumentBuilder<'_, 'input, '_> {
    fn scan<'storage>(
        &mut self,
        reader: &mut Scanner<'input, lexical_storage::Storage<'storage>>,
        xml: &'input str,
        lexical_held: &std::cell::Cell<usize>,
    ) -> Result<()> {
        let mut previous_event_offset = 0usize;
        let mut source_line = 1usize;
        loop {
            lexical_held.set(
                self.meter
                    .retained_bytes()
                    .saturating_add(self.meter.entity_expansion.used)
                    .saturating_add(self.meter.entity_expansion.declaration_bytes),
            );
            let Some(event) = reader.next_event().map_err(|error| match error {
                xml_sec_xml_input::lexical::Error::Resource(error) => error,
                error => Error::Xml(error.to_string()),
            })?
            else {
                break;
            };
            let event_offset = event_range_start(&event);
            source_line = source_line.saturating_add(xml_line_endings(
                &xml.as_bytes()[previous_event_offset..event_offset],
            ));
            previous_event_offset = event_offset;
            self.process(event, source_line)?;
        }
        self.finish()
    }

    fn process<'storage>(
        &mut self,
        event: Event<'input, lexical_storage::Attributes<'input, 'storage>>,
        source_line: usize,
    ) -> Result<()> {
        match event {
            Event::Start(start) => self.start(start, false, source_line),
            Event::Empty(start) => self.start(start, true, source_line),
            Event::End { name, .. } => self.end(name),
            Event::Text { text, .. } => self.text(text, source_line),
            Event::CData { text, .. } => self.cdata(text, source_line),
            Event::Comment { text, .. } => self.comment(text, source_line),
            Event::ProcessingInstruction {
                target, content, ..
            } => self.processing_instruction(target, content, source_line),
            Event::Reference { name, .. } => self.reference(name, source_line),
            Event::Declaration { .. } => self.declaration(),
            Event::DocType { .. } => self.doctype(),
        }
    }
    fn start<'storage>(
        &mut self,
        start: xml_sec_xml_input::lexical::StartTag<
            'input,
            lexical_storage::Attributes<'input, 'storage>,
        >,
        empty: bool,
        source_line: usize,
    ) -> Result<()> {
        #[cfg(test)]
        expansion_workspace_tests::SCANNED_ATTRIBUTES
            .with(|count| count.set(count.get() + start.attributes.len()));
        let lexical_bytes = start.attributes.bytes();
        self.meter.charge_owned(lexical_bytes)?;
        if self.elements.len() == 1 {
            if self.phase == DocumentPhase::Epilog {
                return Err(Error::Xml("multiple document elements".into()));
            }
            self.phase = if empty {
                DocumentPhase::Epilog
            } else {
                DocumentPhase::Content
            };
        }
        let id = push_stream_element(
            self.document,
            self.elements,
            &start,
            empty,
            self.declarations,
            self.meter,
        )?;
        self.document.nodes[id.0].source_line = Some(source_line);
        drop(start);
        self.meter.release_owned(lexical_bytes);

        Ok(())
    }

    fn end(&mut self, name: xml_sec_xml_input::lexical::Name<'input>) -> Result<()> {
        if self.elements.len() == 1 {
            return Err(Error::Xml("unmatched closing element".into()));
        }
        let opening_name = self
            .elements
            .last()
            .and_then(|frame| frame.lexical_name)
            .expect("non-root element frames retain their lexical name");
        if name != opening_name {
            let closing_name = name.qualified();
            let opening_name = opening_name.qualified();
            return Err(Error::Xml(format!(
                "closing element `{closing_name}` does not match `{opening_name}`"
            )));
        }
        self.elements.pop();
        if self.elements.len() == 1 {
            self.phase = DocumentPhase::Epilog;
        }

        Ok(())
    }

    fn text(&mut self, text: &str, source_line: usize) -> Result<()> {
        if self.elements.len() == 1 && !text.trim_matches([' ', '\t', '\r', '\n']).is_empty() {
            return Err(Error::Xml(
                "non-whitespace text outside the document element".into(),
            ));
        }
        if self.elements.len() > 1 && !text.is_empty() {
            let id = push_parsed_text(
                self.document,
                self.elements,
                ParsedText::Source(text),
                self.meter,
            )?;
            self.document.nodes[id.0]
                .source_line
                .get_or_insert(source_line);
        } else if self.phase == DocumentPhase::Start {
            self.phase = DocumentPhase::Prolog;
        }

        Ok(())
    }

    fn cdata(&mut self, text: &str, source_line: usize) -> Result<()> {
        if self.elements.len() == 1 {
            return Err(Error::Xml(
                "CDATA is not allowed outside the document element".into(),
            ));
        }
        let id = push_parsed_text(
            self.document,
            self.elements,
            ParsedText::Source(text),
            self.meter,
        )?;
        self.document.nodes[id.0]
            .source_line
            .get_or_insert(source_line);

        Ok(())
    }

    fn comment(&mut self, text: &str, source_line: usize) -> Result<()> {
        if self.phase == DocumentPhase::Start {
            self.phase = DocumentPhase::Prolog;
        }
        let parent = self
            .elements
            .last()
            .expect("document frame remains present")
            .node;
        self.meter.reserve_node()?;
        let value = copy_parsed_text(ParsedText::Source(text), self.meter)?;
        let inherited_base = copy_base_uri(self.document, parent, self.meter)?;
        let id = push_metered(
            self.document,
            parent,
            NodeKind::Comment(value),
            inherited_base,
            self.meter,
        )?;
        self.document.nodes[id.0].source_line = Some(source_line);

        Ok(())
    }

    fn processing_instruction(
        &mut self,
        target: &str,
        content: Option<&str>,
        source_line: usize,
    ) -> Result<()> {
        if self.phase == DocumentPhase::Start {
            self.phase = DocumentPhase::Prolog;
        }
        let parent = self
            .elements
            .last()
            .expect("document frame remains present")
            .node;
        self.meter.reserve_node()?;
        let target = copy_parsed_literal(target, self.meter)?;
        let value = content
            .map(|text| copy_parsed_text(ParsedText::Source(text), self.meter))
            .transpose()?;
        let inherited_base = copy_base_uri(self.document, parent, self.meter)?;
        let id = push_metered(
            self.document,
            parent,
            NodeKind::ProcessingInstruction { target, value },
            inherited_base,
            self.meter,
        )?;
        self.document.nodes[id.0].source_line = Some(source_line);

        Ok(())
    }

    fn reference(&mut self, reference: &str, source_line: usize) -> Result<()> {
        if self.elements.len() == 1 {
            return Err(Error::Xml(
                "character and entity references are not allowed outside the document element"
                    .into(),
            ));
        }
        let value = match reference {
            "amp" => '&',
            "apos" => '\'',
            "gt" => '>',
            "lt" => '<',
            "quot" => '"',
            value if value.starts_with('#') => {
                xml_sec_xml_input::lexical::decode_numeric_character_reference(&value[1..])
                    .map_err(|_| Error::Xml("invalid character reference".into()))?
            }
            name => {
                return Err(Error::Xml(format!("unresolved entity reference &{name};")));
            }
        };
        let id = push_parsed_text(
            self.document,
            self.elements,
            ParsedText::Reference(value),
            self.meter,
        )?;
        self.document.nodes[id.0]
            .source_line
            .get_or_insert(source_line);

        Ok(())
    }

    fn declaration(&mut self) -> Result<()> {
        if self.phase != DocumentPhase::Start {
            return Err(Error::Xml(
                "XML declaration is permitted only at the start of the document".into(),
            ));
        }
        self.phase = DocumentPhase::Prolog;

        Ok(())
    }

    fn doctype(&mut self) -> Result<()> {
        if matches!(self.phase, DocumentPhase::Content | DocumentPhase::Epilog) {
            return Err(Error::Xml(
                "document type declaration is permitted only in the prolog".into(),
            ));
        }
        if self.saw_doctype {
            return Err(Error::Xml("duplicate document type declaration".into()));
        }
        self.saw_doctype = true;
        self.phase = DocumentPhase::Prolog;

        Ok(())
    }

    fn finish(&self) -> Result<()> {
        if self.elements.len() != 1 {
            return Err(Error::Xml("unclosed element".into()));
        }
        if self.phase != DocumentPhase::Epilog {
            return Err(Error::Xml("document element is missing".into()));
        }
        Ok(())
    }
}

struct StreamElementFrame<'a> {
    node: NodeId,
    lexical_name: Option<xml_sec_xml_input::lexical::Name<'a>>,
}

struct StreamParseMeter<'w> {
    budget: ParseBudget,
    nodes: usize,
    entity_references: usize,
    entity_expansion: EntityExpansionMeter<'w>,
    namespace_scope_bytes: usize,
    owned_bytes: usize,
}

impl StreamParseMeter<'_> {
    /// Admit `bytes` more of the tree; namespace scopes share the same ceiling.
    fn charge_owned(&mut self, bytes: usize) -> Result<()> {
        let refused = || Error::Budget {
            kind: BudgetKind::OwnedBytes,
            limit: self.budget.owned_bytes,
            actual: usize::MAX,
        };
        let owned = self.owned_bytes.checked_add(bytes).ok_or_else(refused)?;
        let actual = owned
            .checked_add(self.namespace_scope_bytes)
            .and_then(|actual| actual.checked_add(self.entity_expansion.used))
            .and_then(|actual| actual.checked_add(self.entity_expansion.declaration_bytes))
            .ok_or_else(refused)?;
        ensure(BudgetKind::OwnedBytes, self.budget.owned_bytes, actual)?;
        self.owned_bytes = owned;
        Ok(())
    }

    /// Return `bytes` admitted for storage that was not kept.
    fn release_owned(&mut self, bytes: usize) {
        self.owned_bytes = self
            .owned_bytes
            .checked_sub(bytes)
            .expect("released owned bytes were admitted");
    }

    /// Bytes the tree holds so far.
    const fn retained_bytes(&self) -> usize {
        // Both count bytes of live allocations, so their sum fits the address space.
        self.owned_bytes + self.namespace_scope_bytes
    }

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

trait ParseAllocationBudget {
    fn owned_limit(&self) -> usize;
    fn charge_owned(&mut self, bytes: usize) -> Result<()>;
    fn release_owned(&mut self, bytes: usize);
}

impl ParseAllocationBudget for StreamParseMeter<'_> {
    fn owned_limit(&self) -> usize {
        self.budget.owned_bytes
    }
    fn charge_owned(&mut self, bytes: usize) -> Result<()> {
        StreamParseMeter::charge_owned(self, bytes)
    }
    fn release_owned(&mut self, bytes: usize) {
        StreamParseMeter::release_owned(self, bytes);
    }
}

trait ParseIndex {
    fn len(&self) -> usize;
    fn capacity(&self) -> usize;
    fn entry_bytes(&self) -> usize;
    fn try_reserve(
        &mut self,
        additional: usize,
    ) -> std::result::Result<(), std::collections::TryReserveError>;
}

impl<K: Eq + std::hash::Hash, V> ParseIndex for HashMap<K, V> {
    fn len(&self) -> usize {
        HashMap::len(self)
    }
    fn capacity(&self) -> usize {
        HashMap::capacity(self)
    }
    fn entry_bytes(&self) -> usize {
        std::mem::size_of::<(K, V)>() + std::mem::size_of::<u64>()
    }
    fn try_reserve(
        &mut self,
        additional: usize,
    ) -> std::result::Result<(), std::collections::TryReserveError> {
        HashMap::try_reserve(self, additional)
    }
}

impl<K: Eq + std::hash::Hash> ParseIndex for HashSet<K> {
    fn len(&self) -> usize {
        HashSet::len(self)
    }
    fn capacity(&self) -> usize {
        HashSet::capacity(self)
    }
    fn entry_bytes(&self) -> usize {
        std::mem::size_of::<K>() + std::mem::size_of::<u64>()
    }
    fn try_reserve(
        &mut self,
        additional: usize,
    ) -> std::result::Result<(), std::collections::TryReserveError> {
        HashSet::try_reserve(self, additional)
    }
}

/// Append a parsed node whose owned payload was admitted before construction.
///
/// The arena and the parent's child list grow by explicit exact reservations,
/// so their capacity is admitted before it is allocated.
fn push_metered(
    document: &mut Document,
    parent: NodeId,
    kind: NodeKind,
    base_uri: Option<String>,
    meter: &mut StreamParseMeter,
) -> Result<NodeId> {
    reserve_node_storage(document, parent, meter)?;
    Ok(document.push(parent, kind, base_uri))
}

fn reserve_node_storage(
    document: &mut Document,
    parent: NodeId,
    meter: &mut StreamParseMeter,
) -> Result<()> {
    let nodes = &mut document.nodes;
    if nodes.len() == nodes.capacity() {
        let additional = nodes.capacity().max(4);
        reserve_charged(nodes, additional, meter)?;
    }
    let children = &mut nodes[parent.0].children;
    if children.len() == children.capacity() {
        let additional = children.capacity().max(4);
        reserve_charged(children, additional, meter)?;
    }
    Ok(())
}

/// Admit one more entry of a retained index whose strings own `owned_bytes`, growing the
/// index first when it is full. Storage is counted as `estimated_owned_bytes` counts it.
fn reserve_index_entry(
    index: &mut impl ParseIndex,
    owned_bytes: usize,
    meter: &mut impl ParseAllocationBudget,
) -> Result<()> {
    let limit = meter.owned_limit();
    let refused = || Error::Budget {
        kind: BudgetKind::OwnedBytes,
        limit,
        actual: usize::MAX,
    };
    if index.len() == index.capacity() {
        let entry = index.entry_bytes();
        let additional = index.capacity().max(4);
        // A hash table reports a capacity of at least the entries it reserves and at
        // most twice as many, so this bounds the growth before it is allocated.
        let bound = additional
            .checked_mul(2)
            .and_then(|slots| slots.checked_mul(entry))
            .ok_or_else(refused)?;
        meter.charge_owned(bound)?;
        let before = index.capacity();
        index.try_reserve(additional).map_err(|_| refused())?;
        let granted = (index.capacity() - before)
            .checked_mul(entry)
            .ok_or_else(refused)?;
        if granted > bound {
            meter.charge_owned(granted - bound)?;
        } else {
            meter.release_owned(bound - granted);
        }
    }
    meter.charge_owned(owned_bytes)
}

/// Grow `values` by `additional` slots, charging the requested capacity before
/// allocating and any further capacity the allocator granted after it.
fn reserve_charged<T>(
    values: &mut Vec<T>,
    additional: usize,
    meter: &mut impl ParseAllocationBudget,
) -> Result<()> {
    let limit = meter.owned_limit();
    let refused = || Error::Budget {
        kind: BudgetKind::OwnedBytes,
        limit,
        actual: usize::MAX,
    };
    let old_bytes = values.capacity() * std::mem::size_of::<T>();
    let requested = values
        .len()
        .checked_add(additional)
        .ok_or_else(refused)?
        .checked_mul(std::mem::size_of::<T>())
        .ok_or_else(refused)?;
    // A reallocating vector can hold both blocks until the copy completes.
    meter.charge_owned(requested)?;
    let before = values.capacity();
    values
        .try_reserve_exact(additional)
        .map_err(|_| refused())?;
    // `try_reserve_exact` may allocate more than requested; capacity never shrinks here.
    let granted = values
        .capacity()
        .checked_mul(std::mem::size_of::<T>())
        .ok_or_else(refused)?;
    if granted > requested {
        meter.charge_owned(granted - requested)?;
    } else {
        meter.release_owned(requested - granted);
    }
    debug_assert!(values.capacity() >= before);
    meter.release_owned(old_bytes);
    Ok(())
}

fn push_stream_element<
    'a,
    A: std::ops::Deref<Target = [xml_sec_xml_input::lexical::Attribute<'a>]>,
>(
    document: &mut Document,
    elements: &mut Vec<StreamElementFrame<'a>>,
    start: &xml_sec_xml_input::lexical::StartTag<'a, A>,
    empty: bool,
    declarations: &InternalEntityDeclarations,
    meter: &mut StreamParseMeter,
) -> Result<NodeId> {
    meter.element_depth(elements.len())?;
    meter.reserve_node()?;
    // Frames survive semantic staging and borrow QName slices from the input.
    // Admit replacement capacity while the old stack is still live.
    if !empty && elements.len() == elements.capacity() {
        let additional = elements.capacity().max(4);
        reserve_charged(elements, additional, meter)?;
    }
    let staging_start = meter.owned_bytes;
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
    let (mut namespace_index, mut namespace_index_bytes) =
        admit_namespace_index(&namespaces, meter)?;
    meter
        .charge_owned(start.name.local().len() + start.name.prefix().map_or(0, |p| p.len() + 1))?;
    let lexical_name = start.name.qualified();
    let declared_attributes = declarations
        .attributes
        .get(lexical_name.as_ref())
        .map_or(&[][..], Vec::as_slice);
    let mut raw_attributes = Vec::new();
    {
        let mut stage = StreamAttributeStage {
            namespaces: &mut namespaces,
            namespace_index: &mut namespace_index,
            namespace_index_bytes: &mut namespace_index_bytes,
            raw_attributes: &mut raw_attributes,
        };
        stage.source_attributes(start, declared_attributes, declarations, meter)?;
        stage.default_attributes(start, declared_attributes, declarations, meter)?;
    }
    meter.charge_owned(lexical_name.len())?;
    let prefix = start.name.prefix().map(str::to_owned);
    let local = start.name.local().to_owned();
    if let Some(position) = namespace_index.get(prefix.as_deref().unwrap_or_default()) {
        meter.charge_owned(namespaces[*position].uri.len())?;
    }
    let namespace = namespace_for(&namespaces, &namespace_index, prefix.as_deref());
    if prefix.is_some() && namespace.is_none() {
        return Err(Error::Xml(format!(
            "undeclared namespace prefix in element {lexical_name}"
        )));
    }
    drop(lexical_name);
    let StreamProjectedAttributes {
        attributes,
        first_id_attribute,
        additional_id_attributes,
    } = project_stream_attributes(raw_attributes, &namespaces, &namespace_index, meter)?;
    let inherited_base = copy_base_uri(document, parent, meter)?;
    let effective_base = if let Some(attribute) = attributes.iter().find(|attribute| {
        attribute.name.namespace.as_deref() == Some(XML_NS) && attribute.name.local == "base"
    }) {
        Some(super::resolver::resolve_uri_reference(
            inherited_base.as_deref(),
            &attribute.value,
        ))
    } else {
        inherited_base
    };
    drop(namespace_index);
    // Keep the admitted payload live while growing the node arena and parent's
    // child vector. Only dropped staging is released, never the moved strings.
    let id_bytes = additional_id_attributes.capacity() * std::mem::size_of::<usize>();
    let kind = NodeKind::Element {
        name: ExpandedName::new(namespace, local),
        prefix,
        attributes,
        namespaces,
    };
    let payload = node_payload_bytes(&kind, effective_base.as_deref());
    let staged = meter.owned_bytes - staging_start - id_bytes;
    if staged >= payload {
        meter.release_owned(staged - payload);
    } else {
        meter.charge_owned(payload - staged)?;
    }
    reserve_node_storage(document, parent, meter)?;
    let projected = document.push(parent, kind, effective_base);
    register_stream_id_attributes(
        document,
        projected,
        first_id_attribute
            .into_iter()
            .chain(additional_id_attributes),
        meter,
    )?;
    meter.release_owned(id_bytes);
    if !empty {
        elements.push(StreamElementFrame {
            node: projected,
            lexical_name: Some(start.name),
        });
    }
    Ok(projected)
}
fn admit_namespace_index(
    namespaces: &[Namespace],
    meter: &mut StreamParseMeter<'_>,
) -> Result<(HashMap<String, usize>, usize)> {
    let bytes = namespace_index_owned_bytes(namespaces);
    ensure(
        BudgetKind::NamespaceScopeBytes,
        meter.budget.namespace_scope_bytes,
        meter.namespace_scope_bytes.saturating_add(bytes),
    )?;
    meter.charge_owned(bytes)?;
    Ok((namespace_index(namespaces), bytes))
}

fn register_stream_id_attributes(
    document: &mut Document,
    projected: NodeId,
    indices: impl IntoIterator<Item = usize>,
    meter: &mut StreamParseMeter<'_>,
) -> Result<()> {
    for index in indices {
        let value = document
            .node(projected)
            .and_then(|node| match &node.kind {
                NodeKind::Element { attributes, .. } => attributes.get(index),
                _ => None,
            })
            .map(|attribute| collapse_xml_whitespace(&attribute.value).into_owned())
            .ok_or_else(|| Error::Xml("DTD ID attribute reference is stale".into()))?;
        let key_bytes = value.capacity();
        reserve_index_entry(&mut document.ids, key_bytes, meter)?;
        let indexed = document.ids.len();
        document.register_dtd_id_value(projected, value)?;
        if document.ids.len() == indexed {
            // A repeated ID keeps its first owner; this key was dropped.
            meter.release_owned(key_bytes);
        }
    }
    Ok(())
}

struct StreamAttributeStage<'a> {
    namespaces: &'a mut Arc<Vec<Namespace>>,
    namespace_index: &'a mut HashMap<String, usize>,
    namespace_index_bytes: &'a mut usize,
    raw_attributes: &'a mut Vec<(String, String, InternalAttributeType)>,
}

impl StreamAttributeStage<'_> {
    fn source_attributes<
        'input,
        A: std::ops::Deref<Target = [xml_sec_xml_input::lexical::Attribute<'input>]>,
    >(
        &mut self,
        start: &xml_sec_xml_input::lexical::StartTag<'input, A>,
        declared_attributes: &[InternalAttributeDeclaration],
        declarations: &InternalEntityDeclarations,
        meter: &mut StreamParseMeter<'_>,
    ) -> Result<()> {
        for attribute in start.attributes.iter() {
            meter.charge_owned(
                attribute.name.local().len() + attribute.name.prefix().map_or(0, |p| p.len() + 1),
            )?;
            let name = attribute.name.qualified();
            let attribute_type = declared_attributes
                .iter()
                .find(|declaration| declaration.name == name)
                .map_or(InternalAttributeType::Cdata, |declaration| {
                    declaration.attribute_type
                });
            let value = prepare_stream_attribute_value(
                name.as_ref(),
                attribute.value,
                &declarations.general,
                attribute_type.is_cdata(),
                meter,
            )?;
            if name == "xmlns" {
                validate_namespace_binding(None, &value)?;
                set_namespace_bounded(
                    self.namespaces,
                    self.namespace_index,
                    None,
                    value,
                    meter.budget.namespace_scope_bytes,
                    self.namespace_index_bytes,
                    &mut meter.namespace_scope_bytes,
                )?;
            } else if let Some(prefix) = name.strip_prefix("xmlns:") {
                if !super::lexical::is_ncname(prefix) {
                    return Err(Error::Xml(format!("invalid namespace prefix {prefix}")));
                }
                validate_namespace_binding(Some(prefix), &value)?;
                set_namespace_bounded(
                    self.namespaces,
                    self.namespace_index,
                    Some(prefix.into()),
                    value,
                    meter.budget.namespace_scope_bytes,
                    self.namespace_index_bytes,
                    &mut meter.namespace_scope_bytes,
                )?;
            } else {
                if self.raw_attributes.len() == self.raw_attributes.capacity() {
                    let additional = self.raw_attributes.capacity().max(4);
                    reserve_charged(self.raw_attributes, additional, meter)?;
                }
                self.raw_attributes
                    .push((name.into_owned(), value, attribute_type));
            }
        }

        Ok(())
    }

    fn default_attributes<
        'input,
        A: std::ops::Deref<Target = [xml_sec_xml_input::lexical::Attribute<'input>]>,
    >(
        &mut self,
        start: &xml_sec_xml_input::lexical::StartTag<'input, A>,
        declared_attributes: &[InternalAttributeDeclaration],
        declarations: &InternalEntityDeclarations,
        meter: &mut StreamParseMeter<'_>,
    ) -> Result<()> {
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
            meter.charge_owned(declaration.name.len())?;
            let value = prepare_stream_attribute_value(
                &declaration.name,
                default,
                &declarations.general,
                declaration.attribute_type.is_cdata(),
                meter,
            )?;
            if declaration.name == "xmlns" {
                validate_namespace_binding(None, &value)?;
                set_namespace_bounded(
                    self.namespaces,
                    self.namespace_index,
                    None,
                    value,
                    meter.budget.namespace_scope_bytes,
                    self.namespace_index_bytes,
                    &mut meter.namespace_scope_bytes,
                )?;
            } else if let Some(prefix) = declaration.name.strip_prefix("xmlns:") {
                validate_namespace_binding(Some(prefix), &value)?;
                set_namespace_bounded(
                    self.namespaces,
                    self.namespace_index,
                    Some(prefix.into()),
                    value,
                    meter.budget.namespace_scope_bytes,
                    self.namespace_index_bytes,
                    &mut meter.namespace_scope_bytes,
                )?;
            } else {
                if self.raw_attributes.len() == self.raw_attributes.capacity() {
                    let additional = self.raw_attributes.capacity().max(4);
                    reserve_charged(self.raw_attributes, additional, meter)?;
                }
                self.raw_attributes.push((
                    declaration.name.clone(),
                    value,
                    declaration.attribute_type,
                ));
            }
        }

        Ok(())
    }
}

struct StreamProjectedAttributes {
    attributes: Vec<Attribute>,
    first_id_attribute: Option<usize>,
    additional_id_attributes: Vec<usize>,
}

fn project_stream_attributes(
    raw_attributes: Vec<(String, String, InternalAttributeType)>,
    namespaces: &[Namespace],
    namespace_index: &HashMap<String, usize>,
    meter: &mut StreamParseMeter<'_>,
) -> Result<StreamProjectedAttributes> {
    let mut first_id_attribute = None;
    let mut additional_id_attributes = Vec::new();
    let mut attributes = Vec::new();
    reserve_charged(&mut attributes, raw_attributes.len(), meter)?;
    for (index, (lexical, value, attribute_type)) in raw_attributes.into_iter().enumerate() {
        meter.charge_owned(lexical.len())?;
        let (prefix, local) = split_lexical_name(&lexical)?;
        if let Some(position) = prefix
            .as_deref()
            .and_then(|prefix| namespace_index.get(prefix))
        {
            meter.charge_owned(namespaces[*position].uri.len())?;
        }
        let namespace = prefix
            .as_deref()
            .and_then(|prefix| namespace_for(namespaces, namespace_index, Some(prefix)));
        if prefix.is_some() && namespace.is_none() {
            return Err(Error::Xml(format!(
                "undeclared namespace prefix in attribute {lexical}"
            )));
        }
        if attribute_type.is_id() {
            if first_id_attribute.is_none() {
                first_id_attribute = Some(index);
            } else {
                if additional_id_attributes.len() == additional_id_attributes.capacity() {
                    let additional = additional_id_attributes.capacity().max(4);
                    reserve_charged(&mut additional_id_attributes, additional, meter)?;
                }
                additional_id_attributes.push(index);
            }
        }
        attributes.push(Attribute {
            name: ExpandedName::new(namespace, local),
            prefix,
            value,
        });
    }

    check_duplicate_attributes(&attributes, meter)?;
    Ok(StreamProjectedAttributes {
        attributes,
        first_id_attribute,
        additional_id_attributes,
    })
}

fn check_duplicate_attributes(
    attributes: &[Attribute],
    meter: &mut StreamParseMeter<'_>,
) -> Result<()> {
    // Borrow names instead of cloning every namespace/local string into the
    // duplicate detector. Admit its bucket bound before allocating it.
    if attributes.len() > 1 {
        let duplicate_bytes = attributes
            .len()
            .max(4)
            .checked_mul(2)
            .and_then(|slots| {
                slots.checked_mul(std::mem::size_of::<&ExpandedName>() + std::mem::size_of::<u64>())
            })
            .ok_or(Error::Budget {
                kind: BudgetKind::OwnedBytes,
                limit: meter.budget.owned_bytes,
                actual: usize::MAX,
            })?;
        meter.charge_owned(duplicate_bytes)?;
        let mut expanded_names = HashSet::with_capacity(attributes.len());
        if let Some(duplicate) = attributes
            .iter()
            .find(|attribute| !expanded_names.insert(&attribute.name))
        {
            return Err(Error::Xml(format!(
                "duplicate expanded attribute {{{}}}{}",
                duplicate.name.namespace.as_deref().unwrap_or(""),
                duplicate.name.local
            )));
        }
        drop(expanded_names);
        meter.release_owned(duplicate_bytes);
    }

    Ok(())
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
    finish_attribute_value(name, value, is_cdata)
}

fn prepare_stream_attribute_value(
    name: &str,
    raw: &str,
    entities: &HashMap<String, String>,
    is_cdata: bool,
    meter: &mut StreamParseMeter,
) -> Result<String> {
    // Entity expansion and attribute staging coexist with the retained tree.
    // Bound expansion by that remaining space, then admit normalization,
    // reference decoding and tokenized collapse before any of them allocate.
    let workspace = meter.entity_expansion.workspace;
    meter.entity_expansion.workspace = meter
        .budget
        .owned_bytes
        .saturating_sub(meter.owned_bytes)
        .saturating_sub(meter.namespace_scope_bytes);
    let expanded = expand_entity_references(
        raw,
        entities,
        0,
        &mut meter.entity_references,
        &mut meter.entity_expansion,
    );
    meter.entity_expansion.workspace = workspace;
    let expanded = expanded?;
    let staging = expanded.len().checked_mul(3).ok_or(Error::Budget {
        kind: BudgetKind::OwnedBytes,
        limit: meter.budget.owned_bytes,
        actual: usize::MAX,
    })?;
    meter.charge_owned(staging)?;
    finish_attribute_value(name, expanded, is_cdata)
}

fn finish_attribute_value(name: &str, value: Cow<'_, str>, is_cdata: bool) -> Result<String> {
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

fn event_range_start<A>(event: &xml_sec_xml_input::lexical::Event<'_, A>) -> usize {
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
        .split(super::lexical::is_xml_whitespace)
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
    elements: &[StreamElementFrame<'_>],
    value: ParsedText<'_>,
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
        reserve_parsed_string(existing, value.maximum_bytes(), meter)?;
        value.append(existing, meter)?;
        return Ok(last_child);
    }
    meter.reserve_node()?;
    let value = copy_parsed_text(value, meter)?;
    let inherited_base = copy_base_uri(document, parent, meter)?;
    push_metered(
        document,
        parent,
        NodeKind::Text {
            value,
            disable_output_escaping: false,
        },
        inherited_base,
        meter,
    )
}

fn split_lexical_name(name: &str) -> Result<(Option<String>, String)> {
    let (prefix, local) = name
        .split_once(':')
        .map_or((None, name), |(prefix, local)| (Some(prefix), local));
    if !super::lexical::is_ncname(local)
        || prefix.is_some_and(|prefix| !super::lexical::is_ncname(prefix))
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
    limit: usize,
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
    ensure(BudgetKind::NamespaceScopeBytes, limit, next)?;
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
        let declarations = collect_internal_entity_declarations(expanded_subset.as_ref(), meter)?;
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
                let held = declarations.owned_bytes;
                drop(declarations);
                meter.release_declarations(held);
                changed = true;
                rounds += 1;
                meter.check_depth(rounds)?;
                expanded_subset = Cow::Owned(next);
            }
        }
    };
    let mut header = doctype.start + "<!DOCTYPE".len();
    skip_xml_whitespace(xml, &mut header);
    parse_dtd_name(xml, &mut header, "DOCTYPE name")?;
    skip_xml_whitespace(xml, &mut header);
    let external_subset =
        xml[header..].starts_with("SYSTEM") || xml[header..].starts_with("PUBLIC");
    let standalone = if xml.trim_start_matches('\u{feff}').starts_with("<?xml") {
        matches!(
            Scanner::new(xml)
                .next_event()
                .map_err(|error| Error::Xml(error.to_string()))?,
            Some(Event::Declaration {
                standalone: Some(true),
                ..
            })
        )
    } else {
        false
    };
    let require_declared = standalone || (!external_subset && !changed);
    validate_unused_entity_graph(&declarations, require_declared, meter)?;
    validate_attribute_default_entities(&declarations, require_declared, meter)?;
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

fn validate_unused_entity_graph(
    declarations: &InternalEntityDeclarations,
    require_declared: bool,
    meter: &mut EntityExpansionMeter,
) -> Result<()> {
    // XML 1.0 Fifth Edition sections 4.1 (Entity Declared / No Recursion) and 5.1:
    // check declarations even when unused, but do not impose the validity-only declaration
    // constraint when an external subset/PE can supply bindings and standalone is not yes.
    // https://www.w3.org/TR/2008/REC-xml-20081126/#wf-entdeclared
    // https://www.w3.org/TR/2008/REC-xml-20081126/#norecursion
    type Entry<'a> = (&'a str, &'a str, usize, u8);
    let count = declarations.general.len();
    meter.charge(count.saturating_mul(std::mem::size_of::<Entry<'_>>()))?;
    let mut entries: Vec<Entry<'_>> = Vec::with_capacity(count);
    entries.extend(
        declarations
            .general
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str(), 0, 0)),
    );
    entries.sort_unstable_by_key(|entry| entry.0);
    // Iterative, memoized DFS: visit each replacement once without expanding its text.
    let mut active = [0usize; ENTITY_EXPANSION_DEPTH_CEILING];
    for root in 0..entries.len() {
        if entries[root].3 != 0 {
            continue;
        }
        meter.check_depth(1)?;
        entries[root].3 = 1;
        active[0] = root;
        let mut depth = 1;
        while depth != 0 {
            let index = active[depth - 1];
            let (_, value, cursor, _) = entries[index];
            let Some(offset) = value[cursor..].find('&') else {
                entries[index].3 = 2;
                depth -= 1;
                continue;
            };
            let start = cursor + offset;
            let (name, consumed) = general_entity_reference(&value[start..])
                .ok_or_else(|| Error::Xml("invalid entity reference in declaration".into()))?;
            entries[index].2 = start + consumed;
            if name.starts_with('#') || matches!(name, "amp" | "lt" | "gt" | "apos" | "quot") {
                continue;
            }
            if declarations.unparsed.contains_key(name) {
                return Err(Error::Xml(format!(
                    "reference to unparsed entity `&{name};`"
                )));
            }
            let Ok(target) = entries.binary_search_by_key(&name, |entry| entry.0) else {
                if require_declared && !declarations.declared_general.contains(name) {
                    return Err(Error::Xml(format!("undeclared entity `&{name};`")));
                }
                continue;
            };
            match entries[target].3 {
                1 => return Err(Error::Xml(format!("recursive entity reference `&{name};`"))),
                2 => continue,
                _ => {}
            }
            meter.check_depth(depth + 1)?;
            entries[target].3 = 1;
            active[depth] = target;
            depth += 1;
        }
    }
    Ok(())
}

fn validate_attribute_default_entities(
    declarations: &InternalEntityDeclarations,
    require_declared: bool,
    meter: &mut EntityExpansionMeter,
) -> Result<()> {
    let external_reachability = parsed_external_reachability(declarations, meter)?;
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
            if !name.starts_with('#') && !matches!(name, "amp" | "apos" | "gt" | "lt" | "quot") {
                if declarations.parsed_external.contains(name)
                    || external_reachability
                        .binary_search_by_key(&name, |entry| entry.0)
                        .is_ok_and(|index| external_reachability[index].4)
                {
                    // XML 1.0 Fifth Edition section 3.1 forbids direct and indirect external
                    // entity references in attribute values, including declaration defaults.
                    // https://www.w3.org/TR/2008/REC-xml-20081126/#NoExternalRefs
                    return Err(Error::Xml(format!(
                        "ATTLIST default references parsed external entity through `&{name};`"
                    )));
                }
                if require_declared && !declarations.declared_general.contains(name) {
                    return Err(Error::Xml(format!(
                        "ATTLIST default references undeclared entity `&{name};`"
                    )));
                }
            }
            cursor = start + consumed;
        }
    }
    Ok(())
}

type EntityReachabilityEntry<'a> = (&'a str, &'a str, usize, u8, bool);

fn parsed_external_reachability<'a>(
    declarations: &'a InternalEntityDeclarations,
    meter: &mut EntityExpansionMeter,
) -> Result<Vec<EntityReachabilityEntry<'a>>> {
    let count = declarations.general.len();
    meter.charge(count.saturating_mul(std::mem::size_of::<EntityReachabilityEntry<'_>>()))?;
    let mut entries: Vec<EntityReachabilityEntry<'_>> = Vec::with_capacity(count);
    entries.extend(
        declarations
            .general
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str(), 0, 0, false)),
    );
    entries.sort_unstable_by_key(|entry| entry.0);
    let mut active = [0usize; ENTITY_EXPANSION_DEPTH_CEILING];
    for root in 0..entries.len() {
        if entries[root].3 != 0 {
            continue;
        }
        entries[root].3 = 1;
        active[0] = root;
        let mut depth = 1usize;
        while depth != 0 {
            let index = active[depth - 1];
            let (_, value, cursor, _, _) = entries[index];
            let Some(offset) = value[cursor..].find('&') else {
                entries[index].3 = 2;
                depth -= 1;
                if depth != 0 && entries[index].4 {
                    entries[active[depth - 1]].4 = true;
                }
                continue;
            };
            let start = cursor + offset;
            let (dependency, consumed) = general_entity_reference(&value[start..])
                .ok_or_else(|| Error::Xml("invalid entity reference in declaration".into()))?;
            entries[index].2 = start + consumed;
            if dependency.starts_with('#')
                || matches!(dependency, "amp" | "apos" | "gt" | "lt" | "quot")
            {
                continue;
            }
            if declarations.parsed_external.contains(dependency) {
                entries[index].4 = true;
                continue;
            }
            let Ok(target) = entries.binary_search_by_key(&dependency, |entry| entry.0) else {
                continue;
            };
            if entries[target].3 == 2 {
                if entries[target].4 {
                    entries[index].4 = true;
                }
                continue;
            }
            debug_assert_eq!(entries[target].3, 0, "entity cycles were rejected earlier");
            meter.check_depth(depth + 1)?;
            entries[target].3 = 1;
            active[depth] = target;
            depth += 1;
        }
    }
    Ok(entries)
}

#[derive(Default)]
struct InternalEntityDeclarations {
    owned_bytes: usize,
    general: HashMap<String, String>,
    parameter: HashMap<String, String>,
    parameter_spans: Vec<(usize, usize)>,
    attributes: HashMap<String, Vec<InternalAttributeDeclaration>>,
    unparsed: HashMap<String, String>,
    declared_general: HashSet<String>,
    parsed_external: HashSet<String>,
}

struct InternalAttributeDeclaration {
    name: String,
    attribute_type: InternalAttributeType,
    default: Option<String>,
}

// Declaration storage is live until expansion and default-attribute processing
// finish. It shares the parser's workspace, but is not entity expansion output.
struct DeclarationAllocation<'a, 'w> {
    expansion: &'a mut EntityExpansionMeter<'w>,
    owned: &'a mut usize,
}

impl ParseAllocationBudget for DeclarationAllocation<'_, '_> {
    fn owned_limit(&self) -> usize {
        self.expansion.workspace_maximum
    }
    fn charge_owned(&mut self, bytes: usize) -> Result<()> {
        self.expansion.check_workspace(bytes)?;
        self.expansion.charge_parse_work(bytes)?;
        self.expansion.declaration_bytes += bytes;
        *self.owned += bytes;
        Ok(())
    }
    fn release_owned(&mut self, bytes: usize) {
        self.expansion.release_declarations(bytes);
        *self.owned = self
            .owned
            .checked_sub(bytes)
            .expect("admitted declaration storage");
    }
}

fn declaration_string(value: &str, budget: &mut impl ParseAllocationBudget) -> Result<String> {
    budget.charge_owned(value.len())?;
    Ok(value.to_owned())
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

fn collect_internal_entity_declarations(
    subset: &str,
    meter: &mut EntityExpansionMeter,
) -> Result<InternalEntityDeclarations> {
    let mut declarations = InternalEntityDeclarations::default();
    let mut cursor = 0;
    while cursor < subset.len() {
        if subset[cursor..]
            .chars()
            .next()
            .is_some_and(super::lexical::is_xml_whitespace)
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
            cursor = collect_internal_attribute_list(subset, cursor, &mut declarations, meter)?;
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
        cursor = collect_entity_declaration(subset, cursor, &mut declarations, meter)?;
    }
    #[cfg(test)]
    expansion_workspace_tests::observe_declarations(&declarations);
    Ok(declarations)
}
fn collect_entity_declaration(
    subset: &str,
    mut cursor: usize,
    declarations: &mut InternalEntityDeclarations,
    meter: &mut EntityExpansionMeter<'_>,
) -> Result<usize> {
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
        record_external_entity(declarations, meter, name, parameter, system_identifier)?;
        cursor = end;
        return Ok(cursor);
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
    let raw_value = &subset[value_start..cursor];
    cursor += 1;
    validate_entity_value(name, raw_value, parameter)?;
    // XML 1.0 Fifth Edition section 4.2, [70]-[74], permits only XML S before `>`
    // after an internal EntityValue, for both general and parameter entities.
    // https://www.w3.org/TR/2008/REC-xml-20081126/#sec-entity-decl
    skip_xml_whitespace(subset, &mut cursor);
    if subset.as_bytes().get(cursor) != Some(&b'>') {
        return Err(Error::Xml(format!(
            "entity declaration `{name}` has content after its definition"
        )));
    }
    cursor += 1;

    record_internal_entity(
        declarations,
        meter,
        name,
        raw_value,
        parameter,
        (declaration_start, cursor),
    )?;
    Ok(cursor)
}

fn record_external_entity(
    declarations: &mut InternalEntityDeclarations,
    meter: &mut EntityExpansionMeter<'_>,
    name: &str,
    parameter: bool,
    system_identifier: Option<&str>,
) -> Result<()> {
    if !parameter && !declarations.declared_general.contains(name) {
        let mut allocation = DeclarationAllocation {
            expansion: meter,
            owned: &mut declarations.owned_bytes,
        };
        reserve_index_entry(&mut declarations.declared_general, 0, &mut allocation)?;
        declarations
            .declared_general
            .insert(declaration_string(name, &mut allocation)?);
        if let Some(system_identifier) = system_identifier {
            reserve_index_entry(&mut declarations.unparsed, 0, &mut allocation)?;
            let name = declaration_string(name, &mut allocation)?;
            let identifier = declaration_string(system_identifier, &mut allocation)?;
            declarations.unparsed.insert(name, identifier);
        } else {
            reserve_index_entry(&mut declarations.parsed_external, 0, &mut allocation)?;
            declarations
                .parsed_external
                .insert(declaration_string(name, &mut allocation)?);
        }
    }
    Ok(())
}

fn record_internal_entity(
    declarations: &mut InternalEntityDeclarations,
    meter: &mut EntityExpansionMeter<'_>,
    name: &str,
    raw_value: &str,
    parameter: bool,
    declaration_span: (usize, usize),
) -> Result<()> {
    let mut allocation = DeclarationAllocation {
        expansion: meter,
        owned: &mut declarations.owned_bytes,
    };
    if parameter {
        if declarations.parameter_spans.len() == declarations.parameter_spans.capacity() {
            let additional = declarations.parameter_spans.capacity().max(4);
            reserve_charged(
                &mut declarations.parameter_spans,
                additional,
                &mut allocation,
            )?;
        }
        declarations.parameter_spans.push(declaration_span);
    }
    let duplicate = if parameter {
        declarations.parameter.contains_key(name)
    } else {
        declarations.declared_general.contains(name)
    };
    let predefined = !parameter && matches!(name, "amp" | "apos" | "gt" | "lt" | "quot");
    if duplicate && !predefined {
        return Ok(());
    }
    let value = if parameter {
        declaration_string(raw_value, &mut allocation)?
    } else if predefined {
        let scratch = raw_value.len().checked_mul(2).ok_or(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            limit: allocation.owned_limit(),
            actual: usize::MAX,
        })?;
        allocation.charge_owned(scratch)?;
        let value = normalize_predefined_entity_declaration(name, raw_value)?;
        allocation.release_owned(scratch - value.capacity());
        value
    } else {
        // XML 1.0 section 4.5 constructs replacement text by expanding character
        // references, but leaves general references for their eventual context.
        // https://www.w3.org/TR/xml/#intern-replacement
        match decode_parameter_character_references_in(raw_value, |bytes| {
            allocation.expansion.check(bytes)?;
            allocation.charge_owned(bytes)
        })? {
            Cow::Owned(value) => value,
            Cow::Borrowed(value) => declaration_string(value, &mut allocation)?,
        }
    };
    if duplicate {
        let capacity = value.capacity();
        drop(value);
        allocation.release_owned(capacity);
        return Ok(());
    }
    if parameter {
        reserve_index_entry(&mut declarations.parameter, 0, &mut allocation)?;
        declarations
            .parameter
            .entry(declaration_string(name, &mut allocation)?)
            .or_insert(value);
    } else {
        reserve_index_entry(&mut declarations.declared_general, 0, &mut allocation)?;
        declarations
            .declared_general
            .insert(declaration_string(name, &mut allocation)?);
        reserve_index_entry(&mut declarations.general, 0, &mut allocation)?;
        declarations
            .general
            .insert(declaration_string(name, &mut allocation)?, value);
    }
    Ok(())
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
                super::lexical::is_xml_whitespace(character) || character == '>'
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
                // XML 1.0 Fifth Edition section 3.2.1 productions [49] and [50]: choices require
                // two particles, while sequences admit one because their comma tail is `*`.
                // https://www.w3.org/TR/2008/REC-xml-20081126/#sec-element-content
                if group.items == 0
                    || group.expects_item
                    || (group.connector == Some(b'|') && group.items < 2)
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
    declarations: &mut InternalEntityDeclarations,
    meter: &mut EntityExpansionMeter,
) -> Result<usize> {
    cursor += "<!ATTLIST".len();
    require_dtd_whitespace(subset, &mut cursor, "after <!ATTLIST")?;
    let element_name = parse_dtd_name(subset, &mut cursor, "ATTLIST element")?;
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
        let name = parse_dtd_name(subset, &mut cursor, "ATTLIST attribute")?;
        require_dtd_whitespace(subset, &mut cursor, "after ATTLIST attribute name")?;
        let attribute_type = parse_dtd_attribute_type(subset, &mut cursor)?;
        require_dtd_whitespace(subset, &mut cursor, "before ATTLIST default declaration")?;
        let default = parse_dtd_attribute_default(subset, &mut cursor)?;
        let mut allocation = DeclarationAllocation {
            expansion: meter,
            owned: &mut declarations.owned_bytes,
        };
        if !declarations.attributes.contains_key(element_name) {
            reserve_index_entry(&mut declarations.attributes, 0, &mut allocation)?;
            let key = declaration_string(element_name, &mut allocation)?;
            declarations.attributes.insert(key, Vec::new());
        }
        let element_declarations = declarations
            .attributes
            .get_mut(element_name)
            .expect("inserted declaration group");
        if !element_declarations
            .iter()
            .any(|declaration| declaration.name == name)
        {
            if element_declarations.len() == element_declarations.capacity() {
                let additional = element_declarations.capacity().max(4);
                reserve_charged(element_declarations, additional, &mut allocation)?;
            }
            let name = declaration_string(name, &mut allocation)?;
            let default = default
                .map(|value| declaration_string(value, &mut allocation))
                .transpose()?;
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
            .is_some_and(super::lexical::is_xml_whitespace)
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
        && (character == ':' || super::lexical::is_ncname_char(character))
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

fn parse_dtd_attribute_default<'a>(subset: &'a str, cursor: &mut usize) -> Result<Option<&'a str>> {
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
    Ok(Some(value))
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
        let valid = if let Some(reference) = reference.strip_prefix('#') {
            valid_xml_character_reference(reference)
        } else {
            super::lexical::is_xml_name(reference)
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
        // XML 1.0 Fifth Edition section 4.2 [71]/[74]: an unquoted definition must
        // be ExternalID, not an arbitrary token ignored until the closing bracket.
        // https://www.w3.org/TR/2008/REC-xml-20081126/#sec-entity-decl
        return Err(Error::Xml(
            "entity definition must be a quoted value, SYSTEM, or PUBLIC".into(),
        ));
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
        && (character == ':' || super::lexical::is_ncname_char(character))
    {
        *cursor += character.len_utf8();
    }
    let name = &subset[start..*cursor];
    if super::lexical::is_xml_name(name) {
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
    // This collector reads only the internal subset. XML 1.0 section 2.8 WFC PEs
    // in Internal Subset forbids PE references inside declarations, including literals.
    // https://www.w3.org/TR/xml/#wfc-PEinInternalSubset
    if value.contains('%') {
        return Err(Error::Xml(format!(
            "parameter entity reference inside internal entity declaration `{name}`"
        )));
    }
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
        if !super::lexical::is_xml10_character(character) {
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
                super::lexical::is_xml_name(reference)
            } else if let Some(reference) = reference.strip_prefix('#') {
                valid_xml_character_reference(reference)
            } else {
                super::lexical::is_xml_name(reference)
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

fn valid_xml_character_reference(reference: &str) -> bool {
    xml_sec_xml_input::lexical::decode_numeric_character_reference(reference).is_ok()
}

fn normalize_predefined_entity_declaration(name: &str, value: &str) -> Result<String> {
    let (expected, required_replacement) = match name {
        "amp" => ('&', Some("&#38;")),
        "apos" => ('\'', None),
        "gt" => ('>', None),
        "lt" => ('<', Some("&#60;")),
        "quot" => ('"', None),
        _ => return Ok(value.to_owned()),
    };
    let first = xml_sec_xml_input::lexical::decode_references(value)
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
    entities: &'a HashMap<String, String>,
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
    let mut active = [""; ENTITY_EXPANSION_DEPTH_CEILING];
    let context = ParameterEntityExpansion {
        entities,
        reject_unresolved,
    };
    let mut cursor = 0;
    for &(start, end) in excluded_declarations {
        expand_parameter_entity_references_into(
            &value[cursor..start],
            &context,
            depth,
            references,
            meter,
            &mut output,
            &mut active,
        )?;
        cursor = end;
    }
    expand_parameter_entity_references_into(
        &value[cursor..],
        &context,
        depth,
        references,
        meter,
        &mut output,
        &mut active,
    )?;
    Ok(Cow::Owned(output))
}

struct ParameterEntityExpansion<'entities> {
    entities: &'entities HashMap<String, String>,
    reject_unresolved: bool,
}

fn expand_parameter_entity_references_into<'entities>(
    value: &str,
    context: &ParameterEntityExpansion<'entities>,
    depth: usize,
    references: &mut usize,
    meter: &mut EntityExpansionMeter,
    output: &mut String,
    active: &mut [&'entities str; ENTITY_EXPANSION_DEPTH_CEILING],
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
                .is_some_and(super::lexical::is_xml_whitespace)
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
            if !super::lexical::is_xml_name(name) {
                return Err(Error::Xml("invalid parameter entity reference name".into()));
            }
            if let Some((entity_name, replacement)) = context.entities.get_key_value(name) {
                meter.charge_reference(references)?;
                // XML 1.0 section 4.1 WFC No Recursion makes direct and indirect recursive entity
                // references fatal independently of caller-selected resource budgets.
                // https://www.w3.org/TR/xml/#norecursion
                if active[..depth].contains(&name) {
                    return Err(Error::Xml(format!(
                        "recursive parameter entity reference `%{name};`"
                    )));
                }
                meter.check_depth(depth + 1)?;
                active[depth] = entity_name;
                let replacement = decode_parameter_character_references(replacement, meter)?;
                let result = expand_parameter_entity_references_into(
                    replacement.as_ref(),
                    context,
                    depth + 1,
                    references,
                    meter,
                    output,
                    active,
                );
                active[depth] = "";
                result?;
                cursor += end + 2;
                continue;
            }
            if context.reject_unresolved {
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
    decode_parameter_character_references_in(value, |bytes| meter.check(bytes))
}

fn decode_parameter_character_references_in(
    value: &str,
    admit: impl FnOnce(usize) -> Result<()>,
) -> Result<Cow<'_, str>> {
    if !value.as_bytes().windows(2).any(|bytes| bytes == b"&#") {
        return Ok(Cow::Borrowed(value));
    }
    admit(value.len())?;
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
        let character =
            xml_sec_xml_input::lexical::decode_numeric_character_reference(reference)
                .map_err(|_| Error::Xml("invalid parameter entity character reference".into()))?;
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

fn skip_xml_whitespace(value: &str, cursor: &mut usize) {
    while let Some(character) = value[*cursor..].chars().next()
        && super::lexical::is_xml_whitespace(character)
    {
        *cursor += character.len_utf8();
    }
}

fn expand_document_entities<'a>(
    xml: &'a str,
    entities: &'a HashMap<String, String>,
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
    let mut active = [""; ENTITY_EXPANSION_DEPTH_CEILING];
    meter.append(&mut expanded, &xml[..doctype_end])?;
    let mut position = DocumentEntityPosition::BeforeElement;
    expand_entity_references_into(
        &xml[doctype_end..],
        entities,
        0,
        references,
        meter,
        &mut EntityExpansionOutput {
            value: &mut expanded,
            document_position: Some(&mut position),
            entity_nesting: None,
        },
        &mut active,
    )?;
    Ok(Cow::Owned(expanded))
}

fn expand_entity_references<'a>(
    value: &'a str,
    entities: &'a HashMap<String, String>,
    depth: usize,
    references: &mut usize,
    meter: &mut EntityExpansionMeter,
) -> Result<Cow<'a, str>> {
    if entities.is_empty() || !contains_expandable_entity_reference(value, entities) {
        return Ok(Cow::Borrowed(value));
    }
    meter.check(value.len())?;
    let mut output = String::with_capacity(value.len());
    let mut active = [""; ENTITY_EXPANSION_DEPTH_CEILING];
    expand_entity_references_into(
        value,
        entities,
        depth,
        references,
        meter,
        &mut EntityExpansionOutput {
            value: &mut output,
            document_position: None,
            entity_nesting: None,
        },
        &mut active,
    )?;
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

enum DocumentEntityPosition {
    BeforeElement,
    Content(usize),
    AfterElement,
}

impl DocumentEntityPosition {
    fn permits_reference(&self) -> bool {
        matches!(self, Self::Content(_))
    }

    fn observe_markup(&mut self, markup: &str) {
        if markup.starts_with("<!--")
            || markup.starts_with("<![CDATA[")
            || markup.starts_with("<?")
            || markup.starts_with("<!")
        {
            return;
        }
        if markup.starts_with("</") {
            if let Self::Content(depth) = self {
                if *depth == 1 {
                    *self = Self::AfterElement;
                } else {
                    *depth -= 1;
                }
            }
            return;
        }
        let empty = markup[..markup.len() - 1].trim_end().ends_with('/');
        match self {
            Self::BeforeElement if empty => *self = Self::AfterElement,
            Self::BeforeElement => *self = Self::Content(1),
            Self::Content(depth) if !empty => *depth += 1,
            Self::Content(_) | Self::AfterElement => {}
        }
    }
}

struct EntityExpansionOutput<'output, 'position> {
    value: &'output mut String,
    document_position: Option<&'position mut DocumentEntityPosition>,
    entity_nesting: Option<&'position mut EntityMarkupNesting>,
}

#[derive(Default)]
struct EntityMarkupNesting {
    depth: usize,
}

impl EntityMarkupNesting {
    fn observe_markup(&mut self, markup: &str) -> Result<()> {
        if markup.starts_with("<!--")
            || markup.starts_with("<![CDATA[")
            || markup.starts_with("<?")
            || markup.starts_with("<!")
        {
            return Ok(());
        }
        if markup.starts_with("</") {
            self.depth = self.depth.checked_sub(1).ok_or_else(|| {
                Error::Xml("entity replacement closes markup opened outside the entity".into())
            })?;
        } else if !markup[..markup.len() - 1].trim_end().ends_with('/') {
            self.depth += 1;
        }
        Ok(())
    }
}

fn expand_entity_references_into<'entities>(
    value: &str,
    entities: &'entities HashMap<String, String>,
    depth: usize,
    references: &mut usize,
    meter: &mut EntityExpansionMeter,
    output: &mut EntityExpansionOutput<'_, '_>,
    active: &mut [&'entities str; ENTITY_EXPANSION_DEPTH_CEILING],
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
            let markup = &tail[..length];
            if let Some(position) = output.document_position.as_deref_mut() {
                position.observe_markup(markup);
            }
            if let Some(nesting) = output.entity_nesting.as_deref_mut() {
                nesting.observe_markup(markup)?;
            }
            meter.append(output.value, markup)?;
            cursor += length;
            continue;
        }
        if tail.starts_with('<')
            && let Some(length) = xml_markup_len(tail)
        {
            let markup = &tail[..length];
            if let Some(position) = output.document_position.as_deref_mut() {
                position.observe_markup(markup);
            }
            if let Some(nesting) = output.entity_nesting.as_deref_mut() {
                nesting.observe_markup(markup)?;
            }
            meter.append(output.value, markup)?;
            cursor += length;
            continue;
        }
        if let Some((name, consumed)) = general_entity_reference(tail)
            && let Some((entity_name, replacement)) = entities.get_key_value(name)
        {
            if output
                .document_position
                .as_deref()
                .is_some_and(|position| !position.permits_reference())
            {
                // XML 1.0 production [1] permits content only inside the document element;
                // prolog and trailing Misc cannot contain general entity references.
                // https://www.w3.org/TR/xml/#sec-well-formed
                return Err(Error::Xml(format!(
                    "entity reference `&{name};` is outside the document element"
                )));
            }
            meter.charge_reference(references)?;
            // XML 1.0 section 4.1 WFC No Recursion rejects cycles as malformed XML rather than
            // reporting them as exhaustion of a caller-selected recursion budget.
            // https://www.w3.org/TR/xml/#norecursion
            if active[..depth].contains(&name) {
                return Err(Error::Xml(format!("recursive entity reference `&{name};`")));
            }
            meter.check_depth(depth + 1)?;
            active[depth] = entity_name;
            let mut entity_nesting = EntityMarkupNesting::default();
            let result = expand_entity_references_into(
                replacement,
                entities,
                depth + 1,
                references,
                meter,
                &mut EntityExpansionOutput {
                    value: output.value,
                    document_position: output.document_position.as_deref_mut(),
                    entity_nesting: Some(&mut entity_nesting),
                },
                active,
            );
            active[depth] = "";
            result?;
            if entity_nesting.depth != 0 {
                return Err(Error::Xml(
                    "entity replacement leaves markup open across the entity boundary".into(),
                ));
            }
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
        meter.append(output.value, &tail[..plain_end])?;
        cursor += plain_end;
    }
    Ok(())
}

struct EntityExpansionMeter<'w> {
    kind: BudgetKind,
    limit: usize,
    used: usize,
    reference_limit: usize,
    depth_limit: usize,
    workspace: usize,
    workspace_maximum: usize,
    declaration_bytes: usize,
    parse_work: Option<&'w mut ParseWork>,
}

impl EntityExpansionMeter<'_> {
    #[cfg(test)]
    const fn new(limit: usize) -> Self {
        Self::with_reference_limit(limit, usize::MAX)
    }

    #[cfg(test)]
    const fn with_reference_limit(limit: usize, reference_limit: usize) -> Self {
        Self::with_limits(
            BudgetKind::EntityExpansionBytes,
            limit,
            reference_limit,
            ENTITY_EXPANSION_DEPTH_CEILING,
        )
    }

    const fn with_parse_budget(budget: ParseBudget) -> Self {
        let mut meter = Self::with_limits(
            BudgetKind::EntityExpansionBytes,
            if budget.entity_expansion_bytes < ENTITY_EXPANSION_BYTE_CEILING {
                budget.entity_expansion_bytes
            } else {
                ENTITY_EXPANSION_BYTE_CEILING
            },
            budget.entity_references,
            if budget.recursion_depth < ENTITY_EXPANSION_DEPTH_CEILING {
                budget.recursion_depth
            } else {
                ENTITY_EXPANSION_DEPTH_CEILING
            },
        );
        meter.workspace = budget.owned_bytes;
        meter.workspace_maximum = budget.owned_bytes;
        meter
    }

    const fn with_limits(
        kind: BudgetKind,
        limit: usize,
        reference_limit: usize,
        depth_limit: usize,
    ) -> Self {
        Self {
            kind,
            limit,
            used: 0,
            reference_limit,
            depth_limit,
            workspace: usize::MAX,
            workspace_maximum: usize::MAX,
            declaration_bytes: 0,
            parse_work: None,
        }
    }

    fn check_depth(&self, actual: usize) -> Result<()> {
        // XML 1.0 section 4.4.2 defines recursive inclusion without a fixed depth ceiling. The
        // caller's recursion budget governs it; the internal clamp only protects native frames.
        // https://www.w3.org/TR/xml/#included
        super::budget::ensure(super::BudgetKind::RecursionDepth, self.depth_limit, actual)
    }

    fn check_workspace(&self, additional: usize) -> Result<()> {
        let actual = self
            .used
            .saturating_add(self.declaration_bytes)
            .saturating_add(additional);
        if actual > self.workspace {
            return Err(Error::Budget {
                kind: BudgetKind::OwnedBytes,
                limit: self.workspace_maximum,
                actual: self
                    .workspace_maximum
                    .saturating_sub(self.workspace)
                    .saturating_add(actual),
            });
        }
        Ok(())
    }

    fn release_declarations(&mut self, bytes: usize) {
        self.declaration_bytes = self
            .declaration_bytes
            .checked_sub(bytes)
            .expect("released declarations were admitted");
    }

    fn charge_reference(&self, references: &mut usize) -> Result<()> {
        let actual = references.saturating_add(1);
        super::budget::ensure(
            super::BudgetKind::EntityReferences,
            self.reference_limit,
            actual,
        )?;
        *references = actual;
        Ok(())
    }

    fn append(&mut self, output: &mut String, value: &str) -> Result<()> {
        self.charge(value.len())?;
        #[cfg(test)]
        expansion_workspace_tests::APPENDED.with(|bytes| bytes.set(bytes.get() + value.len()));
        let needed = output.len().checked_add(value.len()).ok_or(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            limit: self.workspace,
            actual: usize::MAX,
        })?;
        if needed > output.capacity() {
            // A growing string can briefly hold its old and replacement blocks.
            // Admit that peak before asking the allocator, not after materializing it.
            let capacity = needed.max(output.capacity().saturating_mul(2));
            self.check_workspace(capacity)?;
            output
                .try_reserve_exact(capacity - output.len())
                .map_err(|_| Error::Budget {
                    kind: BudgetKind::OwnedBytes,
                    limit: self.workspace,
                    actual: capacity,
                })?;
        }
        output.push_str(value);
        Ok(())
    }

    fn check(&self, amount: usize) -> Result<()> {
        let actual = self.used.saturating_add(amount);
        self.check_workspace(amount)?;
        super::budget::ensure(self.kind, self.limit, actual)
    }

    fn charge(&mut self, amount: usize) -> Result<()> {
        let actual = self.used.saturating_add(amount);
        self.check_workspace(amount)?;
        super::budget::ensure(self.kind, self.limit, actual)?;
        self.charge_parse_work(amount)?;
        self.used = actual;
        Ok(())
    }

    fn charge_parse_work(&mut self, amount: usize) -> Result<()> {
        if let Some(work) = &mut self.parse_work {
            work.charge(amount)?;
        }
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
            .and_then(roxmltree::Namespace::name)
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

#[cfg(all(test, not(feature = "embedded")))]
mod parser_boundary_tests;

#[cfg(test)]
mod expansion_workspace_tests {
    use super::*;
    thread_local! { pub(super) static APPENDED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
    thread_local! { pub(super) static SCANNED_ATTRIBUTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
    thread_local! { pub(super) static NORMALIZED_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
    thread_local! { pub(super) static CREATED_ROOTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
    thread_local! { static DECLARATION_BYTES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

    pub(super) fn observe_declarations(declarations: &InternalEntityDeclarations) {
        let mut bytes = 0;
        for map in [
            &declarations.general,
            &declarations.parameter,
            &declarations.unparsed,
        ] {
            bytes += map.capacity()
                * (std::mem::size_of::<(String, String)>() + std::mem::size_of::<u64>());
            bytes += map
                .iter()
                .map(|(name, value)| name.capacity() + value.capacity())
                .sum::<usize>();
        }
        for set in [
            &declarations.declared_general,
            &declarations.parsed_external,
        ] {
            bytes += set.capacity() * (std::mem::size_of::<String>() + std::mem::size_of::<u64>());
            bytes += set.iter().map(String::capacity).sum::<usize>();
        }
        bytes += declarations.parameter_spans.capacity() * std::mem::size_of::<(usize, usize)>();
        bytes += declarations.attributes.capacity()
            * (std::mem::size_of::<(String, Vec<InternalAttributeDeclaration>)>()
                + std::mem::size_of::<u64>());
        for (name, attributes) in &declarations.attributes {
            bytes += name.capacity()
                + attributes.capacity() * std::mem::size_of::<InternalAttributeDeclaration>();
            bytes += attributes
                .iter()
                .map(|attribute| {
                    attribute.name.capacity()
                        + attribute.default.as_ref().map_or(0, String::capacity)
                })
                .sum::<usize>();
        }
        DECLARATION_BYTES.with(|peak| peak.set(peak.get().max(bytes)));
    }

    include!("model/expansion_workspace_tests.rs");
}
