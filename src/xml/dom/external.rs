//! The semantic arena built from an external tree's events instead of a parse.
//!
//! An external tree (a libxml2 document, for one) walks itself in document
//! order and reports each node to [`TreeSink`]. The sink enforces the same
//! node, depth, namespace, byte and entity limits a parse enforces and builds
//! the arena every XML Security algorithm reads, so the tree is never
//! serialized and parsed again.

use alloc::{string::String, vec::Vec};

use super::storage::{Native, Storage, Values};
use super::tree::{AttributeData, NamespaceData, NamespaceSet, NodeId, NodeKind, TreeBuilder};
use super::{Document, LexicalPreflight, ParseError};

/// Ceilings a projection enforces, taken from the operation's policy.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ProjectionLimits {
    pub(crate) nodes: u32,
    pub(crate) depth: usize,
    pub(crate) namespace_bindings: usize,
    pub(crate) bytes: usize,
    pub(crate) allow_dtd: bool,
}

/// What a projection measured, for the document's later policy checks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProjectionMetrics {
    pub(crate) max_depth: usize,
    pub(crate) peak_namespace_bindings: usize,
    pub(crate) bytes: usize,
    pub(crate) has_dtd: bool,
}

/// Opaque reference to one node of an external tree, owned by that tree.
///
/// The core never interprets it; it is handed back to the tree for edits and
/// serialization and is meaningful only while the projection that recorded it
/// is current.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExternalNode(pub u64);

/// The text nodes the projection joined from adjacent tree text (text and
/// CDATA, XML 1.0 has no boundary between them): for each, its arena
/// position and the tree nodes of the run in order, `None` for text an
/// entity expansion produced. Sorted by position, since a joined node is
/// always the last one built.
pub(crate) type TextRuns = Vec<(usize, Vec<Option<ExternalNode>>)>;

/// A finished projection: the document, the tree node of each arena node
/// (`None` where none corresponds alone), the joined text runs and the
/// projection's measurements.
pub(crate) struct Projection<'input> {
    pub(crate) document: Document<'input>,
    pub(crate) nodes: Vec<Option<ExternalNode>>,
    pub(crate) runs: TextRuns,
    pub(crate) metrics: ProjectionMetrics,
}

/// An element whose start tag is being reported.
struct Pending {
    node: ExternalNode,
    name: String,
    prefix: Option<String>,
    namespace: Option<String>,
    attributes: Vec<AttributeData<Native>>,
}

/// Receives an external tree in document order and builds its semantic arena.
///
/// Call order: [`Self::document_type`] at most once before the first node;
/// then for each element [`Self::begin_element`], any number of
/// [`Self::declare_namespace`] and [`Self::attribute`], [`Self::open_element`],
/// its content, and [`Self::end_element`]; text, comments and processing
/// instructions anywhere inside the document element or around it. Content
/// that an entity reference expands to is reported between
/// [`Self::enter_entity`] and [`Self::leave_entity`]. A call out of order is
/// refused with an error naming it.
pub struct TreeSink<'input> {
    tree: TreeBuilder<'input, Native>,
    open: Vec<NodeId>,
    nodes: Vec<Option<ExternalNode>>,
    runs: TextRuns,
    pending: Option<Pending>,
    /// The current start tag's declarations; reused from element to element.
    declarations: Vec<(Option<String>, String)>,
    limits: ProjectionLimits,
    metrics: ProjectionMetrics,
    entity_depth: usize,
    entity_expansions: u32,
    started: bool,
}

const SOURCE: &str = "external-tree";

fn misuse(message: &str) -> ParseError {
    ParseError::Backend {
        backend: SOURCE,
        message: message.into(),
    }
}

impl<'input> TreeSink<'input> {
    pub(crate) fn new(
        input: &'input str,
        document: ExternalNode,
        limits: ProjectionLimits,
    ) -> Result<Self, ParseError> {
        if limits.nodes == 0 {
            return Err(ParseError::NodesLimitReached);
        }
        let mut tree = TreeBuilder::new(input, 0, Native)?;
        let root = tree.push(None, NodeKind::Root, 0..0)?;
        Ok(Self {
            tree,
            open: alloc::vec![root],
            nodes: alloc::vec![Some(document)],
            runs: Vec::new(),
            pending: None,
            declarations: Vec::new(),
            limits,
            metrics: ProjectionMetrics::default(),
            entity_depth: 0,
            entity_expansions: 0,
            started: false,
        })
    }

    /// Report that the document has a document type declaration.
    ///
    /// # Errors
    /// [`ParseError::DtdDetected`] when the policy does not allow one.
    pub fn document_type(&mut self) -> Result<(), ParseError> {
        if self.started || self.metrics.has_dtd {
            return Err(misuse("document type reported after content or twice"));
        }
        if !self.limits.allow_dtd {
            return Err(ParseError::DtdDetected);
        }
        self.metrics.has_dtd = true;
        Ok(())
    }

    /// Start reporting an element: its expanded name and the node it is.
    ///
    /// # Errors
    /// A limit the element passes, or a call inside another start tag.
    pub fn begin_element(
        &mut self,
        node: ExternalNode,
        local_name: &str,
        prefix: Option<&str>,
        namespace: Option<&str>,
    ) -> Result<(), ParseError> {
        self.started = true;
        if self.pending.is_some() {
            return Err(misuse("element started inside a start tag"));
        }
        self.admit_node()?;
        self.charge_bytes(local_name.len() + prefix.map_or(0, str::len))?;
        self.pending = Some(Pending {
            node,
            name: String::from(local_name),
            prefix: prefix.map(String::from),
            namespace: namespace.filter(|uri| !uri.is_empty()).map(String::from),
            attributes: Vec::new(),
        });
        self.declarations.clear();
        Ok(())
    }

    /// Report a namespace declaration of the current start tag; `None` binds
    /// the default namespace, and an empty `uri` undeclares it.
    ///
    /// # Errors
    /// Outside a start tag, or when the declaration passes the byte limit.
    pub fn declare_namespace(&mut self, prefix: Option<&str>, uri: &str) -> Result<(), ParseError> {
        self.charge_bytes(prefix.map_or(0, str::len) + uri.len())?;
        if self.pending.is_none() {
            return Err(misuse("namespace declared outside a start tag"));
        }
        Values::push(
            &mut self.declarations,
            (prefix.map(String::from), String::from(uri)),
        )
    }

    /// Report an attribute of the current start tag. `is_id` is whether the
    /// tree registered it as an ID (DTD type, `xml:id` or the caller).
    ///
    /// # Errors
    /// Outside a start tag, or when the attribute passes the byte limit.
    pub fn attribute(
        &mut self,
        local_name: &str,
        prefix: Option<&str>,
        namespace: Option<&str>,
        value: &str,
        is_id: bool,
    ) -> Result<(), ParseError> {
        self.charge_bytes(local_name.len() + prefix.map_or(0, str::len) + value.len())?;
        let pending = self
            .pending
            .as_mut()
            .ok_or_else(|| misuse("attribute reported outside a start tag"))?;
        Values::push(
            &mut pending.attributes,
            AttributeData {
                name: String::from(local_name),
                namespace: namespace.filter(|uri| !uri.is_empty()).map(String::from),
                prefix: prefix.map(String::from),
                value: String::from(value),
                is_id,
                xml_id_error: None,
            },
        )
    }

    /// End the current start tag; the element's content follows.
    ///
    /// # Errors
    /// Without a start tag, or when the element passes the depth or
    /// namespace-binding limit.
    pub fn open_element(&mut self) -> Result<(), ParseError> {
        let pending = self
            .pending
            .take()
            .ok_or_else(|| misuse("element opened without a start tag"))?;
        let parent = self.parent();
        let depth = self.open.len();
        if depth > self.limits.depth {
            return Err(ParseError::DepthLimitReached {
                maximum: self.limits.depth,
                actual: depth,
            });
        }
        self.metrics.max_depth = self.metrics.max_depth.max(depth);
        let namespaces = self.namespaces(parent)?;
        let element = self.tree.push_with_actionability(
            Some(parent),
            NodeKind::Element {
                name: pending.name,
                namespace: pending.namespace,
                prefix: pending.prefix,
                attributes: pending.attributes,
                namespaces,
            },
            0..0,
            false,
        )?;
        self.record(element, pending.node);
        self.open.push(element);
        Ok(())
    }

    /// End the innermost open element.
    ///
    /// # Errors
    /// Inside a start tag, or with no element open.
    pub fn end_element(&mut self) -> Result<(), ParseError> {
        if self.pending.is_some() {
            return Err(misuse("element ended inside its start tag"));
        }
        // The root stays at the bottom of the stack; only an element above it ends.
        match self.open.len() {
            0 | 1 => Err(misuse("element ended with none open")),
            _ => {
                let element = self.open.pop().ok_or(ParseError::AllocationFailed)?;
                self.tree.finish_subtree(element);
                Ok(())
            }
        }
    }

    /// Report character data; adjacent text joins one semantic text node.
    ///
    /// # Errors
    /// Inside a start tag, or a limit the text passes.
    pub fn text(&mut self, node: ExternalNode, value: &str) -> Result<(), ParseError> {
        self.started = true;
        self.outside_start_tag("text")?;
        self.charge_bytes(value.len())?;
        let parent = self.parent();
        // Outside the document element only whitespace may occur, and it is
        // not content (XML 1.0 section 2.8, production 27 `Misc`).
        if self.open.len() == 1 {
            if value.chars().all(char::is_whitespace) {
                return Ok(());
            }
            return Err(misuse("character data outside the document element"));
        }
        if !self.tree.has_text_tail(parent) {
            self.admit_node()?;
        }
        let before = self.tree.len();
        self.tree
            .append_text(parent, String::from(value), 0..0, false)?;
        if self.tree.len() > before {
            // The node limit, a u32, admitted this node.
            let text =
                NodeId::from(u32::try_from(before).map_err(|_| ParseError::NodesLimitReached)?);
            self.record(text, node);
        } else if let Some(joined) = self.nodes.last_mut() {
            // The value joined the parent's trailing text, which is the last
            // node built: nothing follows it under its parent, and every
            // earlier sibling's subtree was built before it. That run now
            // spans several tree nodes, none of which alone is the node an
            // edit would select, so it keeps no reference and refuses edits;
            // the run keeps them for read-only selection.
            let previous = joined.take();
            let position = self.nodes.len() - 1;
            let constituent = (self.entity_depth == 0).then_some(node);
            match self.runs.last_mut() {
                Some((last, run)) if *last == position => run.push(constituent),
                _ => self
                    .runs
                    .push((position, alloc::vec![previous, constituent])),
            }
        }
        Ok(())
    }

    /// Report a comment.
    ///
    /// # Errors
    /// Inside a start tag, or a limit the comment passes.
    pub fn comment(&mut self, node: ExternalNode, value: &str) -> Result<(), ParseError> {
        self.charge_bytes(value.len())?;
        self.leaf(node, NodeKind::Comment(String::from(value)), "comment")
    }

    /// Report a processing instruction.
    ///
    /// # Errors
    /// Inside a start tag, or a limit the instruction passes.
    pub fn processing_instruction(
        &mut self,
        node: ExternalNode,
        target: &str,
        value: Option<&str>,
    ) -> Result<(), ParseError> {
        self.charge_bytes(target.len() + value.map_or(0, str::len))?;
        let kind = NodeKind::PI {
            target: String::from(target),
            value: value.map(String::from),
        };
        self.leaf(node, kind, "processing instruction")
    }

    /// Nodes reported until the matching [`Self::leave_entity`] are an entity
    /// reference's replacement: part of the content, but no edit may target them.
    ///
    /// # Errors
    /// Inside a start tag, or past the entity expansion ceiling.
    pub fn enter_entity(&mut self) -> Result<(), ParseError> {
        self.outside_start_tag("entity reference")?;
        self.count_expansion()?;
        self.entity_depth += 1;
        Ok(())
    }

    /// Report an entity reference the tree expands inside the value of the
    /// attribute being built; it counts toward the same expansion ceiling as
    /// one in content.
    ///
    /// # Errors
    /// [`ParseError::EntityExpansionLimitReached`] past the ceiling.
    pub fn expand_attribute_entity(&mut self) -> Result<(), ParseError> {
        if self.pending.is_none() {
            return Err(misuse("attribute entity reference outside a start tag"));
        }
        self.count_expansion()
    }

    /// Refuse, before it is built, an attribute value of `bytes` the byte
    /// limit could not hold; [`Self::attribute`] charges the value itself.
    ///
    /// # Errors
    /// [`ParseError::ByteLimitReached`] when the value would pass the limit.
    pub fn admit_attribute_bytes(&self, bytes: usize) -> Result<(), ParseError> {
        let total = self.metrics.bytes.checked_add(bytes);
        match total {
            Some(total) if total <= self.limits.bytes => Ok(()),
            _ => Err(ParseError::ByteLimitReached {
                maximum: self.limits.bytes,
                actual: total.unwrap_or(usize::MAX),
            }),
        }
    }

    fn count_expansion(&mut self) -> Result<(), ParseError> {
        let maximum = crate::hard_limits::XML_ENTITY_EXPANSION_CEILING;
        if self.entity_expansions >= maximum {
            return Err(ParseError::EntityExpansionLimitReached {
                maximum,
                actual: self.entity_expansions + 1,
            });
        }
        self.entity_expansions += 1;
        Ok(())
    }

    /// End the innermost entity reference's replacement.
    ///
    /// # Errors
    /// Without a matching [`Self::enter_entity`].
    pub fn leave_entity(&mut self) -> Result<(), ParseError> {
        self.entity_depth = self
            .entity_depth
            .checked_sub(1)
            .ok_or_else(|| misuse("entity reference left without entering one"))?;
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<Projection<'input>, ParseError> {
        if self.pending.is_some() || self.open.len() != 1 || self.entity_depth != 0 {
            return Err(misuse("projection ended inside an open node"));
        }
        let root = self.open[0];
        self.tree.finish_subtree(root);
        let document = self.tree.finish(&LexicalPreflight::unscanned(Native))?;
        if !document.root().children().any(|node| node.is_element()) {
            return Err(misuse("projection has no document element"));
        }
        Ok(Projection {
            document,
            nodes: self.nodes,
            runs: self.runs,
            metrics: self.metrics,
        })
    }

    fn parent(&self) -> NodeId {
        *self.open.last().expect("the root stays open")
    }

    fn outside_start_tag(&self, what: &str) -> Result<(), ParseError> {
        if self.pending.is_some() {
            return Err(ParseError::Backend {
                backend: SOURCE,
                message: alloc::format!("{what} reported inside a start tag"),
            });
        }
        Ok(())
    }

    fn leaf(
        &mut self,
        node: ExternalNode,
        kind: NodeKind<Native>,
        what: &str,
    ) -> Result<(), ParseError> {
        self.started = true;
        self.outside_start_tag(what)?;
        self.admit_node()?;
        let parent = self.parent();
        let leaf = self
            .tree
            .push_with_actionability(Some(parent), kind, 0..0, false)?;
        self.record(leaf, node);
        Ok(())
    }

    /// Record the external node an arena node came from; a node an entity
    /// expanded to keeps no reference, since no edit may address it.
    fn record(&mut self, id: NodeId, node: ExternalNode) {
        debug_assert_eq!(id.get_usize(), self.nodes.len());
        self.nodes.push((self.entity_depth == 0).then_some(node));
    }

    fn admit_node(&self) -> Result<(), ParseError> {
        if self.tree.len() >= self.limits.nodes as usize {
            Err(ParseError::NodesLimitReached)
        } else {
            Ok(())
        }
    }

    fn charge_bytes(&mut self, bytes: usize) -> Result<(), ParseError> {
        let total = self.metrics.bytes.checked_add(bytes);
        match total {
            Some(total) if total <= self.limits.bytes => {
                self.metrics.bytes = total;
                Ok(())
            }
            _ => Err(ParseError::ByteLimitReached {
                maximum: self.limits.bytes,
                actual: total.unwrap_or(usize::MAX),
            }),
        }
    }

    /// The element's in-scope set: its parent's, unless it declares bindings.
    fn namespaces(&mut self, parent: NodeId) -> Result<NamespaceSet, ParseError> {
        let inherited = self.tree.namespace_set_of(Some(parent));
        if self.declarations.is_empty() {
            return Ok(inherited);
        }
        let inherited = self.tree.namespace_bindings(inherited);
        let mut namespaces: Vec<NamespaceData<Native>> =
            Native.values(inherited.len() + self.declarations.len())?;
        for namespace in inherited {
            Values::push(
                &mut namespaces,
                NamespaceData {
                    prefix: namespace.prefix.clone(),
                    uri: namespace.uri.clone(),
                },
            )?;
        }
        for (prefix, uri) in self.declarations.drain(..) {
            match namespaces
                .iter_mut()
                .find(|existing| existing.prefix == prefix)
            {
                Some(existing) => existing.uri = uri,
                None => Values::push(&mut namespaces, NamespaceData { prefix, uri })?,
            }
        }
        let active = namespaces
            .iter()
            .filter(|binding| !binding.uri.is_empty())
            .count();
        if active > self.limits.namespace_bindings {
            return Err(ParseError::NamespaceBindingLimitReached {
                maximum: self.limits.namespace_bindings,
                actual: active,
            });
        }
        self.metrics.peak_namespace_bindings = self.metrics.peak_namespace_bindings.max(active);
        self.tree.add_namespace_set(namespaces)
    }
}
