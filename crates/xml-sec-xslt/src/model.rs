use std::collections::HashMap;

use crate::{Error, Result};

/// Stable index of a node inside one owned document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub usize);

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
}

/// Parser-independent owned XML tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    nodes: Vec<Node>,
    root: NodeId,
    source_xml: Option<String>,
}

impl Document {
    /// Parse caller-supplied XML into the engine semantic model.
    pub fn parse(xml: &str, base_uri: Option<&str>) -> Result<Self> {
        let parsed =
            roxmltree::Document::parse(xml).map_err(|error| Error::Xml(error.to_string()))?;
        let mut document = Self::empty(base_uri.map(str::to_owned));
        document.source_xml = Some(xml.to_owned());
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
                let namespaces = source
                    .namespaces()
                    .map(|namespace| Namespace {
                        prefix: namespace.name().map(str::to_owned),
                        uri: namespace.uri().to_owned(),
                    })
                    .collect();
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
            mapping.insert(source.id(), id);
        }
        Ok(document)
    }

    #[must_use]
    pub fn empty(base_uri: Option<String>) -> Self {
        Self {
            nodes: vec![Node {
                kind: NodeKind::Root,
                parent: None,
                children: Vec::new(),
                base_uri,
            }],
            root: NodeId(0),
            source_xml: None,
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

    #[must_use]
    pub fn nodes(&self) -> impl ExactSizeIterator<Item = (NodeId, &Node)> {
        self.nodes
            .iter()
            .enumerate()
            .map(|(index, node)| (NodeId(index), node))
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
        });
        if let Some(parent) = self.nodes.get_mut(parent.0) {
            parent.children.push(id);
        }
        id
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
                self.collect_text(id, &mut output);
                output
            }
        }
    }

    fn collect_text(&self, id: NodeId, output: &mut String) {
        let Some(node) = self.node(id) else { return };
        if let NodeKind::Text { value, .. } = &node.kind {
            output.push_str(value);
        }
        for child in &node.children {
            self.collect_text(*child, output);
        }
    }

    pub(crate) fn retain_nodes(&mut self, mut keep: impl FnMut(NodeId, &Node) -> bool) {
        for index in 0..self.nodes.len() {
            let id = NodeId(index);
            let children = self.nodes[index]
                .children
                .iter()
                .copied()
                .filter(|child| keep(*child, &self.nodes[child.0]))
                .collect();
            self.nodes[index].children = children;
            let _ = id;
        }
        self.source_xml = None;
    }

    pub(crate) fn rebuild_source_xml(&mut self, xml: String) {
        self.source_xml = Some(xml);
    }
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
    node.namespaces()
        .find(|entry| entry.uri() == namespace && entry.name().is_some())
        .and_then(|entry| entry.name())
        .map(str::to_owned)
}
