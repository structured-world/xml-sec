use crate::{Document, NodeReference};

/// XSLT 1.0 value space, including the distinct result-tree-fragment type.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Value {
    /// XPath nodes whose identities are interpreted against the associated source document.
    NodeSet(Vec<NodeReference>),
    /// XPath boolean value.
    Boolean(bool),
    /// XPath IEEE-754 number value.
    Number(f64),
    /// XPath string value.
    String(String),
    /// XSLT 1.0 temporary tree retaining all constructed node kinds.
    ResultTreeFragment(Document),
}

impl Value {
    #[must_use]
    pub fn into_boolean(self) -> bool {
        match self {
            Self::NodeSet(nodes) => !nodes.is_empty(),
            Self::Boolean(value) => value,
            Self::Number(value) => value != 0.0 && !value.is_nan(),
            Self::String(value) => !value.is_empty(),
            Self::ResultTreeFragment(document) => {
                !document.string_value(document.root()).is_empty()
                    || document
                        .node(document.root())
                        .is_some_and(|root| !root.children.is_empty())
            }
        }
    }

    #[must_use]
    /// Convert using the document that owns any node identities in this value.
    pub fn into_string(self, document: &Document) -> String {
        match self {
            Self::NodeSet(nodes) => nodes
                .first()
                .map(|node| match node {
                    NodeReference::Node(id) => document.string_value(*id),
                    NodeReference::Attribute { owner, index } => document
                        .node(*owner)
                        .and_then(|node| match &node.kind {
                            crate::NodeKind::Element { attributes, .. } => attributes.get(*index),
                            _ => None,
                        })
                        .map(|attribute| attribute.value.clone())
                        .unwrap_or_default(),
                    NodeReference::Namespace { owner, index } => document
                        .node(*owner)
                        .and_then(|node| match &node.kind {
                            crate::NodeKind::Element { namespaces, .. } => namespaces.get(*index),
                            _ => None,
                        })
                        .map(|namespace| namespace.uri.clone())
                        .unwrap_or_default(),
                })
                .unwrap_or_default(),
            Self::Boolean(true) => "true".into(),
            Self::Boolean(false) => "false".into(),
            Self::Number(value) if value.is_nan() => "NaN".into(),
            Self::Number(value) if value == f64::INFINITY => "Infinity".into(),
            Self::Number(value) if value == f64::NEG_INFINITY => "-Infinity".into(),
            Self::Number(0.0) => "0".into(),
            Self::Number(value) => format_xpath_number(value),
            Self::String(value) => value,
            Self::ResultTreeFragment(document) => document.string_value(document.root()),
        }
    }
}

pub(crate) fn format_xpath_number(value: f64) -> String {
    let rendered = value.to_string();
    rendered.strip_suffix(".0").unwrap_or(&rendered).to_owned()
}
