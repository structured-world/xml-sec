use std::sync::Arc;

use super::{Document, NodeReference};

/// XSLT 1.0 value space, including the distinct result-tree-fragment type.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Value {
    /// `XPath` nodes whose identities are interpreted against the associated source document.
    NodeSet(Vec<NodeReference>),
    /// `XPath` boolean value.
    Boolean(bool),
    /// `XPath` IEEE-754 number value.
    Number(f64),
    /// `XPath` string value.
    String(String),
    /// Compiled-expression handle produced by compatible dynamic `XPath` extensions.
    StoredExpression(String),
    /// XSLT 1.0 temporary tree retaining all constructed node kinds.
    ResultTreeFragment(Arc<Document>),
}

impl Value {
    #[must_use]
    pub fn into_boolean(self) -> bool {
        self.boolean()
    }

    pub(crate) fn boolean(&self) -> bool {
        match self {
            Self::NodeSet(nodes) => !nodes.is_empty(),
            Self::Boolean(value) => *value,
            Self::Number(value) => *value != 0.0 && !value.is_nan(),
            Self::String(value) | Self::StoredExpression(value) => !value.is_empty(),
            // XSLT 1.0 defines every result-tree fragment as the equivalent node-set
            // containing its root node, including fragments with no constructed children.
            Self::ResultTreeFragment(_) => true,
        }
    }

    #[must_use]
    /// Convert using the document that owns any node identities in this value.
    pub fn into_string(self, document: &Document) -> String {
        match self {
            Self::NodeSet(nodes) => nodes
                .into_iter()
                .filter_map(|node| document.document_order_key(&node).map(|key| (key, node)))
                .min_by_key(|(key, _)| *key)
                .map(|(_, node)| match node {
                    NodeReference::Node(id) => document.string_value(id),
                    NodeReference::Attribute { owner, index } => document
                        .node(owner)
                        .and_then(|node| match &node.kind {
                            super::NodeKind::Element { attributes, .. } => attributes.get(index),
                            _ => None,
                        })
                        .map(|attribute| attribute.value.clone())
                        .unwrap_or_default(),
                    NodeReference::Namespace { owner, index } => document
                        .node(owner)
                        .and_then(|node| match &node.kind {
                            super::NodeKind::Element { namespaces, .. } => namespaces.get(index),
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
            Self::String(value) | Self::StoredExpression(value) => value,
            Self::ResultTreeFragment(document) => document.string_value(document.root()),
        }
    }
}

pub(crate) fn format_xpath_number(value: f64) -> String {
    if value.is_nan() {
        return "NaN".into();
    }
    if value == f64::INFINITY {
        return "Infinity".into();
    }
    if value == f64::NEG_INFINITY {
        return "-Infinity".into();
    }
    if value == 0.0 {
        return "0".into();
    }
    expand_decimal_exponent(&value.to_string())
}

fn expand_decimal_exponent(value: &str) -> String {
    let Some((mantissa, exponent)) = value.split_once(['e', 'E']) else {
        return value.to_owned();
    };
    let exponent = exponent.parse::<i32>().unwrap_or_default();
    let negative = mantissa.starts_with('-');
    let digits = mantissa
        .trim_start_matches('-')
        .chars()
        .filter(|character| *character != '.')
        .collect::<String>();
    let decimal = mantissa
        .trim_start_matches('-')
        .find('.')
        .unwrap_or(digits.len());
    let decimal = i32::try_from(decimal).expect("binary64 mantissa length fits i32");
    let target = decimal + exponent;
    let mut output = String::new();
    if negative {
        output.push('-');
    }
    if target <= 0 {
        output.push_str("0.");
        let zeroes =
            usize::try_from(target.unsigned_abs()).expect("binary64 decimal exponent fits usize");
        output.extend(std::iter::repeat_n('0', zeroes));
        output.push_str(&digits);
    } else {
        let target = usize::try_from(target).expect("positive decimal position fits usize");
        if target >= digits.len() {
            output.push_str(&digits);
            output.extend(std::iter::repeat_n('0', target - digits.len()));
        } else {
            output.push_str(&digits[..target]);
            output.push('.');
            output.push_str(&digits[target..]);
        }
    }
    output
}

#[cfg(all(test, not(feature = "embedded")))]
mod tests;
