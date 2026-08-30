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
    /// Compiled-expression handle produced by compatible dynamic XPath extensions.
    StoredExpression(String),
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
            Self::StoredExpression(value) => !value.is_empty(),
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
            Self::StoredExpression(value) => value,
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
    let exponent = value.abs().log10().floor() as i32;
    let scale = 10_f64.powi(14_i32.saturating_sub(exponent));
    let scaled = value * scale;
    let value = if scale.is_finite() && scale != 0.0 && scaled.is_finite() {
        scaled.round() / scale
    } else {
        value
    };
    if exponent >= 10 {
        let rendered = format!("{value:.11e}");
        let (mantissa, exponent) = rendered
            .split_once('e')
            .expect("scientific formatting includes an exponent");
        let mantissa = mantissa.trim_end_matches('0').trim_end_matches('.');
        let exponent = exponent
            .parse::<i32>()
            .expect("formatted exponent is numeric");
        return format!("{mantissa}e{exponent:+}");
    }
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::format_xpath_number;

    #[test]
    fn xpath_non_finite_numbers_keep_their_lexical_forms() {
        assert_eq!(format_xpath_number(f64::NAN), "NaN");
        assert_eq!(format_xpath_number(f64::INFINITY), "Infinity");
        assert_eq!(format_xpath_number(f64::NEG_INFINITY), "-Infinity");
    }

    #[test]
    fn xpath_finite_numbers_do_not_lose_significant_digits() {
        assert_eq!(format_xpath_number(59.999_999_999_99), "59.99999999999");
        assert_eq!(format_xpath_number(0.000_01), "0.00001");
        assert_eq!(format_xpath_number(0.640_000_000_000_000_1), "0.64");
        assert_eq!(format_xpath_number(95_012.388_419_899_99), "95012.3884199");
    }
}
