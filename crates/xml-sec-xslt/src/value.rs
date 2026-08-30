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
        .map_or_else(|| digits.len() as i32, |index| index as i32);
    let target = decimal + exponent;
    let mut output = String::new();
    if negative {
        output.push('-');
    }
    if target <= 0 {
        output.push_str("0.");
        output.extend(std::iter::repeat_n('0', target.unsigned_abs() as usize));
        output.push_str(&digits);
    } else if target as usize >= digits.len() {
        output.push_str(&digits);
        output.extend(std::iter::repeat_n('0', target as usize - digits.len()));
    } else {
        let target = target as usize;
        output.push_str(&digits[..target]);
        output.push('.');
        output.push_str(&digits[target..]);
    }
    output
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
        assert_eq!(
            format_xpath_number(0.640_000_000_000_000_1),
            "0.6400000000000001"
        );
        assert_eq!(
            format_xpath_number(95_012.388_419_899_99),
            "95012.38841989999"
        );
        assert_eq!(format_xpath_number(285_311_670_611.0), "285311670611");
    }
}
