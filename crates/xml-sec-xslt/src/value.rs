use crate::NodeId;

/// XSLT 1.0 value space, including the distinct result-tree-fragment type.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Value {
    NodeSet(Vec<NodeId>),
    Boolean(bool),
    Number(f64),
    String(String),
    ResultTreeFragment(String),
}

impl Value {
    #[must_use]
    pub fn into_boolean(self) -> bool {
        match self {
            Self::NodeSet(nodes) => !nodes.is_empty(),
            Self::Boolean(value) => value,
            Self::Number(value) => value != 0.0 && !value.is_nan(),
            Self::String(value) | Self::ResultTreeFragment(value) => !value.is_empty(),
        }
    }

    #[must_use]
    pub fn into_string(self) -> String {
        match self {
            Self::NodeSet(_) => String::new(),
            Self::Boolean(true) => "true".into(),
            Self::Boolean(false) => "false".into(),
            Self::Number(value) if value.is_nan() => "NaN".into(),
            Self::Number(value) if value == f64::INFINITY => "Infinity".into(),
            Self::Number(value) if value == f64::NEG_INFINITY => "-Infinity".into(),
            Self::Number(0.0) => "0".into(),
            Self::Number(value) => format_xpath_number(value),
            Self::String(value) | Self::ResultTreeFragment(value) => value,
        }
    }
}

fn format_xpath_number(value: f64) -> String {
    let rendered = value.to_string();
    rendered.strip_suffix(".0").unwrap_or(&rendered).to_owned()
}
