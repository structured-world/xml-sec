use std::collections::HashMap;

use sxd_document_no_unsafe::Package;
use sxd_xpath_no_unsafe::{Context, Factory, Value as SxdValue, function, nodeset};

use crate::budget::Meter;
use crate::compiler::{DecimalFormat, Expression, KeyDeclaration, Pattern};
use crate::{BudgetKind, Document, Error, ExpandedName, NodeId, NodeKind, Result, Value};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum SourceNode {
    Node(NodeId),
    Attribute { owner: NodeId, index: usize },
    Namespace { owner: NodeId, index: usize },
}

pub(crate) struct Evaluator<'a> {
    pub(crate) source: &'a Document,
    package: Package,
    key_index: HashMap<(ExpandedName, String), Vec<Vec<usize>>>,
    decimal_formats: Vec<DecimalFormat>,
}

impl<'a> Evaluator<'a> {
    pub(crate) fn new(source: &'a Document) -> Result<Self> {
        let xml = source.source_xml().ok_or_else(|| {
            Error::Dynamic("source document has no lexical XML representation".into())
        })?;
        let package = sxd_document_no_unsafe::parser::parse(xml)
            .map_err(|error| Error::Xml(error.to_string()))?;
        Ok(Self {
            source,
            package,
            key_index: HashMap::new(),
            decimal_formats: Vec::new(),
        })
    }

    pub(crate) fn initialize_xslt(
        &mut self,
        keys: &[KeyDeclaration],
        decimal_formats: &[DecimalFormat],
        meter: &mut Meter,
    ) -> Result<()> {
        self.decimal_formats = decimal_formats.to_vec();
        let variables = HashMap::new();
        let maps = NodeMaps::new(self.source, self.package.as_document().root().into());
        let mut index = HashMap::<(ExpandedName, String), Vec<Vec<usize>>>::new();
        for declaration in keys {
            for (id, _) in self.source.nodes() {
                let node = SourceNode::Node(id);
                if !self.matches(&declaration.match_pattern, &node, &variables, meter)? {
                    continue;
                }
                let value =
                    self.evaluate(&declaration.use_expression, &node, 1, 1, &variables, meter)?;
                let values = match value {
                    XPathValue::NodeSet(nodes) => nodes
                        .iter()
                        .map(|node| self.string_value(node))
                        .collect::<Vec<_>>(),
                    value => vec![value.string(self)],
                };
                let Some(sxd) = maps.to_sxd(&node) else {
                    continue;
                };
                let path = path_to(&sxd);
                for value in values {
                    meter.charge(BudgetKind::KeyEntries, 1)?;
                    index
                        .entry((declaration.name.clone(), value))
                        .or_default()
                        .push(path.clone());
                }
            }
        }
        self.key_index = index;
        Ok(())
    }

    pub(crate) fn evaluate(
        &self,
        expression: &Expression,
        node: &SourceNode,
        position: usize,
        size: usize,
        variables: &HashMap<ExpandedName, Value>,
        meter: &mut Meter,
    ) -> Result<XPathValue> {
        meter.charge(BudgetKind::XPathEvaluations, 1)?;
        let document = self.package.as_document();
        let maps = NodeMaps::new(self.source, document.root().into());
        let context_node = maps
            .to_sxd(node)
            .ok_or_else(|| Error::Dynamic("XPath context node is stale".into()))?;
        let xpath = Factory::new().build(&expression.source).map_err(|error| {
            Error::Static(format!(
                "invalid XPath expression `{}`: {error}",
                expression.source
            ))
        })?;
        let mut context = Context::new();
        for (prefix, uri) in &expression.namespaces {
            context.set_namespace(prefix, uri);
        }
        context.set_namespace("xml", "http://www.w3.org/XML/1998/namespace");
        context.set_function("position", FixedNumber(position as f64));
        context.set_function("last", FixedNumber(size as f64));
        context.set_function(
            "current",
            CurrentNode {
                path: path_to(&context_node),
            },
        );
        context.set_function(
            "key",
            KeyFunction {
                index: self.key_index.clone(),
                namespaces: expression.namespaces.clone(),
            },
        );
        context.set_function(
            "format-number",
            FormatNumberFunction {
                formats: self.decimal_formats.clone(),
                namespaces: expression.namespaces.clone(),
            },
        );
        context.set_function("generate-id", GenerateId);
        context.set_function(
            "system-property",
            SystemProperty {
                namespaces: expression.namespaces.clone(),
            },
        );
        context.set_function(
            "element-available",
            ElementAvailable {
                namespaces: expression.namespaces.clone(),
            },
        );
        context.set_function(
            "function-available",
            FunctionAvailable {
                namespaces: expression.namespaces.clone(),
            },
        );
        context.set_function("unparsed-entity-uri", EmptyUriFunction);
        for (name, value) in variables {
            let qname: sxd_xpath_no_unsafe::OwnedQName = name.namespace.as_deref().map_or_else(
                || name.local.as_str().into(),
                |namespace| (namespace, name.local.as_str()).into(),
            );
            match value {
                Value::Boolean(value) => context.set_variable(qname.clone(), *value),
                Value::Number(value) => context.set_variable(qname.clone(), *value),
                Value::String(value) | Value::ResultTreeFragment(value) => {
                    context.set_variable(qname.clone(), value.clone())
                }
                Value::NodeSet(nodes) => {
                    let mut set = nodeset::Nodeset::new();
                    for id in nodes {
                        if let Some(node) = maps.to_sxd(&SourceNode::Node(*id)) {
                            set.add(node);
                        }
                    }
                    context.set_variable(qname, set);
                }
            }
        }
        let value = xpath.evaluate(&context, context_node).map_err(|error| {
            Error::Dynamic(format!("XPath `{}` failed: {error}", expression.source))
        })?;
        maps.project_value(value)
    }

    pub(crate) fn matches(
        &self,
        pattern: &Pattern,
        node: &SourceNode,
        variables: &HashMap<ExpandedName, Value>,
        meter: &mut Meter,
    ) -> Result<bool> {
        let source = pattern.source.trim();
        if source == "/" {
            return Ok(matches!(node, SourceNode::Node(id) if *id == self.source.root()));
        }
        for branch in split_pattern_branches(source) {
            let branch = branch.trim();
            let expression = if branch.starts_with('/')
                || branch.starts_with("id(")
                || branch.starts_with("key(")
            {
                branch.to_owned()
            } else {
                format!("//{branch}")
            };
            let value = self.evaluate(
                &Expression {
                    source: expression,
                    namespaces: pattern.namespaces.clone(),
                },
                &SourceNode::Node(self.source.root()),
                1,
                1,
                variables,
                meter,
            )?;
            if matches!(value, XPathValue::NodeSet(ref nodes) if nodes.contains(node)) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(crate) fn children(&self, node: &SourceNode) -> Vec<SourceNode> {
        match node {
            SourceNode::Node(id) => self
                .source
                .node(*id)
                .map(|node| {
                    node.children
                        .iter()
                        .copied()
                        .map(SourceNode::Node)
                        .collect()
                })
                .unwrap_or_default(),
            SourceNode::Attribute { .. } | SourceNode::Namespace { .. } => Vec::new(),
        }
    }

    pub(crate) fn string_value(&self, node: &SourceNode) -> String {
        match node {
            SourceNode::Node(id) => self.source.string_value(*id),
            SourceNode::Attribute { owner, index } => self
                .source
                .node(*owner)
                .and_then(|node| match &node.kind {
                    NodeKind::Element { attributes, .. } => attributes
                        .get(*index)
                        .map(|attribute| attribute.value.clone()),
                    _ => None,
                })
                .unwrap_or_default(),
            SourceNode::Namespace { owner, index } => self
                .source
                .node(*owner)
                .and_then(|node| match &node.kind {
                    NodeKind::Element { namespaces, .. } => namespaces
                        .get(*index)
                        .map(|namespace| namespace.uri.clone()),
                    _ => None,
                })
                .unwrap_or_default(),
        }
    }
}

fn split_pattern_branches(source: &str) -> Vec<&str> {
    let mut branches = Vec::new();
    let mut start = 0;
    let mut depth = 0usize;
    let mut quote = None;
    for (index, character) in source.char_indices() {
        if let Some(active) = quote {
            if character == active {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            '(' | '[' => depth += 1,
            ')' | ']' => depth = depth.saturating_sub(1),
            '|' if depth == 0 => {
                branches.push(&source[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    branches.push(&source[start..]);
    branches
}

#[derive(Debug, Clone)]
pub(crate) enum XPathValue {
    NodeSet(Vec<SourceNode>),
    Boolean(bool),
    Number(f64),
    String(String),
}
impl XPathValue {
    pub(crate) fn boolean(&self) -> bool {
        match self {
            Self::NodeSet(nodes) => !nodes.is_empty(),
            Self::Boolean(value) => *value,
            Self::Number(value) => *value != 0.0 && !value.is_nan(),
            Self::String(value) => !value.is_empty(),
        }
    }
    pub(crate) fn string(&self, evaluator: &Evaluator<'_>) -> String {
        match self {
            Self::NodeSet(nodes) => nodes
                .first()
                .map(|node| evaluator.string_value(node))
                .unwrap_or_default(),
            Self::Boolean(true) => "true".into(),
            Self::Boolean(false) => "false".into(),
            Self::Number(value) => Value::Number(*value).into_string(),
            Self::String(value) => value.clone(),
        }
    }
    pub(crate) fn number(&self, evaluator: &Evaluator<'_>) -> f64 {
        match self {
            Self::Number(value) => *value,
            Self::Boolean(true) => 1.0,
            Self::Boolean(false) => 0.0,
            Self::String(value) => xpath_number(value),
            Self::NodeSet(_) => xpath_number(&self.string(evaluator)),
        }
    }
}

fn xpath_number(value: &str) -> f64 {
    let trimmed = value.trim_matches(|c| matches!(c, ' ' | '\t' | '\r' | '\n'));
    if trimmed.is_empty() {
        f64::NAN
    } else {
        trimmed.parse().unwrap_or(f64::NAN)
    }
}

struct NodeMaps<'d> {
    forward: HashMap<SourceNode, nodeset::Node<'d>>,
    reverse: Vec<(nodeset::Node<'d>, SourceNode)>,
}
impl<'d> NodeMaps<'d> {
    fn new(source: &Document, root: nodeset::Node<'d>) -> Self {
        let mut ordinary = vec![];
        collect_ordinary(root.clone(), &mut ordinary);
        let mut source_nodes = source
            .nodes()
            .map(|(id, _)| SourceNode::Node(id))
            .collect::<Vec<_>>();
        let mut forward = HashMap::new();
        let mut reverse = Vec::new();
        for (source_node, sxd) in source_nodes.drain(..).zip(ordinary) {
            forward.insert(source_node.clone(), sxd.clone());
            reverse.push((sxd, source_node));
        }
        for (id, node) in source.nodes() {
            if let Some(element) = forward
                .get(&SourceNode::Node(id))
                .and_then(nodeset::Node::element)
                && let NodeKind::Element {
                    attributes,
                    namespaces,
                    ..
                } = &node.kind
            {
                for (index, source_attribute) in attributes.iter().enumerate() {
                    let Some(attribute) = element.attributes().into_iter().find(|candidate| {
                        let name = candidate.name();
                        let name = name.get();
                        name.local_part() == source_attribute.name.local
                            && name.namespace_uri() == source_attribute.name.namespace.as_deref()
                    }) else {
                        continue;
                    };
                    let key = SourceNode::Attribute { owner: id, index };
                    let value = nodeset::Node::Attribute(attribute);
                    forward.insert(key.clone(), value.clone());
                    reverse.push((value, key));
                }
                for (index, namespace) in namespaces.iter().enumerate() {
                    if let Some(candidate) =
                        element.namespaces_in_scope().into_iter().find(|candidate| {
                            candidate.prefix() == namespace.prefix.as_deref().unwrap_or("")
                                && candidate.uri() == namespace.uri
                        })
                    {
                        let key = SourceNode::Namespace { owner: id, index };
                        let value = nodeset::Node::Namespace(nodeset::Namespace {
                            parent: element,
                            prefix: sxd_document_no_unsafe::to_ns_str!(candidate.prefix()),
                            uri: sxd_document_no_unsafe::to_ns_str!(candidate.uri()),
                        });
                        forward.insert(key.clone(), value.clone());
                        reverse.push((value, key));
                    }
                }
            }
        }
        Self { forward, reverse }
    }
    fn to_sxd(&self, node: &SourceNode) -> Option<nodeset::Node<'d>> {
        self.forward.get(node).cloned()
    }
    fn project_value(&self, value: SxdValue<'d>) -> Result<XPathValue> {
        Ok(match value {
            SxdValue::Boolean(value) => XPathValue::Boolean(value),
            SxdValue::Number(value) => XPathValue::Number(value),
            SxdValue::String(value) => XPathValue::String(value),
            SxdValue::Nodeset(nodes) => XPathValue::NodeSet(
                nodes
                    .document_order()
                    .into_iter()
                    .filter_map(|node| {
                        self.reverse
                            .iter()
                            .find(|(candidate, _)| candidate == &node)
                            .map(|(_, source)| source.clone())
                    })
                    .collect(),
            ),
        })
    }
}
fn collect_ordinary<'d>(node: nodeset::Node<'d>, output: &mut Vec<nodeset::Node<'d>>) {
    output.push(node.clone());
    for child in node.children() {
        collect_ordinary(child, output)
    }
}
fn path_to(node: &nodeset::Node<'_>) -> Vec<usize> {
    let mut current = node.clone();
    let mut path = vec![];
    while let Some(parent) = current.parent() {
        let index = parent
            .children()
            .iter()
            .position(|child| *child == current)
            .unwrap_or(0);
        path.push(index);
        current = parent;
    }
    path.reverse();
    path
}
struct FixedNumber(f64);
impl function::Function for FixedNumber {
    fn evaluate<'c, 'd>(
        &self,
        _: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: Vec<SxdValue<'d>>,
    ) -> std::result::Result<SxdValue<'d>, function::Error> {
        if !args.is_empty() {
            return Err(function::Error::TooManyArguments {
                expected: 0,
                actual: args.len(),
            });
        }
        Ok(SxdValue::Number(self.0))
    }
}

struct GenerateId;
impl function::Function for GenerateId {
    fn evaluate<'c, 'd>(
        &self,
        _: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: Vec<SxdValue<'d>>,
    ) -> std::result::Result<SxdValue<'d>, function::Error> {
        if args.len() != 1 {
            return Err(function::Error::Other {
                what: "generate-id() requires one argument".into(),
            });
        }
        let SxdValue::Nodeset(nodes) = &args[0] else {
            return Err(function::Error::Other {
                what: "generate-id() requires a node-set".into(),
            });
        };
        let Some(node) = nodes.document_order().first().cloned() else {
            return Ok(SxdValue::String(String::new()));
        };
        let id = path_to(&node)
            .into_iter()
            .map(|index| index.to_string())
            .collect::<Vec<_>>()
            .join("_");
        let suffix = match &node {
            nodeset::Node::Attribute(attribute) => {
                let index = attribute
                    .parent()
                    .map(|parent| {
                        parent
                            .attributes()
                            .iter()
                            .position(|candidate| candidate == attribute)
                            .unwrap_or(0)
                    })
                    .unwrap_or(0);
                format!("A{index}")
            }
            nodeset::Node::Namespace(namespace) => format!("S{}", namespace.prefix()),
            _ => String::new(),
        };
        Ok(SxdValue::String(format!("N{id}{suffix}")))
    }
}

struct SystemProperty {
    namespaces: Vec<(String, String)>,
}
impl function::Function for SystemProperty {
    fn evaluate<'c, 'd>(
        &self,
        _: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: Vec<SxdValue<'d>>,
    ) -> std::result::Result<SxdValue<'d>, function::Error> {
        let name = one_qname_argument(args, &self.namespaces, "system-property")?;
        if name.namespace.as_deref() == Some(crate::compiler::XSLT_NS) && name.local == "version" {
            return Ok(SxdValue::Number(1.0));
        }
        let value = if name.namespace.as_deref() == Some(crate::compiler::XSLT_NS) {
            match name.local.as_str() {
                "vendor" => "structured-world xml-sec-xslt",
                "vendor-url" => "https://github.com/structured-world/xml-sec",
                _ => "",
            }
        } else {
            ""
        };
        Ok(SxdValue::String(value.into()))
    }
}

struct ElementAvailable {
    namespaces: Vec<(String, String)>,
}
impl function::Function for ElementAvailable {
    fn evaluate<'c, 'd>(
        &self,
        _: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: Vec<SxdValue<'d>>,
    ) -> std::result::Result<SxdValue<'d>, function::Error> {
        let name = one_qname_argument(args, &self.namespaces, "element-available")?;
        let available = name.namespace.as_deref() == Some(crate::compiler::XSLT_NS)
            && matches!(
                name.local.as_str(),
                "apply-imports"
                    | "apply-templates"
                    | "attribute"
                    | "call-template"
                    | "choose"
                    | "comment"
                    | "copy"
                    | "copy-of"
                    | "element"
                    | "for-each"
                    | "fallback"
                    | "if"
                    | "message"
                    | "number"
                    | "processing-instruction"
                    | "text"
                    | "value-of"
                    | "variable"
            );
        Ok(SxdValue::Boolean(available))
    }
}

struct FunctionAvailable {
    namespaces: Vec<(String, String)>,
}
impl function::Function for FunctionAvailable {
    fn evaluate<'c, 'd>(
        &self,
        _: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: Vec<SxdValue<'d>>,
    ) -> std::result::Result<SxdValue<'d>, function::Error> {
        let name = one_qname_argument(args, &self.namespaces, "function-available")?;
        let available = if name.namespace.is_some() {
            false
        } else {
            matches!(
                name.local.as_str(),
                "boolean"
                    | "ceiling"
                    | "concat"
                    | "contains"
                    | "count"
                    | "false"
                    | "floor"
                    | "format-number"
                    | "generate-id"
                    | "id"
                    | "key"
                    | "lang"
                    | "last"
                    | "local-name"
                    | "name"
                    | "namespace-uri"
                    | "normalize-space"
                    | "not"
                    | "number"
                    | "position"
                    | "round"
                    | "starts-with"
                    | "string"
                    | "string-length"
                    | "substring"
                    | "substring-after"
                    | "substring-before"
                    | "sum"
                    | "system-property"
                    | "translate"
                    | "true"
                    | "unparsed-entity-uri"
                    | "element-available"
                    | "function-available"
            )
        };
        Ok(SxdValue::Boolean(available))
    }
}

struct EmptyUriFunction;
impl function::Function for EmptyUriFunction {
    fn evaluate<'c, 'd>(
        &self,
        _: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: Vec<SxdValue<'d>>,
    ) -> std::result::Result<SxdValue<'d>, function::Error> {
        if args.len() != 1 {
            return Err(function::Error::Other {
                what: "unparsed-entity-uri() requires one argument".into(),
            });
        }
        Ok(SxdValue::String(String::new()))
    }
}

fn one_qname_argument(
    args: Vec<SxdValue<'_>>,
    namespaces: &[(String, String)],
    function: &str,
) -> std::result::Result<ExpandedName, function::Error> {
    if args.len() != 1 {
        return Err(function::Error::Other {
            what: format!("{function}() requires one argument"),
        });
    }
    resolve_lexical_name(&args[0].string(), namespaces)
}
struct CurrentNode {
    path: Vec<usize>,
}

struct KeyFunction {
    index: HashMap<(ExpandedName, String), Vec<Vec<usize>>>,
    namespaces: Vec<(String, String)>,
}
impl function::Function for KeyFunction {
    fn evaluate<'c, 'd>(
        &self,
        context: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: Vec<SxdValue<'d>>,
    ) -> std::result::Result<SxdValue<'d>, function::Error> {
        if args.len() != 2 {
            return Err(function::Error::Other {
                what: "key() requires exactly two arguments".into(),
            });
        }
        let name = resolve_lexical_name(&args[0].string(), &self.namespaces)?;
        let values = match &args[1] {
            SxdValue::Nodeset(nodes) => nodes
                .document_order()
                .iter()
                .map(|node| node.string_value())
                .collect(),
            value => vec![value.string()],
        };
        let mut result = nodeset::Nodeset::new();
        for value in values {
            if let Some(paths) = self.index.get(&(name.clone(), value)) {
                for path in paths {
                    if let Some(node) = follow_path(context.node.document().root().into(), path) {
                        result.add(node);
                    }
                }
            }
        }
        Ok(SxdValue::Nodeset(result))
    }
}

struct FormatNumberFunction {
    formats: Vec<DecimalFormat>,
    namespaces: Vec<(String, String)>,
}
impl function::Function for FormatNumberFunction {
    fn evaluate<'c, 'd>(
        &self,
        _: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: Vec<SxdValue<'d>>,
    ) -> std::result::Result<SxdValue<'d>, function::Error> {
        if !(2..=3).contains(&args.len()) {
            return Err(function::Error::Other {
                what: "format-number() requires two or three arguments".into(),
            });
        }
        let name = if args.len() == 3 {
            Some(resolve_lexical_name(&args[2].string(), &self.namespaces)?)
        } else {
            None
        };
        let format = self
            .formats
            .iter()
            .rev()
            .find(|format| format.name == name)
            .cloned()
            .or_else(|| name.is_none().then(default_decimal_format))
            .ok_or_else(|| function::Error::Other {
                what: "unknown decimal-format".into(),
            })?;
        Ok(SxdValue::String(render_decimal(
            args[0].number(),
            &args[1].string(),
            &format,
        )?))
    }
}

fn resolve_lexical_name(
    lexical: &str,
    namespaces: &[(String, String)],
) -> std::result::Result<ExpandedName, function::Error> {
    if let Some((prefix, local)) = lexical.split_once(':') {
        let namespace = namespaces
            .iter()
            .find(|(candidate, _)| candidate == prefix)
            .map(|(_, uri)| uri.clone())
            .ok_or_else(|| function::Error::Other {
                what: format!("unbound QName prefix {prefix}"),
            })?;
        Ok(ExpandedName::new(Some(namespace), local))
    } else {
        Ok(ExpandedName::new(None::<String>, lexical))
    }
}

fn follow_path<'d>(mut node: nodeset::Node<'d>, path: &[usize]) -> Option<nodeset::Node<'d>> {
    for index in path {
        node = node.children().get(*index).cloned()?;
    }
    Some(node)
}

fn default_decimal_format() -> DecimalFormat {
    DecimalFormat {
        name: None,
        decimal_separator: '.',
        grouping_separator: ',',
        infinity: "Infinity".into(),
        minus_sign: '-',
        nan: "NaN".into(),
        percent: '%',
        per_mille: '‰',
        zero_digit: '0',
        digit: '#',
        pattern_separator: ';',
    }
}

fn render_decimal(
    value: f64,
    pattern: &str,
    format: &DecimalFormat,
) -> std::result::Result<String, function::Error> {
    if value.is_nan() {
        return Ok(format.nan.clone());
    }
    if value.is_infinite() {
        return Ok(if value.is_sign_negative() {
            format!("{}{}", format.minus_sign, format.infinity)
        } else {
            format.infinity.clone()
        });
    }
    let alternatives = pattern.split(format.pattern_separator).collect::<Vec<_>>();
    let negative = value.is_sign_negative();
    let selected = if negative && alternatives.len() > 1 {
        alternatives[1]
    } else {
        alternatives[0]
    };
    let multiplier = if selected.contains(format.percent) {
        100.0
    } else if selected.contains(format.per_mille) {
        1000.0
    } else {
        1.0
    };
    let first = selected
        .find([format.digit, format.zero_digit])
        .ok_or_else(|| function::Error::Other {
            what: "format-number pattern has no digit".into(),
        })?;
    let last = selected
        .rfind([format.digit, format.zero_digit])
        .unwrap_or(first);
    let number_pattern = &selected[first..=last];
    let mut split = number_pattern.split(format.decimal_separator);
    let integer_pattern = split.next().unwrap_or_default();
    let fraction_pattern = split.next().unwrap_or_default();
    let minimum_integer = integer_pattern
        .chars()
        .filter(|c| *c == format.zero_digit)
        .count();
    let minimum_fraction = fraction_pattern
        .chars()
        .filter(|c| *c == format.zero_digit)
        .count();
    let maximum_fraction = fraction_pattern
        .chars()
        .filter(|c| *c == format.zero_digit || *c == format.digit)
        .count();
    let scaled = value.abs() * multiplier;
    let mut rendered = format!("{scaled:.maximum_fraction$}");
    if maximum_fraction > minimum_fraction && rendered.contains('.') {
        while rendered.ends_with('0')
            && rendered.split('.').nth(1).map_or(0, str::len) > minimum_fraction
        {
            rendered.pop();
        }
        if rendered.ends_with('.') {
            rendered.pop();
        }
    }
    let (integer, fraction) = rendered.split_once('.').unwrap_or((&rendered, ""));
    let mut integer = format!("{integer:0>minimum_integer$}");
    if let Some(group) = integer_pattern.rfind(format.grouping_separator) {
        let size = integer_pattern[group + format.grouping_separator.len_utf8()..]
            .chars()
            .filter(|c| *c == format.zero_digit || *c == format.digit)
            .count();
        if size > 0 {
            let chars = integer.chars().rev().collect::<Vec<_>>();
            integer = chars
                .chunks(size)
                .map(|chunk| chunk.iter().collect::<String>())
                .collect::<Vec<_>>()
                .join(&format.grouping_separator.to_string())
                .chars()
                .rev()
                .collect();
        }
    }
    let mut output = String::new();
    if negative && alternatives.len() == 1 {
        output.push(format.minus_sign);
    }
    output.push_str(&selected[..first]);
    output.push_str(&integer);
    if !fraction.is_empty() {
        output.push(format.decimal_separator);
        output.push_str(fraction);
    }
    output.push_str(&selected[last + selected[last..].chars().next().map_or(0, char::len_utf8)..]);
    if format.zero_digit != '0' {
        output = output
            .chars()
            .map(|c| {
                c.to_digit(10)
                    .and_then(|digit| char::from_u32(u32::from(format.zero_digit) + digit))
                    .unwrap_or(c)
            })
            .collect();
    }
    Ok(output)
}
impl function::Function for CurrentNode {
    fn evaluate<'c, 'd>(
        &self,
        context: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: Vec<SxdValue<'d>>,
    ) -> std::result::Result<SxdValue<'d>, function::Error> {
        if !args.is_empty() {
            return Err(function::Error::TooManyArguments {
                expected: 0,
                actual: args.len(),
            });
        }
        let mut node = nodeset::Node::Root(context.node.document().root());
        for index in &self.path {
            node = node
                .children()
                .get(*index)
                .cloned()
                .ok_or_else(|| function::Error::Other {
                    what: "current() context is stale".into(),
                })?;
        }
        let mut set = nodeset::Nodeset::new();
        set.add(node);
        Ok(SxdValue::Nodeset(set))
    }
}
