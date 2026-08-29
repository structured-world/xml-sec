use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::Arc;

use crate::budget::Meter;
use crate::compiler::{
    AttributeValueTemplate, AvtPart, Instruction, Sort, Stylesheet, Template, Variable,
};
use crate::serializer::serialize;
use crate::xpath::{Evaluator, SourceNode, XPathValue};
use crate::{
    Attribute, BudgetKind, Document, Error, ExecutionBudget, ExpandedName, Namespace, NodeId,
    NodeKind, Resolver, Result, SerializedOutput, Value,
};

/// Top-level stylesheet parameters supplied by the caller.
pub type Parameters = HashMap<ExpandedName, Value>;

/// Explicit inputs controlling one stylesheet execution.
#[derive(Debug, Clone)]
pub struct ExecutionOptions {
    pub budget: ExecutionBudget,
    pub initial_mode: Option<ExpandedName>,
    pub initial_template: Option<ExpandedName>,
}

/// One `xsl:message` emitted during execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub content: String,
    pub terminate: bool,
}

/// Successful transformation output.
#[derive(Debug, Clone)]
pub struct TransformResult {
    pub document: Document,
    pub serialized: SerializedOutput,
    pub messages: Vec<Message>,
}

impl Stylesheet {
    /// Execute this compiled stylesheet against one explicit source document.
    pub fn execute<R: Resolver + 'static>(
        &self,
        source: &Document,
        parameters: &Parameters,
        resolver: Arc<R>,
        options: ExecutionOptions,
    ) -> Result<TransformResult> {
        let source_bytes = source.source_xml().map_or(0, str::len);
        let prepared = self.prepare_source(source)?;
        let mut state = Execution::new(
            self,
            &prepared,
            parameters,
            resolver,
            options.budget,
            source_bytes,
        )?;
        let root = SourceNode::Node(prepared.root());
        if let Some(name) = options.initial_template {
            state.call_named(&name, &HashMap::new(), &root, 1, 1, 1)?;
        } else {
            state.apply_one(
                root,
                options.initial_mode.as_ref(),
                &HashMap::new(),
                ApplyFrame::new(1, 1, 1),
            )?;
        }
        let serialized = serialize(&state.result, &self.output, &mut state.meter)?;
        Ok(TransformResult {
            document: state.result,
            serialized,
            messages: state.messages,
        })
    }

    fn prepare_source(&self, source: &Document) -> Result<Document> {
        if self.whitespace.is_empty() {
            return Ok(source.clone());
        }
        let mut prepared = source.clone();
        let original = source.clone();
        prepared.retain_nodes(|id, node| {
            let NodeKind::Text { value, .. } = &node.kind else {
                return true;
            };
            if !value.chars().all(char::is_whitespace) {
                return true;
            }
            let Some(parent) = node.parent.and_then(|parent| original.node(parent)) else {
                return true;
            };
            let NodeKind::Element {
                name, attributes, ..
            } = &parent.kind
            else {
                return true;
            };
            if attributes.iter().any(|attribute| {
                attribute.name.namespace.as_deref() == Some("http://www.w3.org/XML/1998/namespace")
                    && attribute.name.local == "space"
                    && attribute.value == "preserve"
            }) {
                return true;
            }
            let decision = self
                .whitespace
                .iter()
                .filter(|(test, _, _, _)| test.matches(name))
                .max_by_key(|(_, _, precedence, order)| (*precedence, *order));
            !matches!(decision, Some((_, false, _, _))) || id == original.root()
        });
        // XPath is evaluated by the independent SXD engine, so keep its lexical input in
        // lockstep with the filtered semantic tree.
        let mut meter = Meter::new(
            ExecutionBudget::unlimited(),
            source.source_xml().map_or(0, str::len),
        )?;
        let lexical = serialize(
            &prepared,
            &crate::serializer::OutputDefinition::default(),
            &mut meter,
        )?;
        prepared.rebuild_source_xml(
            String::from_utf8(lexical.bytes)
                .map_err(|_| Error::Xml("prepared source is not UTF-8".into()))?,
        );
        Ok(prepared)
    }
}

struct Execution<'a> {
    stylesheet: &'a Stylesheet,
    evaluator: Evaluator<'a>,
    result: Document,
    output_stack: Vec<NodeId>,
    scopes: Vec<HashMap<ExpandedName, Value>>,
    meter: Meter,
    messages: Vec<Message>,
    // Retain the caller boundary for the full execution lifetime. The following
    // resolver-sandbox task wires document() through this same contract.
    _resolver: Arc<dyn Resolver>,
    modes: Vec<Option<ExpandedName>>,
}

#[derive(Clone, Copy)]
struct ApplyFrame {
    max_precedence: Option<usize>,
    position: usize,
    size: usize,
    depth: usize,
}

impl ApplyFrame {
    const fn new(position: usize, size: usize, depth: usize) -> Self {
        Self {
            max_precedence: None,
            position,
            size,
            depth,
        }
    }
}

impl<'a> Execution<'a> {
    fn new<R: Resolver + 'static>(
        stylesheet: &'a Stylesheet,
        source: &'a Document,
        parameters: &Parameters,
        resolver: Arc<R>,
        budget: ExecutionBudget,
        source_bytes: usize,
    ) -> Result<Self> {
        let mut state = Self {
            stylesheet,
            evaluator: Evaluator::new(source)?,
            result: Document::empty(None),
            output_stack: vec![NodeId(0)],
            scopes: vec![parameters.clone()],
            meter: Meter::new(budget, source_bytes)?,
            messages: vec![],
            _resolver: resolver,
            modes: vec![None],
        };
        state.evaluator.initialize_xslt(
            &stylesheet.keys,
            &stylesheet.decimal_formats,
            &mut state.meter,
        )?;
        state.initialize_globals(parameters)?;
        Ok(state)
    }

    fn initialize_globals(&mut self, parameters: &Parameters) -> Result<()> {
        let mut declarations = self.stylesheet.globals.iter().collect::<Vec<_>>();
        declarations.sort_by_key(|global| (global.precedence, global.order));
        for global in declarations {
            if global.is_parameter && parameters.contains_key(&global.variable.name) {
                continue;
            }
            let value = self.evaluate_variable(
                &global.variable,
                &SourceNode::Node(self.evaluator.source.root()),
                1,
                1,
                1,
            )?;
            self.scopes[0].insert(global.variable.name.clone(), value);
        }
        Ok(())
    }

    fn variables(&self) -> HashMap<ExpandedName, Value> {
        let mut variables = HashMap::new();
        for scope in &self.scopes {
            variables.extend(scope.clone())
        }
        variables
    }

    fn apply_one(
        &mut self,
        node: SourceNode,
        mode: Option<&ExpandedName>,
        params: &HashMap<ExpandedName, Value>,
        frame: ApplyFrame,
    ) -> Result<()> {
        let ApplyFrame {
            max_precedence,
            position,
            size,
            depth,
        } = frame;
        self.meter.recursion(depth)?;
        self.meter.charge(BudgetKind::TemplateApplications, 1)?;
        let variables = self.variables();
        let mut selected = None::<&Template>;
        for template in self.stylesheet.templates.iter() {
            if template.pattern.is_none()
                || template.mode.as_ref() != mode
                || max_precedence.is_some_and(|max| template.precedence >= max)
            {
                continue;
            }
            let Some(pattern) = template.pattern.as_ref() else {
                continue;
            };
            if self
                .evaluator
                .matches(pattern, &node, &variables, &mut self.meter)?
                && selected.is_none_or(|current| {
                    template.precedence > current.precedence
                        || (template.precedence == current.precedence
                            && (template.priority > current.priority
                                || (template.priority == current.priority
                                    && template.order > current.order)))
                })
            {
                selected = Some(template)
            }
        }
        if let Some(template) = selected {
            self.modes.push(mode.cloned());
            let result = self.execute_template(template, node, params, position, size, depth);
            self.modes.pop();
            result
        } else {
            self.built_in(node, mode, depth)
        }
    }

    fn execute_template(
        &mut self,
        template: &Template,
        node: SourceNode,
        params: &HashMap<ExpandedName, Value>,
        position: usize,
        size: usize,
        depth: usize,
    ) -> Result<()> {
        let mut scope = HashMap::new();
        for parameter in &template.params {
            let value = params.get(&parameter.name).cloned().map_or_else(
                || self.evaluate_variable(parameter, &node, position, size, depth),
                Ok,
            )?;
            scope.insert(parameter.name.clone(), value);
        }
        self.scopes.push(scope);
        let result = self.execute_sequence(
            &template.body,
            &node,
            position,
            size,
            depth,
            Some(template.precedence),
        );
        self.scopes.pop();
        result
    }

    fn built_in(
        &mut self,
        node: SourceNode,
        mode: Option<&ExpandedName>,
        depth: usize,
    ) -> Result<()> {
        match &node {
            SourceNode::Node(id) => match &self.evaluator.source.node(*id).map(|node| &node.kind) {
                Some(NodeKind::Root | NodeKind::Element { .. }) => {
                    let children = self.evaluator.children(&node);
                    let size = children.len();
                    for (index, child) in children.into_iter().enumerate() {
                        self.apply_one(
                            child,
                            mode,
                            &HashMap::new(),
                            ApplyFrame::new(index + 1, size, depth + 1),
                        )?;
                    }
                    Ok(())
                }
                Some(NodeKind::Text { value, .. }) => self.append_text(value, false),
                _ => Ok(()),
            },
            SourceNode::Attribute { .. } | SourceNode::Namespace { .. } => {
                let value = self.evaluator.string_value(&node);
                self.append_text(&value, false)
            }
        }
    }

    fn execute_sequence(
        &mut self,
        instructions: &[Instruction],
        node: &SourceNode,
        position: usize,
        size: usize,
        depth: usize,
        current_precedence: Option<usize>,
    ) -> Result<()> {
        self.meter.recursion(depth)?;
        for instruction in instructions {
            self.execute_instruction(instruction, node, position, size, depth, current_precedence)?;
        }
        Ok(())
    }

    fn execute_instruction(
        &mut self,
        instruction: &Instruction,
        node: &SourceNode,
        position: usize,
        size: usize,
        depth: usize,
        current_precedence: Option<usize>,
    ) -> Result<()> {
        match instruction {
            Instruction::Text(value, disable) => self.append_text(value, *disable),
            Instruction::LiteralElement {
                name,
                prefix,
                attributes,
                namespaces,
                children,
                attribute_sets,
            } => {
                let (name, prefix) = self.alias_name(name, prefix.as_deref());
                let mut result_namespaces = Vec::<Namespace>::new();
                for namespace in namespaces {
                    let mapped = self.alias_namespace(namespace);
                    if let Some(existing) = result_namespaces
                        .iter_mut()
                        .find(|existing| existing.prefix == mapped.prefix)
                    {
                        *existing = mapped;
                    } else {
                        result_namespaces.push(mapped);
                    }
                }
                let parent = self.parent();
                let id = self.push_node(
                    parent,
                    NodeKind::Element {
                        name,
                        prefix,
                        attributes: vec![],
                        namespaces: result_namespaces,
                    },
                )?;
                self.output_stack.push(id);
                for set in attribute_sets {
                    self.apply_attribute_set(set, node, position, size, depth, &mut Vec::new())?;
                }
                for attribute in attributes {
                    let value = self.evaluate_avt(&attribute.value, node, position, size)?;
                    let (name, prefix) =
                        self.alias_name(&attribute.name, attribute.prefix.as_deref());
                    self.add_attribute(Attribute {
                        name,
                        prefix,
                        value,
                    })?;
                }
                let result = self.execute_sequence(
                    children,
                    node,
                    position,
                    size,
                    depth + 1,
                    current_precedence,
                );
                self.output_stack.pop();
                result
            }
            Instruction::ApplyTemplates {
                select,
                mode,
                sorts,
                parameters,
            } => {
                let mut nodes = self.select_nodes(select, node, position, size)?;
                self.sort_nodes(&mut nodes, sorts)?;
                let supplied =
                    self.evaluate_with_params(parameters, node, position, size, depth)?;
                let total = nodes.len();
                for (index, selected) in nodes.into_iter().enumerate() {
                    self.apply_one(
                        selected,
                        mode.as_ref(),
                        &supplied,
                        ApplyFrame::new(index + 1, total, depth + 1),
                    )?
                }
                Ok(())
            }
            Instruction::ApplyImports => {
                let mode = self.modes.last().cloned().flatten();
                self.apply_one(
                    node.clone(),
                    mode.as_ref(),
                    &HashMap::new(),
                    ApplyFrame {
                        max_precedence: current_precedence,
                        position,
                        size,
                        depth: depth + 1,
                    },
                )
            }
            Instruction::CallTemplate { name, parameters } => {
                let supplied =
                    self.evaluate_with_params(parameters, node, position, size, depth)?;
                self.call_named(name, &supplied, node, position, size, depth + 1)
            }
            Instruction::ForEach {
                select,
                sorts,
                body,
            } => {
                let mut nodes = self.select_nodes(select, node, position, size)?;
                self.sort_nodes(&mut nodes, sorts)?;
                let total = nodes.len();
                for (index, selected) in nodes.iter().enumerate() {
                    self.scopes.push(HashMap::new());
                    let result = self.execute_sequence(
                        body,
                        selected,
                        index + 1,
                        total,
                        depth + 1,
                        current_precedence,
                    );
                    self.scopes.pop();
                    result?
                }
                Ok(())
            }
            Instruction::If { test, body } => {
                if self.evaluate(test, node, position, size)?.boolean() {
                    self.execute_sequence(
                        body,
                        node,
                        position,
                        size,
                        depth + 1,
                        current_precedence,
                    )?
                }
                Ok(())
            }
            Instruction::Choose {
                branches,
                otherwise,
            } => {
                for (test, body) in branches {
                    if self.evaluate(test, node, position, size)?.boolean() {
                        return self.execute_sequence(
                            body,
                            node,
                            position,
                            size,
                            depth + 1,
                            current_precedence,
                        );
                    }
                }
                self.execute_sequence(
                    otherwise,
                    node,
                    position,
                    size,
                    depth + 1,
                    current_precedence,
                )
            }
            Instruction::ValueOf {
                select,
                disable_output_escaping,
            } => {
                let value = self
                    .evaluate(select, node, position, size)?
                    .string(&self.evaluator);
                self.append_text(&value, *disable_output_escaping)
            }
            Instruction::CopyOf(select) => {
                match self.evaluate(select, node, position, size)? {
                    XPathValue::NodeSet(nodes) => {
                        for selected in nodes {
                            self.copy_source(&selected, self.parent())?
                        }
                    }
                    value => {
                        let text = value.string(&self.evaluator);
                        self.append_text(&text, false)?
                    }
                }
                Ok(())
            }
            Instruction::Copy {
                body,
                attribute_sets,
            } => {
                match node {
                    SourceNode::Node(id) => {
                        if let Some(source) = self.evaluator.source.node(*id) {
                            match &source.kind {
                                NodeKind::Element {
                                    name,
                                    prefix,
                                    attributes: _,
                                    namespaces,
                                } => {
                                    let target = self.push_node(
                                        self.parent(),
                                        NodeKind::Element {
                                            name: name.clone(),
                                            prefix: prefix.clone(),
                                            attributes: vec![],
                                            namespaces: namespaces.clone(),
                                        },
                                    )?;
                                    self.output_stack.push(target);
                                    for set in attribute_sets {
                                        self.apply_attribute_set(
                                            set,
                                            node,
                                            position,
                                            size,
                                            depth,
                                            &mut Vec::new(),
                                        )?;
                                    }
                                    let result = self.execute_sequence(
                                        body,
                                        node,
                                        position,
                                        size,
                                        depth + 1,
                                        current_precedence,
                                    );
                                    self.output_stack.pop();
                                    result?
                                }
                                NodeKind::Text { value, .. } => self.append_text(value, false)?,
                                NodeKind::Comment(value) => {
                                    self.push_node(
                                        self.parent(),
                                        NodeKind::Comment(value.clone()),
                                    )?;
                                }
                                NodeKind::ProcessingInstruction { target, value } => {
                                    self.push_node(
                                        self.parent(),
                                        NodeKind::ProcessingInstruction {
                                            target: target.clone(),
                                            value: value.clone(),
                                        },
                                    )?;
                                }
                                NodeKind::Root => self.execute_sequence(
                                    body,
                                    node,
                                    position,
                                    size,
                                    depth + 1,
                                    current_precedence,
                                )?,
                            }
                        }
                    }
                    SourceNode::Attribute { owner, index } => {
                        if let Some(NodeKind::Element { attributes, .. }) =
                            self.evaluator.source.node(*owner).map(|n| &n.kind)
                            && let Some(attribute) = attributes.get(*index)
                        {
                            self.add_attribute(attribute.clone())?
                        }
                    }
                    SourceNode::Namespace { .. } => {}
                }
                Ok(())
            }
            Instruction::Element {
                name,
                namespace,
                body,
                attribute_sets,
            } => {
                let lexical = self.evaluate_avt(name, node, position, size)?;
                let (prefix, local) = split_name(&lexical)?;
                let namespace = namespace
                    .as_ref()
                    .map(|value| self.evaluate_avt(value, node, position, size))
                    .transpose()?
                    .or_else(|| {
                        prefix
                            .as_deref()
                            .and_then(|prefix| self.lookup_namespace(prefix))
                    });
                let namespaces = namespace
                    .as_ref()
                    .map(|uri| {
                        vec![Namespace {
                            prefix: prefix.clone(),
                            uri: uri.clone(),
                        }]
                    })
                    .unwrap_or_default();
                let id = self.push_node(
                    self.parent(),
                    NodeKind::Element {
                        name: ExpandedName::new(namespace, local),
                        prefix,
                        namespaces,
                        attributes: vec![],
                    },
                )?;
                self.output_stack.push(id);
                for set in attribute_sets {
                    self.apply_attribute_set(set, node, position, size, depth, &mut Vec::new())?;
                }
                let result = self.execute_sequence(
                    body,
                    node,
                    position,
                    size,
                    depth + 1,
                    current_precedence,
                );
                self.output_stack.pop();
                result
            }
            Instruction::Attribute {
                name,
                namespace,
                body,
            } => {
                let lexical = self.evaluate_avt(name, node, position, size)?;
                let (prefix, local) = split_name(&lexical)?;
                let namespace = namespace
                    .as_ref()
                    .map(|value| self.evaluate_avt(value, node, position, size))
                    .transpose()?
                    .or_else(|| {
                        prefix
                            .as_deref()
                            .and_then(|prefix| self.lookup_namespace(prefix))
                    });
                let value =
                    self.capture_text(body, node, position, size, depth, current_precedence)?;
                self.add_attribute(Attribute {
                    name: ExpandedName::new(namespace, local),
                    prefix,
                    value,
                })
            }
            Instruction::Comment(body) => {
                let value =
                    self.capture_text(body, node, position, size, depth, current_precedence)?;
                if value.contains("--") || value.ends_with('-') {
                    return Err(Error::Dynamic(
                        "xsl:comment produced invalid comment content".into(),
                    ));
                }
                self.push_node(self.parent(), NodeKind::Comment(value))?;
                Ok(())
            }
            Instruction::Processing { name, body } => {
                let target = self.evaluate_avt(name, node, position, size)?;
                if target.eq_ignore_ascii_case("xml") || target.contains(':') {
                    return Err(Error::Dynamic(
                        "invalid processing-instruction target".into(),
                    ));
                }
                let value =
                    self.capture_text(body, node, position, size, depth, current_precedence)?;
                if value.contains("?>") {
                    return Err(Error::Dynamic("processing instruction contains ?>".into()));
                }
                self.push_node(
                    self.parent(),
                    NodeKind::ProcessingInstruction {
                        target,
                        value: (!value.is_empty()).then_some(value),
                    },
                )?;
                Ok(())
            }
            Instruction::Number(number) => {
                let values = if let Some(expression) = &number.value {
                    vec![
                        self.evaluate(expression, node, position, size)?
                            .number(&self.evaluator),
                    ]
                } else {
                    self.number_sequence(number, node)?
                };
                self.append_text(
                    &format_number_sequence(
                        &values,
                        &number.format,
                        number.lang.as_deref(),
                        number.letter_value.as_deref(),
                        number.grouping_separator,
                        number.grouping_size,
                    ),
                    false,
                )
            }
            Instruction::Variable(variable) => {
                let value = self.evaluate_variable(variable, node, position, size, depth)?;
                self.scopes
                    .last_mut()
                    .ok_or_else(|| Error::Dynamic("missing variable scope".into()))?
                    .insert(variable.name.clone(), value);
                Ok(())
            }
            Instruction::Message { terminate, body } => {
                self.meter.charge(BudgetKind::Messages, 1)?;
                let content =
                    self.capture_text(body, node, position, size, depth, current_precedence)?;
                self.messages.push(Message {
                    content: content.clone(),
                    terminate: *terminate,
                });
                if *terminate {
                    Err(Error::Dynamic(format!(
                        "xsl:message terminated transformation: {content}"
                    )))
                } else {
                    Ok(())
                }
            }
            Instruction::Fallback(body) => {
                self.execute_sequence(body, node, position, size, depth + 1, current_precedence)
            }
        }
    }

    fn evaluate(
        &mut self,
        expression: &crate::compiler::Expression,
        node: &SourceNode,
        position: usize,
        size: usize,
    ) -> Result<XPathValue> {
        self.evaluator.evaluate(
            expression,
            node,
            position,
            size,
            &self.variables(),
            &mut self.meter,
        )
    }
    fn select_nodes(
        &mut self,
        expression: &crate::compiler::Expression,
        node: &SourceNode,
        position: usize,
        size: usize,
    ) -> Result<Vec<SourceNode>> {
        match self.evaluate(expression, node, position, size)? {
            XPathValue::NodeSet(nodes) => Ok(nodes),
            _ => Err(Error::Dynamic(format!(
                "XPath `{}` must return a node-set",
                expression.source
            ))),
        }
    }
    fn evaluate_variable(
        &mut self,
        variable: &Variable,
        node: &SourceNode,
        position: usize,
        size: usize,
        depth: usize,
    ) -> Result<Value> {
        if let Some(select) = &variable.select {
            Ok(xpath_to_public(
                self.evaluate(select, node, position, size)?,
            ))
        } else if variable.content.is_empty() {
            Ok(Value::String(String::new()))
        } else {
            Ok(Value::ResultTreeFragment(self.capture_text(
                &variable.content,
                node,
                position,
                size,
                depth,
                None,
            )?))
        }
    }
    fn evaluate_with_params(
        &mut self,
        parameters: &[crate::compiler::WithParam],
        node: &SourceNode,
        position: usize,
        size: usize,
        depth: usize,
    ) -> Result<HashMap<ExpandedName, Value>> {
        parameters
            .iter()
            .map(|parameter| {
                self.evaluate_variable(&parameter.variable, node, position, size, depth)
                    .map(|value| (parameter.variable.name.clone(), value))
            })
            .collect()
    }
    fn call_named(
        &mut self,
        name: &ExpandedName,
        params: &HashMap<ExpandedName, Value>,
        node: &SourceNode,
        position: usize,
        size: usize,
        depth: usize,
    ) -> Result<()> {
        let template = self
            .stylesheet
            .templates
            .iter()
            .filter(|template| template.name.as_ref() == Some(name))
            .max_by_key(|template| (template.precedence, template.order))
            .ok_or_else(|| Error::Dynamic(format!("named template {} not found", name.local)))?;
        self.execute_template(template, node.clone(), params, position, size, depth)
    }
    fn evaluate_avt(
        &mut self,
        avt: &AttributeValueTemplate,
        node: &SourceNode,
        position: usize,
        size: usize,
    ) -> Result<String> {
        let mut output = String::new();
        for part in &avt.0 {
            match part {
                AvtPart::Literal(value) => output.push_str(value),
                AvtPart::Expression(expression) => {
                    let value = self
                        .evaluate(expression, node, position, size)?
                        .string(&self.evaluator);
                    output.push_str(&value)
                }
            }
        }
        Ok(output)
    }
    fn sort_nodes(&mut self, nodes: &mut [SourceNode], sorts: &[Sort]) -> Result<()> {
        if sorts.is_empty() {
            return Ok(());
        }
        let variables = self.variables();
        let mut keyed = Vec::with_capacity(nodes.len());
        for (index, node) in nodes.iter().enumerate() {
            let mut keys = vec![];
            for sort in sorts {
                let value = self.evaluator.evaluate(
                    &sort.select,
                    node,
                    index + 1,
                    nodes.len(),
                    &variables,
                    &mut self.meter,
                )?;
                let key = if sort.data_type == "number" {
                    SortKey::Number(value.number(&self.evaluator))
                } else {
                    SortKey::Text(value.string(&self.evaluator))
                };
                keys.push(key);
            }
            keyed.push((node.clone(), keys, index));
        }
        let mut comparisons = 0usize;
        keyed.sort_by(|left, right| {
            comparisons = comparisons.saturating_add(1);
            for ((l, r), spec) in left.1.iter().zip(&right.1).zip(sorts) {
                let mut ordering = l.compare(r, spec.case_order.as_deref(), spec.lang.as_deref());
                if spec.order == "descending" {
                    ordering = ordering.reverse()
                }
                if ordering != Ordering::Equal {
                    return ordering;
                }
            }
            left.2.cmp(&right.2)
        });
        self.meter
            .charge(BudgetKind::SortComparisons, comparisons)?;
        for (target, (node, _, _)) in nodes.iter_mut().zip(keyed) {
            *target = node
        }
        Ok(())
    }
    fn capture_text(
        &mut self,
        body: &[Instruction],
        node: &SourceNode,
        position: usize,
        size: usize,
        depth: usize,
        precedence: Option<usize>,
    ) -> Result<String> {
        let previous = std::mem::replace(&mut self.result, Document::empty(None));
        let stack = std::mem::replace(&mut self.output_stack, vec![NodeId(0)]);
        let result = self.execute_sequence(body, node, position, size, depth + 1, precedence);
        let captured = self.result.string_value(self.result.root());
        self.result = previous;
        self.output_stack = stack;
        result?;
        Ok(captured)
    }
    fn copy_source(&mut self, node: &SourceNode, parent: NodeId) -> Result<()> {
        match node {
            SourceNode::Node(id) => {
                let source = self
                    .evaluator
                    .source
                    .node(*id)
                    .ok_or_else(|| Error::Dynamic("stale source node".into()))?;
                if matches!(source.kind, NodeKind::Root) {
                    for child in &source.children {
                        self.copy_source(&SourceNode::Node(*child), parent)?
                    }
                    return Ok(());
                }
                let target = self.push_node(parent, source.kind.clone())?;
                for child in &source.children {
                    self.copy_source(&SourceNode::Node(*child), target)?
                }
            }
            SourceNode::Attribute { owner, index } => {
                if let Some(NodeKind::Element { attributes, .. }) =
                    self.evaluator.source.node(*owner).map(|n| &n.kind)
                    && let Some(attribute) = attributes.get(*index)
                {
                    self.add_attribute(attribute.clone())?
                }
            }
            SourceNode::Namespace { owner, index } => {
                if let Some(NodeKind::Element { namespaces, .. }) =
                    self.evaluator.source.node(*owner).map(|n| &n.kind)
                    && let Some(namespace) = namespaces.get(*index)
                {
                    self.add_namespace(namespace.clone())?
                }
            }
        }
        Ok(())
    }
    fn apply_attribute_set(
        &mut self,
        name: &ExpandedName,
        node: &SourceNode,
        position: usize,
        size: usize,
        depth: usize,
        active: &mut Vec<ExpandedName>,
    ) -> Result<()> {
        if active.contains(name) {
            return Err(Error::Static("attribute-set cycle".into()));
        }
        active.push(name.clone());
        let sets = self
            .stylesheet
            .attribute_sets
            .iter()
            .filter(|set| &set.name == name)
            .collect::<Vec<_>>();
        for set in sets {
            for used in &set.uses {
                self.apply_attribute_set(used, node, position, size, depth + 1, active)?
            }
            self.execute_sequence(&set.attributes, node, position, size, depth + 1, None)?
        }
        active.pop();
        Ok(())
    }
    fn parent(&self) -> NodeId {
        *self.output_stack.last().unwrap_or(&NodeId(0))
    }
    fn push_node(&mut self, parent: NodeId, kind: NodeKind) -> Result<NodeId> {
        self.meter.charge(BudgetKind::ResultNodes, 1)?;
        Ok(self.result.push(parent, kind, None))
    }
    fn append_text(&mut self, value: &str, disable: bool) -> Result<()> {
        self.meter.charge(BudgetKind::OwnedBytes, value.len())?;
        self.push_node(
            self.parent(),
            NodeKind::Text {
                value: value.into(),
                disable_output_escaping: disable,
            },
        )?;
        Ok(())
    }
    fn add_attribute(&mut self, attribute: Attribute) -> Result<()> {
        let parent = self.parent();
        let node = self
            .result
            .node_mut(parent)
            .ok_or_else(|| Error::Dynamic("attribute has no result parent".into()))?;
        let NodeKind::Element { attributes, .. } = &mut node.kind else {
            return Err(Error::Dynamic(
                "attribute cannot be added after a non-element result".into(),
            ));
        };
        if !node.children.is_empty() {
            return Err(Error::Dynamic(
                "attribute cannot be added after result children".into(),
            ));
        }
        if let Some(existing) = attributes
            .iter_mut()
            .find(|existing| existing.name == attribute.name)
        {
            *existing = attribute
        } else {
            attributes.push(attribute)
        }
        Ok(())
    }
    fn add_namespace(&mut self, namespace: Namespace) -> Result<()> {
        let node = self
            .result
            .node_mut(self.parent())
            .ok_or_else(|| Error::Dynamic("namespace has no result parent".into()))?;
        let NodeKind::Element { namespaces, .. } = &mut node.kind else {
            return Err(Error::Dynamic(
                "namespace requires an element result".into(),
            ));
        };
        if !node.children.is_empty() {
            return Err(Error::Dynamic(
                "namespace cannot be added after result children".into(),
            ));
        }
        if let Some(existing) = namespaces
            .iter_mut()
            .find(|existing| existing.prefix == namespace.prefix)
        {
            *existing = namespace
        } else {
            namespaces.push(namespace)
        }
        Ok(())
    }
    fn lookup_namespace(&self, prefix: &str) -> Option<String> {
        self.result
            .node(self.parent())
            .and_then(|node| match &node.kind {
                NodeKind::Element { namespaces, .. } => namespaces
                    .iter()
                    .rev()
                    .find(|namespace| namespace.prefix.as_deref() == Some(prefix))
                    .map(|namespace| namespace.uri.clone()),
                _ => None,
            })
    }

    fn alias_name(
        &self,
        name: &ExpandedName,
        prefix: Option<&str>,
    ) -> (ExpandedName, Option<String>) {
        let Some(alias) = self
            .stylesheet
            .namespace_aliases
            .iter()
            .rev()
            .find(|alias| alias.stylesheet_namespace == name.namespace)
        else {
            return (name.clone(), prefix.map(str::to_owned));
        };
        (
            ExpandedName::new(alias.result_namespace.clone(), name.local.clone()),
            (!alias.result_prefix.is_empty()).then(|| alias.result_prefix.clone()),
        )
    }

    fn alias_namespace(&self, namespace: &Namespace) -> Namespace {
        let Some(alias) = self
            .stylesheet
            .namespace_aliases
            .iter()
            .rev()
            .find(|alias| alias.stylesheet_namespace.as_deref() == Some(&namespace.uri))
        else {
            return namespace.clone();
        };
        Namespace {
            prefix: (!alias.result_prefix.is_empty()).then(|| alias.result_prefix.clone()),
            uri: alias.result_namespace.clone().unwrap_or_default(),
        }
    }
    fn number_sequence(
        &mut self,
        instruction: &crate::compiler::NumberInstruction,
        node: &SourceNode,
    ) -> Result<Vec<f64>> {
        let SourceNode::Node(current) = node else {
            return Ok(Vec::new());
        };
        let mut lineage = Vec::new();
        let mut cursor = Some(*current);
        while let Some(id) = cursor {
            lineage.push(id);
            cursor = self.evaluator.source.node(id).and_then(|node| node.parent);
        }
        let variables = self.variables();
        let mut matches = |this: &mut Self, id: NodeId| -> Result<bool> {
            if let Some(pattern) = &instruction.count {
                this.evaluator
                    .matches(pattern, &SourceNode::Node(id), &variables, &mut this.meter)
            } else {
                Ok(same_node_kind_and_name(this.evaluator.source, *current, id))
            }
        };
        let from = |this: &mut Self, id: NodeId| -> Result<bool> {
            instruction.from.as_ref().map_or(Ok(false), |pattern| {
                this.evaluator
                    .matches(pattern, &SourceNode::Node(id), &variables, &mut this.meter)
            })
        };
        match instruction.level.as_str() {
            "single" => {
                for id in lineage {
                    if from(self, id)? {
                        break;
                    }
                    if matches(self, id)? {
                        return Ok(vec![self.sibling_number(id, &mut matches)? as f64]);
                    }
                }
                Ok(Vec::new())
            }
            "multiple" => {
                let mut values = Vec::new();
                for id in lineage.into_iter().rev() {
                    if from(self, id)? {
                        values.clear();
                        continue;
                    }
                    if matches(self, id)? {
                        values.push(self.sibling_number(id, &mut matches)? as f64);
                    }
                }
                Ok(values)
            }
            "any" => {
                let mut boundary = None;
                for id in &lineage {
                    if from(self, *id)? {
                        boundary = Some(*id);
                        break;
                    }
                }
                let mut count = 0usize;
                let ids = self
                    .evaluator
                    .source
                    .nodes()
                    .map(|(id, _)| id)
                    .collect::<Vec<_>>();
                for id in ids {
                    if Some(id) == boundary {
                        count = 0;
                    }
                    if matches(self, id)? {
                        count += 1;
                    }
                    if id == *current {
                        break;
                    }
                }
                Ok((count > 0).then_some(count as f64).into_iter().collect())
            }
            level => Err(Error::Static(format!(
                "unsupported xsl:number level {level}"
            ))),
        }
    }

    fn sibling_number(
        &mut self,
        id: NodeId,
        matches: &mut impl FnMut(&mut Self, NodeId) -> Result<bool>,
    ) -> Result<usize> {
        let Some(parent) = self.evaluator.source.node(id).and_then(|node| node.parent) else {
            return Ok(1);
        };
        let siblings = self
            .evaluator
            .source
            .node(parent)
            .map(|node| node.children.clone())
            .unwrap_or_default();
        let mut count = 0;
        for sibling in siblings {
            if matches(self, sibling)? {
                count += 1;
            }
            if sibling == id {
                break;
            }
        }
        Ok(count)
    }
}

enum SortKey {
    Text(String),
    Number(f64),
}
impl SortKey {
    fn compare(&self, other: &Self, case_order: Option<&str>, _lang: Option<&str>) -> Ordering {
        match (self, other) {
            (Self::Text(left), Self::Text(right)) => {
                let primary = left.to_lowercase().cmp(&right.to_lowercase());
                if primary != Ordering::Equal {
                    return primary;
                }
                match case_order {
                    Some("upper-first") => right.cmp(left),
                    Some("lower-first") => left.cmp(right),
                    _ => left.cmp(right),
                }
            }
            (Self::Number(left), Self::Number(right)) => {
                left.partial_cmp(right).unwrap_or_else(|| {
                    if left.is_nan() && right.is_nan() {
                        Ordering::Equal
                    } else if left.is_nan() {
                        Ordering::Less
                    } else {
                        Ordering::Greater
                    }
                })
            }
            _ => Ordering::Equal,
        }
    }
}
fn xpath_to_public(value: XPathValue) -> Value {
    match value {
        XPathValue::NodeSet(nodes) => Value::NodeSet(
            nodes
                .into_iter()
                .filter_map(|node| match node {
                    SourceNode::Node(id) => Some(id),
                    _ => None,
                })
                .collect(),
        ),
        XPathValue::Boolean(value) => Value::Boolean(value),
        XPathValue::Number(value) => Value::Number(value),
        XPathValue::String(value) => Value::String(value),
    }
}
fn split_name(value: &str) -> Result<(Option<String>, String)> {
    if let Some((prefix, local)) = value.split_once(':') {
        if prefix.is_empty() || local.is_empty() || local.contains(':') {
            return Err(Error::Dynamic(format!("invalid computed QName {value}")));
        }
        Ok((Some(prefix.into()), local.into()))
    } else if value.is_empty() {
        Err(Error::Dynamic("computed QName is empty".into()))
    } else {
        Ok((None, value.into()))
    }
}
fn format_number_sequence(
    values: &[f64],
    format: &str,
    _lang: Option<&str>,
    letter_value: Option<&str>,
    separator: Option<char>,
    size: Option<usize>,
) -> String {
    values
        .iter()
        .map(|value| format_number(*value, format, letter_value, separator, size))
        .collect::<Vec<_>>()
        .join(".")
}
fn format_number(
    value: f64,
    format: &str,
    letter_value: Option<&str>,
    separator: Option<char>,
    size: Option<usize>,
) -> String {
    if value.is_nan() {
        return "NaN".into();
    }
    let rounded = value.round();
    let mut output = match format {
        "A" | "a" if letter_value != Some("traditional") => {
            alphabetic(rounded as usize, format == "A")
        }
        "I" | "i" => roman(rounded as usize, format == "I"),
        _ => format!("{rounded:.0}"),
    };
    if let (Some(separator), Some(size)) = (separator, size)
        && size > 0
    {
        let mut chars = output.chars().rev().collect::<Vec<_>>();
        let mut index = size;
        while index < chars.len() {
            chars.insert(index, separator);
            index += size + 1
        }
        output = chars.into_iter().rev().collect()
    }
    output
}

fn same_node_kind_and_name(document: &Document, left: NodeId, right: NodeId) -> bool {
    match (
        document.node(left).map(|node| &node.kind),
        document.node(right).map(|node| &node.kind),
    ) {
        (
            Some(NodeKind::Element { name: left, .. }),
            Some(NodeKind::Element { name: right, .. }),
        ) => left == right,
        (Some(NodeKind::Text { .. }), Some(NodeKind::Text { .. }))
        | (Some(NodeKind::Comment(_)), Some(NodeKind::Comment(_)))
        | (
            Some(NodeKind::ProcessingInstruction { .. }),
            Some(NodeKind::ProcessingInstruction { .. }),
        )
        | (Some(NodeKind::Root), Some(NodeKind::Root)) => true,
        _ => false,
    }
}

fn alphabetic(mut value: usize, upper: bool) -> String {
    if value == 0 {
        return "0".into();
    }
    let mut output = String::new();
    while value > 0 {
        value -= 1;
        let base = if upper { b'A' } else { b'a' };
        output.insert(0, char::from(base + (value % 26) as u8));
        value /= 26;
    }
    output
}

fn roman(mut value: usize, upper: bool) -> String {
    if value == 0 || value > 3999 {
        return value.to_string();
    }
    let mut output = String::new();
    for (number, numeral) in [
        (1000, "M"),
        (900, "CM"),
        (500, "D"),
        (400, "CD"),
        (100, "C"),
        (90, "XC"),
        (50, "L"),
        (40, "XL"),
        (10, "X"),
        (9, "IX"),
        (5, "V"),
        (4, "IV"),
        (1, "I"),
    ] {
        while value >= number {
            output.push_str(numeral);
            value -= number;
        }
    }
    if upper { output } else { output.to_lowercase() }
}
