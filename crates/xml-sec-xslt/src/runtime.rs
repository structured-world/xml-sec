use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use icu_collator::preferences::CollationCaseFirst;
use icu_collator::{Collator, CollatorBorrowed, CollatorPreferences, options::CollatorOptions};
use icu_locale::Locale;

use crate::budget::Meter;
use crate::compiler::{
    AttributeValueTemplate, AvtPart, Expression, ExsltFunction, Instruction, NameTest, Sort,
    Stylesheet, Template, Variable,
};
use crate::expression::innermost_namespaced_call;
use crate::lexical::{is_ncname, unicode_decimal_value};
use crate::serializer::{serialize, serialize_fragment};
use crate::xpath::{
    Evaluator, EvaluatorSourceOptions, PreparedEvaluatorSource, SourceNode, XPathValue,
    prepare_evaluator_source, xpath_number,
};
use crate::{
    Attribute, BudgetKind, Document, Error, ExecutionBudget, ExecutionEnvironment, ExpandedName,
    Namespace, NodeId, NodeKind, NodeReference, Resolver, Result, SerializedOutput, Value,
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

/// Optional preprocessing applied to source and `document()` resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SourceProcessing {
    /// Parse XML without expanding XInclude elements.
    #[default]
    Xml,
    /// Expand XInclude elements through the caller-provided resolver.
    XInclude,
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
    /// Caller-owned secondary result documents keyed by the stylesheet URI.
    ///
    /// The engine never writes these resources to the filesystem or network.
    pub secondary_outputs: Vec<SecondaryOutput>,
    pub messages: Vec<Message>,
}

/// One secondary result produced by a compatible XSLT extension element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecondaryOutput {
    pub uri: String,
    pub serialized: SerializedOutput,
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
        self.execute_with_environment_and_source_processing(
            source,
            parameters,
            ExecutionEnvironment::new(resolver),
            options,
            SourceProcessing::Xml,
        )
    }

    /// Execute with explicit resolver, clock, and extension permissions.
    pub fn execute_with_environment<R: Resolver + 'static>(
        &self,
        source: &Document,
        parameters: &Parameters,
        environment: ExecutionEnvironment<R>,
        options: ExecutionOptions,
    ) -> Result<TransformResult> {
        self.execute_with_environment_and_source_processing(
            source,
            parameters,
            environment,
            options,
            SourceProcessing::Xml,
        )
    }

    /// Execute with explicit source preprocessing semantics.
    pub fn execute_with_source_processing<R: Resolver + 'static>(
        &self,
        source: &Document,
        parameters: &Parameters,
        resolver: Arc<R>,
        options: ExecutionOptions,
        source_processing: SourceProcessing,
    ) -> Result<TransformResult> {
        self.execute_with_environment_and_source_processing(
            source,
            parameters,
            ExecutionEnvironment::new(resolver),
            options,
            source_processing,
        )
    }

    /// Execute with explicit environment and source preprocessing semantics.
    pub fn execute_with_environment_and_source_processing<R: Resolver + 'static>(
        &self,
        source: &Document,
        parameters: &Parameters,
        environment: ExecutionEnvironment<R>,
        options: ExecutionOptions,
        source_processing: SourceProcessing,
    ) -> Result<TransformResult> {
        let source_bytes = source.source_xml().map_or(0, str::len);
        let mut meter = Meter::new(options.budget, source_bytes)?;
        let source_options = EvaluatorSourceOptions {
            processing: source_processing,
            whitespace: Arc::clone(&self.whitespace),
            clock: Arc::clone(&environment.clock),
            extension_policy: environment.extension_policy,
        };
        let mut prepared = prepare_evaluator_source(
            source,
            environment.resolver.as_ref(),
            &mut meter,
            &source_options,
        )?;
        let source_remap = prepared.remap.take();
        let mut state = Execution::new(
            self,
            prepared,
            parameters,
            source_remap.as_ref(),
            environment,
            meter,
            source_options,
        )?;
        let root = SourceNode::Node(state.evaluator.source.root());
        if let Some(name) = options.initial_template {
            state.call_named(
                &name,
                &HashMap::new(),
                &root,
                ApplyFrame::new(1, 1, 1),
                None,
            )?;
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
            secondary_outputs: state.secondary_outputs,
            messages: state.messages,
        })
    }
}

pub(crate) fn apply_whitespace_rules(
    document: &mut Document,
    rules: &[(NameTest, bool, usize, usize)],
) -> Option<HashMap<NodeId, NodeId>> {
    if rules.is_empty() {
        return None;
    }
    let removed = document
        .nodes()
        .filter_map(|(id, node)| {
            let NodeKind::Text { value, .. } = &node.kind else {
                return None;
            };
            if !value
                .chars()
                .all(|character| matches!(character, '\t' | '\n' | '\r' | ' '))
            {
                return None;
            }
            let parent = node.parent.and_then(|parent| document.node(parent))?;
            let NodeKind::Element { name, .. } = &parent.kind else {
                return None;
            };
            let xml_space = node.parent.and_then(|mut ancestor| {
                loop {
                    let current = document.node(ancestor)?;
                    if let NodeKind::Element { attributes, .. } = &current.kind
                        && let Some(value) = attributes.iter().find_map(|attribute| {
                            (attribute.name.namespace.as_deref()
                                == Some("http://www.w3.org/XML/1998/namespace")
                                && attribute.name.local == "space")
                                .then_some(attribute.value.as_str())
                        })
                    {
                        break Some(value);
                    }
                    ancestor = current.parent?;
                }
            });
            if xml_space == Some("preserve") {
                return None;
            }
            let decision = rules
                .iter()
                .filter(|(test, _, _, _)| test.matches(name))
                .max_by_key(|(test, _, precedence, order)| (*precedence, test.priority(), *order));
            matches!(decision, Some((_, false, _, _))).then_some(id)
        })
        .collect::<HashSet<_>>();
    if !removed.is_empty() {
        return Some(document.retain_nodes(|id, _| !removed.contains(&id)));
    }
    None
}

struct Execution<'a> {
    stylesheet: &'a Stylesheet,
    evaluator: Evaluator,
    result: Document,
    output_stack: Vec<NodeId>,
    scopes: Vec<HashMap<ExpandedName, Value>>,
    meter: Meter,
    messages: Vec<Message>,
    secondary_outputs: Vec<SecondaryOutput>,
    modes: Vec<Option<ExpandedName>>,
    function_results: Vec<Option<Value>>,
    function_depth: usize,
    binding_function_defaults: Vec<ExpandedName>,
    built_keys: HashSet<(ExpandedName, NodeId)>,
    building_keys: HashSet<(ExpandedName, NodeId)>,
    attribute_insert_position: Option<usize>,
    attribute_overwrite_existing: bool,
}

struct ResultTreeState {
    document: Document,
    output_stack: Vec<NodeId>,
    attribute_insert_position: Option<usize>,
    attribute_overwrite_existing: bool,
}

#[derive(Clone, Copy)]
enum AttributePosition {
    Back,
}

#[derive(Clone, Copy)]
struct ApplyFrame {
    max_precedence: Option<usize>,
    position: usize,
    size: usize,
    depth: usize,
}

enum TemplateTask {
    EnterTemplate {
        template: Box<Template>,
        params: HashMap<ExpandedName, Value>,
        node: SourceNode,
        frame: ApplyFrame,
        current_rule_precedence: Option<usize>,
    },
    ApplyOne {
        node: SourceNode,
        mode: Option<ExpandedName>,
        params: Arc<HashMap<ExpandedName, Value>>,
        frame: ApplyFrame,
    },
    Sequence {
        instructions: Arc<[Instruction]>,
        index: usize,
        node: SourceNode,
        position: usize,
        size: usize,
        depth: usize,
        precedence: Option<usize>,
    },
    RestoreScopes(Vec<HashMap<ExpandedName, Value>>),
    RestoreMode,
    PopOutput,
    PushScope,
    PopScope,
}

fn push_scoped_sequence(
    tasks: &mut Vec<TemplateTask>,
    instructions: Arc<[Instruction]>,
    node: SourceNode,
    frame: ApplyFrame,
    precedence: Option<usize>,
) {
    tasks.push(TemplateTask::PopScope);
    tasks.push(TemplateTask::Sequence {
        instructions,
        index: 0,
        node,
        position: frame.position,
        size: frame.size,
        depth: frame.depth,
        precedence,
    });
    tasks.push(TemplateTask::PushScope);
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
        source: PreparedEvaluatorSource,
        parameters: &Parameters,
        source_remap: Option<&HashMap<NodeId, NodeId>>,
        environment: ExecutionEnvironment<R>,
        mut meter: Meter,
        source_options: EvaluatorSourceOptions,
    ) -> Result<Self> {
        let evaluator = Evaluator::new(
            source,
            &stylesheet.principal_document,
            stylesheet.principal_base_uri.clone(),
            &stylesheet.module_documents,
            environment.resolver,
            &mut meter,
            source_options,
        )?;
        let mut state = Self {
            stylesheet,
            evaluator,
            result: Document::empty(None),
            output_stack: vec![NodeId(0)],
            scopes: vec![HashMap::new()],
            meter,
            messages: vec![],
            secondary_outputs: vec![],
            modes: vec![None],
            function_results: vec![],
            function_depth: 0,
            binding_function_defaults: vec![],
            built_keys: HashSet::new(),
            building_keys: HashSet::new(),
            attribute_insert_position: None,
            attribute_overwrite_existing: true,
        };
        state.evaluator.initialize_xslt(
            &stylesheet.decimal_formats,
            stylesheet
                .functions
                .iter()
                .map(|function| function.name.clone()),
        );
        state.initialize_globals(parameters, source_remap)?;
        Ok(state)
    }

    fn ensure_key_index(
        &mut self,
        source: &str,
        namespaces: &[(String, String)],
        context: &SourceNode,
    ) -> Result<()> {
        let requested = literal_key_names(source, namespaces)?.unwrap_or_else(|| {
            self.stylesheet
                .keys
                .iter()
                .map(|declaration| declaration.name.clone())
                .collect()
        });
        if requested.is_empty() {
            return Ok(());
        }
        let logical_root = self
            .evaluator
            .source
            .logical_root_for(context)
            .ok_or_else(|| Error::Dynamic("key() context has no logical document".into()))?;
        for name in requested {
            self.build_key(&name, logical_root)?;
        }
        Ok(())
    }

    fn build_key(&mut self, name: &ExpandedName, logical_root: NodeId) -> Result<()> {
        let identity = (name.clone(), logical_root);
        if self.built_keys.contains(&identity) {
            return Ok(());
        }
        if !self.building_keys.insert(identity.clone()) {
            return Err(Error::Dynamic(format!(
                "cyclic xsl:key dependency for {}",
                name.local
            )));
        }
        let declarations = self
            .stylesheet
            .keys
            .iter()
            .filter(|declaration| &declaration.name == name)
            .cloned()
            .collect::<Vec<_>>();
        let variables = HashMap::new();
        for declaration in declarations {
            let mut entries = Vec::new();
            let mut pending = vec![logical_root];
            let mut nodes = Vec::new();
            while let Some(id) = pending.pop() {
                let Some(source) = self.evaluator.source.node(id) else {
                    continue;
                };
                pending.extend(source.children.iter().rev().copied());
                nodes.push(SourceNode::Node(id));
                if declaration.match_pattern.matches_attributes
                    && let NodeKind::Element { attributes, .. } = &source.kind
                {
                    nodes.extend(
                        (0..attributes.len())
                            .map(|index| SourceNode::Attribute { owner: id, index }),
                    );
                }
            }
            for node in nodes {
                if !self.matches_pattern(&declaration.match_pattern, &node, &variables)? {
                    continue;
                }
                let value = self.evaluate(&declaration.use_expression, &node, 1, 1)?;
                let values = match value {
                    XPathValue::NodeSet(nodes) => nodes
                        .iter()
                        .map(|node| self.evaluator.string_value(node))
                        .collect::<Vec<_>>(),
                    value => vec![value.string(&self.evaluator)],
                };
                entries.extend(
                    values
                        .into_iter()
                        .map(|value| (declaration.name.clone(), value, node.clone())),
                );
            }
            self.evaluator.append_key_index(entries, &mut self.meter)?;
        }
        self.building_keys.remove(&identity);
        self.built_keys.insert(identity);
        Ok(())
    }

    fn matches_pattern(
        &mut self,
        pattern: &crate::compiler::Pattern,
        node: &SourceNode,
        variables: &HashMap<ExpandedName, Value>,
    ) -> Result<bool> {
        if self.evaluator.pattern_terminal_rejects(pattern, node)? {
            return Ok(false);
        }
        if xpath_calls_key(&pattern.source) {
            self.ensure_key_index(&pattern.source, &pattern.namespaces, node)?;
        }
        self.evaluator
            .matches(pattern, node, variables, &mut self.meter)
    }

    fn initialize_globals(
        &mut self,
        parameters: &Parameters,
        source_remap: Option<&HashMap<NodeId, NodeId>>,
    ) -> Result<()> {
        let mut effective = HashMap::new();
        for global in self.stylesheet.globals.iter() {
            if effective.get(&global.variable.name).is_none_or(
                |current: &&crate::compiler::GlobalVariable| global.precedence > current.precedence,
            ) {
                effective.insert(global.variable.name.clone(), global);
            }
        }
        let mut pending = effective.into_values().collect::<Vec<_>>();
        pending.sort_by_key(|global| global.order);
        let global_names = pending
            .iter()
            .map(|global| global.variable.name.clone())
            .collect::<HashSet<_>>();
        while !pending.is_empty() {
            let mut deferred = Vec::new();
            let mut progressed = false;
            for global in pending {
                if global.is_parameter
                    && let Some(value) = parameters.get(&global.variable.name)
                {
                    let value = source_remap.map_or_else(
                        || value.clone(),
                        |remap| remap_parameter_value(value, remap),
                    );
                    let owned_bytes = expanded_name_owned_bytes(&global.variable.name)
                        .saturating_add(value_owned_bytes(&value));
                    self.meter
                        .check_additional(BudgetKind::OwnedBytes, owned_bytes)?;
                    let name = global.variable.name.clone();
                    self.meter.charge(BudgetKind::OwnedBytes, owned_bytes)?;
                    self.scopes[0].insert(name, value);
                    progressed = true;
                    continue;
                }
                if global
                    .dependencies
                    .iter()
                    .filter(|name| global_names.contains(*name))
                    .any(|name| !self.scopes[0].contains_key(name))
                {
                    deferred.push(global);
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
                progressed = true;
            }
            if !progressed {
                let names = deferred
                    .iter()
                    .map(|global| global.variable.name.local.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(Error::Dynamic(format!(
                    "circular or unresolved global variable dependency: {names}"
                )));
            }
            pending = deferred;
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
        let variables = HashMap::new();
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
            if self.matches_pattern(pattern, &node, &variables)?
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
            let result = self.execute_template(
                template,
                node,
                params,
                ApplyFrame::new(position, size, depth),
                Some(template.precedence),
            );
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
        frame: ApplyFrame,
        current_rule_precedence: Option<usize>,
    ) -> Result<()> {
        let mut tasks = vec![TemplateTask::EnterTemplate {
            template: Box::new(template.clone()),
            params: params.clone(),
            node,
            frame,
            current_rule_precedence,
        }];
        while let Some(task) = tasks.pop() {
            match task {
                TemplateTask::EnterTemplate {
                    template,
                    params,
                    node,
                    frame,
                    current_rule_precedence,
                } => self.push_template_tasks(
                    &mut tasks,
                    &template,
                    &params,
                    node,
                    frame,
                    current_rule_precedence,
                )?,
                TemplateTask::ApplyOne {
                    node,
                    mode,
                    params,
                    frame,
                } => self.push_apply_one_tasks(&mut tasks, node, mode, params, frame)?,
                TemplateTask::RestoreScopes(caller_scopes) => {
                    self.scopes.pop();
                    self.scopes.extend(caller_scopes);
                }
                TemplateTask::RestoreMode => {
                    self.modes.pop();
                }
                TemplateTask::PopOutput => {
                    self.output_stack.pop();
                }
                TemplateTask::PushScope => self.scopes.push(HashMap::new()),
                TemplateTask::PopScope => {
                    self.scopes.pop();
                }
                TemplateTask::Sequence {
                    instructions,
                    index,
                    node,
                    position,
                    size,
                    depth,
                    precedence,
                } => {
                    self.meter.recursion(depth)?;
                    if self.function_results.last().is_some_and(Option::is_some) {
                        continue;
                    }
                    let Some(instruction) = instructions.get(index).cloned() else {
                        continue;
                    };
                    tasks.push(TemplateTask::Sequence {
                        instructions: instructions.clone(),
                        index: index + 1,
                        node: node.clone(),
                        position,
                        size,
                        depth,
                        precedence,
                    });
                    match instruction {
                        Instruction::CallTemplate { name, parameters } => {
                            self.meter.charge(BudgetKind::TemplateApplications, 1)?;
                            let supplied = self.evaluate_with_params(
                                &parameters,
                                &node,
                                position,
                                size,
                                depth,
                            )?;
                            let target = self
                                .stylesheet
                                .templates
                                .iter()
                                .filter(|candidate| candidate.name.as_ref() == Some(&name))
                                .max_by_key(|candidate| (candidate.precedence, candidate.order))
                                .cloned()
                                .ok_or_else(|| {
                                    Error::Dynamic(format!(
                                        "named template {} not found",
                                        name.local
                                    ))
                                })?;
                            tasks.push(TemplateTask::EnterTemplate {
                                template: Box::new(target),
                                params: supplied,
                                node,
                                frame: ApplyFrame::new(position, size, depth + 1),
                                current_rule_precedence: precedence,
                            });
                        }
                        Instruction::ApplyTemplates {
                            select,
                            mode,
                            sorts,
                            parameters,
                        } => {
                            let mut nodes = self.select_nodes(&select, &node, position, size)?;
                            self.sort_nodes(&mut nodes, &sorts, &node, position, size)?;
                            let supplied = Arc::new(self.evaluate_with_params(
                                &parameters,
                                &node,
                                position,
                                size,
                                depth,
                            )?);
                            let total = nodes.len();
                            for (index, selected) in nodes.into_iter().enumerate().rev() {
                                tasks.push(TemplateTask::ApplyOne {
                                    node: selected,
                                    mode: mode.clone(),
                                    params: Arc::clone(&supplied),
                                    frame: ApplyFrame::new(index + 1, total, depth + 1),
                                });
                            }
                        }
                        Instruction::ApplyImports => {
                            let current_rule_precedence = precedence.ok_or_else(|| {
                                Error::Dynamic(
                                    "xsl:apply-imports requires a current template rule".into(),
                                )
                            })?;
                            tasks.push(TemplateTask::ApplyOne {
                                node,
                                mode: self.modes.last().cloned().flatten(),
                                params: Arc::new(HashMap::new()),
                                frame: ApplyFrame {
                                    max_precedence: Some(current_rule_precedence),
                                    position,
                                    size,
                                    depth: depth + 1,
                                },
                            });
                        }
                        Instruction::LiteralElement {
                            name,
                            prefix,
                            attributes,
                            namespaces,
                            children,
                            attribute_sets,
                        } => {
                            let (name, prefix) = self.alias_name(&name, prefix.as_deref());
                            let mut result_namespaces = Vec::<Namespace>::new();
                            for namespace in &namespaces {
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
                            let id = self.push_node(
                                self.parent(),
                                NodeKind::Element {
                                    name,
                                    prefix,
                                    attributes: vec![],
                                    namespaces: result_namespaces,
                                },
                            )?;
                            self.output_stack.push(id);
                            for set in &attribute_sets {
                                self.apply_attribute_set(
                                    set,
                                    &node,
                                    position,
                                    size,
                                    depth,
                                    &mut Vec::new(),
                                )?;
                            }
                            for attribute in &attributes {
                                let value =
                                    self.evaluate_avt(&attribute.value, &node, position, size)?;
                                let (name, prefix) =
                                    self.alias_name(&attribute.name, attribute.prefix.as_deref());
                                self.add_attribute(Attribute {
                                    name,
                                    prefix,
                                    value,
                                })?;
                            }
                            tasks.push(TemplateTask::PopOutput);
                            push_scoped_sequence(
                                &mut tasks,
                                children.into(),
                                node,
                                ApplyFrame::new(position, size, depth + 1),
                                precedence,
                            );
                        }
                        Instruction::Copy {
                            body,
                            attribute_sets,
                        } => match &node {
                            SourceNode::Node(source_id) => {
                                let kind = self
                                    .evaluator
                                    .source
                                    .node(*source_id)
                                    .map(|source| source.kind.clone())
                                    .ok_or_else(|| Error::Dynamic("stale source node".into()))?;
                                match kind {
                                    NodeKind::Element {
                                        name,
                                        prefix,
                                        namespaces,
                                        ..
                                    } => {
                                        let target = self.push_node(
                                            self.parent(),
                                            NodeKind::Element {
                                                name,
                                                prefix,
                                                attributes: vec![],
                                                namespaces,
                                            },
                                        )?;
                                        self.output_stack.push(target);
                                        for set in &attribute_sets {
                                            self.apply_attribute_set(
                                                set,
                                                &node,
                                                position,
                                                size,
                                                depth,
                                                &mut Vec::new(),
                                            )?;
                                        }
                                        tasks.push(TemplateTask::PopOutput);
                                        push_scoped_sequence(
                                            &mut tasks,
                                            body.into(),
                                            node,
                                            ApplyFrame::new(position, size, depth + 1),
                                            precedence,
                                        );
                                    }
                                    NodeKind::Root => push_scoped_sequence(
                                        &mut tasks,
                                        body.into(),
                                        node,
                                        ApplyFrame::new(position, size, depth + 1),
                                        precedence,
                                    ),
                                    NodeKind::Text { value, .. } => {
                                        self.append_text(&value, false)?
                                    }
                                    NodeKind::Comment(value) => {
                                        self.push_node(self.parent(), NodeKind::Comment(value))?;
                                    }
                                    NodeKind::ProcessingInstruction { target, value } => {
                                        self.push_node(
                                            self.parent(),
                                            NodeKind::ProcessingInstruction { target, value },
                                        )?;
                                    }
                                }
                            }
                            SourceNode::Attribute { owner, index } => {
                                self.copy_source_attribute(*owner, *index)?;
                            }
                            SourceNode::Namespace { owner, index } => {
                                self.copy_source_namespace(*owner, *index)?;
                            }
                        },
                        Instruction::ForEach {
                            select,
                            sorts,
                            body,
                        } => {
                            let mut nodes = self.select_nodes(&select, &node, position, size)?;
                            self.sort_nodes(&mut nodes, &sorts, &node, position, size)?;
                            let total = nodes.len();
                            for (index, selected) in nodes.into_iter().enumerate().rev() {
                                tasks.push(TemplateTask::PopScope);
                                tasks.push(TemplateTask::Sequence {
                                    instructions: Arc::from(body.clone()),
                                    index: 0,
                                    node: selected,
                                    position: index + 1,
                                    size: total,
                                    depth: depth + 1,
                                    precedence: None,
                                });
                                tasks.push(TemplateTask::PushScope);
                            }
                        }
                        Instruction::If { test, body } => {
                            if self.evaluate(&test, &node, position, size)?.boolean() {
                                push_scoped_sequence(
                                    &mut tasks,
                                    body.into(),
                                    node,
                                    ApplyFrame::new(position, size, depth + 1),
                                    precedence,
                                );
                            }
                        }
                        Instruction::Choose {
                            branches,
                            otherwise,
                        } => {
                            let mut selected = otherwise;
                            for (test, body) in branches {
                                if self.evaluate(&test, &node, position, size)?.boolean() {
                                    selected = body;
                                    break;
                                }
                            }
                            push_scoped_sequence(
                                &mut tasks,
                                selected.into(),
                                node,
                                ApplyFrame::new(position, size, depth + 1),
                                precedence,
                            );
                        }
                        Instruction::ExtensionFallback {
                            name,
                            present,
                            body,
                        } => {
                            if !present {
                                return Err(Error::Unsupported(format!(
                                    "extension element {name} has no xsl:fallback"
                                )));
                            }
                            push_scoped_sequence(
                                &mut tasks,
                                body.into(),
                                node,
                                ApplyFrame::new(position, size, depth + 1),
                                precedence,
                            );
                        }
                        instruction => self.execute_instruction(
                            &instruction,
                            &node,
                            position,
                            size,
                            depth,
                            precedence,
                        )?,
                    }
                }
            }
        }
        Ok(())
    }

    fn push_apply_one_tasks(
        &mut self,
        tasks: &mut Vec<TemplateTask>,
        node: SourceNode,
        mode: Option<ExpandedName>,
        params: Arc<HashMap<ExpandedName, Value>>,
        frame: ApplyFrame,
    ) -> Result<()> {
        self.meter.recursion(frame.depth)?;
        self.meter.charge(BudgetKind::TemplateApplications, 1)?;
        let variables = HashMap::new();
        let selected = self
            .stylesheet
            .templates
            .iter()
            .filter(|template| {
                template.pattern.is_some()
                    && template.mode == mode
                    && frame
                        .max_precedence
                        .is_none_or(|max| template.precedence < max)
            })
            .filter_map(|template| {
                let pattern = template.pattern.as_ref()?;
                match self.matches_pattern(pattern, &node, &variables) {
                    Ok(true) => Some(Ok(template)),
                    Ok(false) => None,
                    Err(error) => Some(Err(error)),
                }
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .max_by(|left, right| {
                left.precedence
                    .cmp(&right.precedence)
                    .then_with(|| left.priority.total_cmp(&right.priority))
                    .then_with(|| left.order.cmp(&right.order))
            })
            .cloned();
        if let Some(template) = selected {
            self.modes.push(mode);
            tasks.push(TemplateTask::RestoreMode);
            let current_rule_precedence = Some(template.precedence);
            tasks.push(TemplateTask::EnterTemplate {
                template: Box::new(template),
                params: (*params).clone(),
                node,
                frame,
                current_rule_precedence,
            });
            return Ok(());
        }
        match &node {
            SourceNode::Node(id) => match self
                .evaluator
                .source
                .node(*id)
                .map(|source| source.kind.clone())
            {
                Some(NodeKind::Root | NodeKind::Element { .. }) => {
                    let children = self.evaluator.children(&node);
                    let total = children.len();
                    let built_in_params = Arc::new(HashMap::new());
                    for (index, child) in children.into_iter().enumerate().rev() {
                        tasks.push(TemplateTask::ApplyOne {
                            node: child,
                            mode: mode.clone(),
                            params: Arc::clone(&built_in_params),
                            frame: ApplyFrame::new(index + 1, total, frame.depth + 1),
                        });
                    }
                    Ok(())
                }
                Some(NodeKind::Text { value, .. }) => self.append_text(&value, false),
                _ => Ok(()),
            },
            SourceNode::Attribute { .. } | SourceNode::Namespace { .. } => {
                let value = self.evaluator.string_value(&node);
                self.append_text(&value, false)
            }
        }
    }

    fn push_template_tasks(
        &mut self,
        tasks: &mut Vec<TemplateTask>,
        template: &Template,
        params: &HashMap<ExpandedName, Value>,
        node: SourceNode,
        frame: ApplyFrame,
        current_rule_precedence: Option<usize>,
    ) -> Result<()> {
        let ApplyFrame {
            position,
            size,
            depth,
            ..
        } = frame;
        self.meter.recursion(depth)?;
        let caller_scopes = self.scopes.split_off(1);
        self.scopes.push(HashMap::new());
        for parameter in &template.params {
            let value = params.get(&parameter.name).cloned().map_or_else(
                || self.evaluate_variable(parameter, &node, position, size, depth),
                Ok,
            )?;
            self.scopes
                .last_mut()
                .expect("template parameter scope exists")
                .insert(parameter.name.clone(), value);
        }
        tasks.push(TemplateTask::RestoreScopes(caller_scopes));
        tasks.push(TemplateTask::Sequence {
            instructions: Arc::clone(&template.body),
            index: 0,
            node,
            position,
            size,
            depth,
            precedence: current_rule_precedence,
        });
        Ok(())
    }

    fn built_in(
        &mut self,
        node: SourceNode,
        mode: Option<&ExpandedName>,
        depth: usize,
    ) -> Result<()> {
        match &node {
            SourceNode::Node(id) => match self
                .evaluator
                .source
                .node(*id)
                .map(|node| node.kind.clone())
            {
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
                Some(NodeKind::Text { value, .. }) => self.append_text(&value, false),
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
            if self.function_results.last().is_some_and(Option::is_some) {
                break;
            }
        }
        Ok(())
    }

    fn execute_scoped_sequence(
        &mut self,
        instructions: &[Instruction],
        node: &SourceNode,
        position: usize,
        size: usize,
        depth: usize,
        current_precedence: Option<usize>,
    ) -> Result<()> {
        self.scopes.push(HashMap::new());
        let result = self.execute_sequence(
            instructions,
            node,
            position,
            size,
            depth,
            current_precedence,
        );
        self.scopes.pop();
        result
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
                let result = self.execute_scoped_sequence(
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
                self.sort_nodes(&mut nodes, sorts, node, position, size)?;
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
                let current_rule_precedence = current_precedence.ok_or_else(|| {
                    Error::Dynamic("xsl:apply-imports requires a current template rule".into())
                })?;
                let mode = self.modes.last().cloned().flatten();
                self.apply_one(
                    node.clone(),
                    mode.as_ref(),
                    &HashMap::new(),
                    ApplyFrame {
                        max_precedence: Some(current_rule_precedence),
                        position,
                        size,
                        depth: depth + 1,
                    },
                )
            }
            Instruction::CallTemplate { name, parameters } => {
                let supplied =
                    self.evaluate_with_params(parameters, node, position, size, depth)?;
                self.call_named(
                    name,
                    &supplied,
                    node,
                    ApplyFrame::new(position, size, depth + 1),
                    current_precedence,
                )
            }
            Instruction::ForEach {
                select,
                sorts,
                body,
            } => {
                let mut nodes = self.select_nodes(select, node, position, size)?;
                self.sort_nodes(&mut nodes, sorts, node, position, size)?;
                let total = nodes.len();
                for (index, selected) in nodes.iter().enumerate() {
                    self.scopes.push(HashMap::new());
                    let result =
                        self.execute_sequence(body, selected, index + 1, total, depth + 1, None);
                    self.scopes.pop();
                    result?
                }
                Ok(())
            }
            Instruction::If { test, body } => {
                if self.evaluate(test, node, position, size)?.boolean() {
                    self.execute_scoped_sequence(
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
                        return self.execute_scoped_sequence(
                            body,
                            node,
                            position,
                            size,
                            depth + 1,
                            current_precedence,
                        );
                    }
                }
                self.execute_scoped_sequence(
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
                            self.copy_source(&selected, self.parent(), depth + 1)?
                        }
                    }
                    XPathValue::ResultTreeFragment(fragment) => {
                        self.copy_document(&fragment, fragment.root(), self.parent(), depth + 1)?;
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
                        if let Some(kind) = self
                            .evaluator
                            .source
                            .node(*id)
                            .map(|source| source.kind.clone())
                        {
                            match kind {
                                NodeKind::Element {
                                    name,
                                    prefix,
                                    attributes: _,
                                    namespaces,
                                } => {
                                    let target = self.push_node(
                                        self.parent(),
                                        NodeKind::Element {
                                            name,
                                            prefix,
                                            attributes: vec![],
                                            namespaces,
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
                                    let result = self.execute_scoped_sequence(
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
                                NodeKind::Text { value, .. } => self.append_text(&value, false)?,
                                NodeKind::Comment(value) => {
                                    self.push_node(self.parent(), NodeKind::Comment(value))?;
                                }
                                NodeKind::ProcessingInstruction { target, value } => {
                                    self.push_node(
                                        self.parent(),
                                        NodeKind::ProcessingInstruction { target, value },
                                    )?;
                                }
                                NodeKind::Root => self.execute_scoped_sequence(
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
                        self.copy_source_attribute(*owner, *index)?;
                    }
                    SourceNode::Namespace { owner, index } => {
                        self.copy_source_namespace(*owner, *index)?;
                    }
                }
                Ok(())
            }
            Instruction::Element {
                name,
                namespace,
                namespaces: static_namespaces,
                body,
                attribute_sets,
            } => {
                let lexical = self.evaluate_avt(name, node, position, size)?;
                let (prefix, local) = split_name(&lexical)?;
                let namespace = namespace
                    .as_ref()
                    .map(|value| self.evaluate_avt(value, node, position, size))
                    .transpose()?
                    .or_else(|| computed_element_namespace(static_namespaces, prefix.as_deref()));
                let (prefix, namespace) =
                    normalize_computed_namespace(prefix, namespace, &lexical)?;
                require_bound_computed_prefix(prefix.as_deref(), namespace.as_deref(), &lexical)?;
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
                let result = self.execute_scoped_sequence(
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
                namespaces: static_namespaces,
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
                            .and_then(|prefix| static_namespace(static_namespaces, prefix))
                    });
                let (prefix, namespace) =
                    normalize_computed_namespace(prefix, namespace, &lexical)?;
                validate_computed_attribute_name(prefix.as_deref(), &local, namespace.as_deref())?;
                require_bound_computed_prefix(prefix.as_deref(), namespace.as_deref(), &lexical)?;
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
                if target.eq_ignore_ascii_case("xml") || !is_ncname(&target) {
                    return Err(Error::Dynamic(
                        "invalid processing-instruction target".into(),
                    ));
                }
                let value =
                    self.capture_text(body, node, position, size, depth, current_precedence)?;
                let value = value.trim_start_matches([' ', '\t', '\r', '\n']).to_owned();
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
                if values.is_empty() {
                    return Ok(());
                }
                if number.value.is_some()
                    && let [value] = values.as_slice()
                    && (!value.is_finite() || *value < 0.5)
                {
                    return self.append_text(&crate::value::format_xpath_number(*value), false);
                }
                let grouping_separator = number
                    .grouping_separator
                    .as_ref()
                    .map(|value| self.evaluate_avt(value, node, position, size))
                    .transpose()?
                    .and_then(|value| {
                        let mut characters = value.chars();
                        let first = characters.next()?;
                        characters.next().is_none().then_some(first)
                    });
                let grouping_size = number
                    .grouping_size
                    .as_ref()
                    .map(|value| self.evaluate_avt(value, node, position, size))
                    .transpose()?
                    .and_then(|value| value.parse::<usize>().ok())
                    .filter(|size| *size > 0);
                let format = self.evaluate_avt(&number.format, node, position, size)?;
                let lang = number
                    .lang
                    .as_ref()
                    .map(|value| self.evaluate_avt(value, node, position, size))
                    .transpose()?;
                let letter_value = number
                    .letter_value
                    .as_ref()
                    .map(|value| self.evaluate_avt(value, node, position, size))
                    .transpose()?;
                self.append_text(
                    &format_number_sequence(
                        &values,
                        &format,
                        lang.as_deref(),
                        letter_value.as_deref(),
                        grouping_separator,
                        grouping_size,
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
                let fragment =
                    self.capture_fragment(body, node, position, size, depth, current_precedence)?;
                let content = serialize_fragment(&fragment, &mut self.meter)?;
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
            Instruction::SecondaryOutput {
                uri,
                properties,
                body,
            } => {
                let uri = self.evaluate_avt(uri, node, position, size)?;
                if uri.is_empty() {
                    return Err(Error::Dynamic(
                        "secondary-output URI must not be empty".into(),
                    ));
                }
                if self
                    .secondary_outputs
                    .iter()
                    .any(|output| output.uri == uri)
                {
                    return Err(Error::Dynamic(format!(
                        "secondary-output URI {uri:?} was produced more than once"
                    )));
                }
                let mut definition = self.stylesheet.output.clone();
                for (name, value) in properties {
                    let value = self.evaluate_avt(value, node, position, size)?;
                    apply_secondary_output_property(&mut definition, name, &value)?;
                }
                let fragment = self.capture_fragment(
                    body,
                    node,
                    position,
                    size,
                    depth + 1,
                    current_precedence,
                )?;
                let serialized = serialize(&fragment, &definition, &mut self.meter)?;
                self.secondary_outputs
                    .push(SecondaryOutput { uri, serialized });
                Ok(())
            }
            Instruction::ExtensionFallback {
                name,
                present,
                body,
            } => {
                if !present {
                    return Err(Error::Unsupported(format!(
                        "extension element {name} has no xsl:fallback"
                    )));
                }
                self.execute_scoped_sequence(
                    body,
                    node,
                    position,
                    size,
                    depth + 1,
                    current_precedence,
                )
            }
            Instruction::CompatibilityComment(value) => {
                self.push_node(self.parent(), NodeKind::Comment(value.clone()))?;
                Ok(())
            }
            Instruction::FunctionResult { select, content } => {
                if self.function_results.is_empty() {
                    return Err(Error::Dynamic(
                        "func:result executed outside an EXSLT function".into(),
                    ));
                }
                if self.function_results.last().is_some_and(Option::is_some) {
                    return Err(Error::Dynamic(
                        "EXSLT function produced more than one result".into(),
                    ));
                }
                let value = if let Some(select) = select {
                    xpath_to_public(self.evaluate(select, node, position, size)?)
                } else {
                    Value::ResultTreeFragment(self.capture_fragment(
                        content,
                        node,
                        position,
                        size,
                        depth + 1,
                        current_precedence,
                    )?)
                };
                *self
                    .function_results
                    .last_mut()
                    .expect("function result frame was checked") = Some(value);
                Ok(())
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
        self.meter.charge(BudgetKind::XPathEvaluations, 1)?;
        if xpath_calls_key(&expression.source) {
            self.ensure_key_index(&expression.source, &expression.namespaces, node)?;
        }
        if let Some(name) = direct_variable_reference(expression)?
            && let Some(value) = self.scopes.iter().rev().find_map(|scope| scope.get(&name))
        {
            let value = match value.clone() {
                Value::NodeSet(nodes) => Value::NodeSet(self.evaluator.document_order(nodes)),
                value => value,
            };
            return Ok(public_to_xpath(value));
        }
        match expression.source.trim() {
            "." => return Ok(XPathValue::NodeSet(vec![node.clone()])),
            "@*" => return Ok(XPathValue::NodeSet(self.evaluator.attributes(node))),
            _ => {}
        }
        if let Some(nodes) = self.evaluator.select_child_axis(expression, node)? {
            return Ok(XPathValue::NodeSet(nodes));
        }
        if let Some(value) = self.evaluate_scalar_fast(expression, node)? {
            return Ok(value);
        }
        if let Some(value) = self.evaluate_rtf_order(expression, node)? {
            return Ok(XPathValue::Number(value));
        }
        let (prepared, variables, direct) =
            self.prepare_custom_function_calls(expression, node, position, size)?;
        if let Some(value) = direct {
            return Ok(public_to_xpath(value));
        }
        let value = self.evaluator.evaluate(
            &prepared,
            node,
            position,
            size,
            &variables,
            &mut self.meter,
        )?;
        Ok(value)
    }

    fn evaluate_rtf_order(
        &self,
        expression: &Expression,
        node: &SourceNode,
    ) -> Result<Option<f64>> {
        let Some(remainder) = expression
            .source
            .trim()
            .strip_prefix("count(exsl:node-set($")
        else {
            return Ok(None);
        };
        let Some((variable, predicate)) = remainder.split_once(")/*[name() = ") else {
            return Ok(None);
        };
        let Some(target_expression) = predicate.strip_suffix("]/preceding-sibling::*)") else {
            return Ok(None);
        };
        if !variable.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | ':')
        }) {
            return Ok(None);
        }
        let (prefix, local) = variable
            .split_once(':')
            .map_or((None, variable), |(prefix, local)| (Some(prefix), local));
        let namespace = prefix
            .map(|prefix| {
                expression
                    .namespaces
                    .iter()
                    .find(|(candidate, _)| candidate == prefix)
                    .map(|(_, namespace)| namespace.clone())
                    .ok_or_else(|| Error::Static(format!("unbound variable prefix {prefix}")))
            })
            .transpose()?;
        let variable = ExpandedName::new(namespace, local);
        let Some(Value::ResultTreeFragment(fragment)) = self
            .scopes
            .iter()
            .rev()
            .find_map(|scope| scope.get(&variable))
        else {
            return Ok(None);
        };
        let target = match target_expression.trim() {
            "name(current())" => self.evaluator.qualified_name(node),
            path if path.starts_with("current()/") => self
                .evaluator
                .relative_string(
                    path.trim_start_matches("current()/"),
                    node,
                    &expression.namespaces,
                )?
                .unwrap_or_default(),
            _ => return Ok(None),
        };
        let Some(root) = fragment.node(fragment.root()) else {
            return Ok(Some(0.0));
        };
        let mut preceding = 0usize;
        let mut union_count = 0usize;
        for child in &root.children {
            let Some(candidate) = fragment.node(*child) else {
                continue;
            };
            if let NodeKind::Element { name, prefix, .. } = &candidate.kind {
                let qualified = prefix.as_deref().map_or_else(
                    || name.local.clone(),
                    |prefix| format!("{prefix}:{}", name.local),
                );
                if qualified == target {
                    // Preceding sibling sets are nested in document order, so the last
                    // matching element contributes the complete union.
                    union_count = preceding;
                }
                preceding += 1;
            }
        }
        Ok(Some(union_count as f64))
    }

    fn evaluate_scalar_fast(
        &self,
        expression: &Expression,
        node: &SourceNode,
    ) -> Result<Option<XPathValue>> {
        let source = expression.source.trim();
        match source {
            "self::text()" => {
                return Ok(Some(XPathValue::NodeSet(
                    self.evaluator
                        .is_text_node(node)
                        .then(|| node.clone())
                        .into_iter()
                        .collect(),
                )));
            }
            "self::*" => {
                return Ok(Some(XPathValue::NodeSet(
                    self.evaluator
                        .is_element_node(node)
                        .then(|| node.clone())
                        .into_iter()
                        .collect(),
                )));
            }
            "normalize-space(.)" => {
                return Ok(Some(XPathValue::String(normalize_xpath_space(
                    &self.evaluator.string_value(node),
                ))));
            }
            "concat('<',name(.),'>')" => {
                return Ok(Some(XPathValue::String(format!(
                    "<{}>",
                    self.evaluator.qualified_name(node)
                ))));
            }
            "concat('</',name(.),'>')" => {
                return Ok(Some(XPathValue::String(format!(
                    "</{}>",
                    self.evaluator.qualified_name(node)
                ))));
            }
            _ => {}
        }
        if let Some((variable, increment)) = source
            .strip_prefix('$')
            .and_then(|value| value.split_once('+'))
            && is_lexical_variable_name(variable.trim())
            && let Ok(increment) = increment.trim().parse::<f64>()
        {
            let value = self.variable_value(variable.trim(), &expression.namespaces)?;
            let number = match value {
                Value::Boolean(value) => f64::from(u8::from(*value)),
                Value::Number(value) => *value,
                Value::String(value) | Value::StoredExpression(value) => xpath_number(value),
                Value::NodeSet(_) | Value::ResultTreeFragment(_) => {
                    xpath_number(&value.clone().into_string(&self.evaluator.source))
                }
            };
            return Ok(Some(XPathValue::Number(number + increment)));
        }
        if let Some(arguments) = source
            .strip_prefix("translate(")
            .and_then(|value| value.strip_suffix(')'))
            && let Some((input, variables)) = arguments.split_once(',')
            && let Some((from, to)) = variables.split_once(',')
            && let (Some(from), Some(to)) =
                (from.trim().strip_prefix('$'), to.trim().strip_prefix('$'))
            && let Some(input) =
                self.evaluator
                    .relative_string(input.trim(), node, &expression.namespaces)?
        {
            let from = self.variable_string(from, &expression.namespaces)?;
            let to = self.variable_string(to, &expression.namespaces)?;
            let mut target = to.chars();
            let mut replacements = HashMap::new();
            for character in from.chars() {
                let replacement = target.next();
                replacements.entry(character).or_insert(replacement);
            }
            return Ok(Some(XPathValue::String(
                input
                    .chars()
                    .filter_map(|character| {
                        replacements
                            .get(&character)
                            .map_or(Some(character), |replacement| *replacement)
                    })
                    .collect(),
            )));
        }
        if let Some(arguments) = source
            .strip_prefix("substring (")
            .and_then(|value| value.strip_suffix(')'))
            && let Some((literal, remainder)) = arguments.split_once(',')
            && let Some(literal) = quoted_literal(literal.trim())
            && let Some((start, length)) = remainder.split_once(',')
            && start.trim() == "0"
            && let Some((variable, factor)) = length
                .trim()
                .strip_prefix('$')
                .and_then(|value| value.split_once('*'))
            && let Ok(factor) = factor.trim().parse::<f64>()
        {
            let length =
                xpath_number(&self.variable_string(variable.trim(), &expression.namespaces)?)
                    * factor;
            let take = length.round().max(1.0) as usize - 1;
            return Ok(Some(XPathValue::String(
                literal.chars().take(take).collect(),
            )));
        }
        if let Some(variable) = source
            .strip_prefix("string-length($")
            .and_then(|value| value.strip_suffix(") > 0"))
        {
            let value = self.variable_string(variable, &expression.namespaces)?;
            return Ok(Some(XPathValue::Boolean(!value.is_empty())));
        }
        if let Some(arguments) = source
            .strip_prefix("substring-before($")
            .and_then(|value| value.strip_suffix(')'))
            && let Some((variable, delimiter)) = arguments.split_once(',')
            && let Some(delimiter) = quoted_literal(delimiter.trim())
        {
            let value = self.variable_string(variable.trim(), &expression.namespaces)?;
            return Ok(Some(XPathValue::String(
                value
                    .split_once(delimiter)
                    .map_or("", |(head, _)| head)
                    .into(),
            )));
        }
        if let Some(arguments) = source
            .strip_prefix("substring($")
            .and_then(|value| value.strip_suffix(')'))
            && let Some((variable, offset)) = arguments.split_once(',')
            && let Some(offset) = offset.trim().strip_prefix("string-length($")
            && let Some((length_variable, increment)) = offset.split_once(")+")
            && let Ok(increment) = increment.trim().parse::<usize>()
        {
            let value = self.variable_string(variable.trim(), &expression.namespaces)?;
            let length = self
                .variable_string(length_variable.trim(), &expression.namespaces)?
                .chars()
                .count();
            let start = length.saturating_add(increment).saturating_sub(1);
            return Ok(Some(XPathValue::String(
                value.chars().skip(start).collect(),
            )));
        }
        if let Some(variable) = source
            .strip_prefix("boolean($")
            .and_then(|value| value.strip_suffix(')'))
            && is_lexical_variable_name(variable)
        {
            let value = self.variable_value(variable, &expression.namespaces)?;
            return Ok(Some(XPathValue::Boolean(value.clone().into_boolean())));
        }
        Ok(None)
    }

    fn variable_value(&self, lexical: &str, namespaces: &[(String, String)]) -> Result<&Value> {
        let name = expanded_variable_name(lexical, namespaces)?;
        self.scopes
            .iter()
            .rev()
            .find_map(|scope| scope.get(&name))
            .ok_or_else(|| Error::Dynamic(format!("undefined variable ${lexical}")))
    }

    fn variable_string(&self, lexical: &str, namespaces: &[(String, String)]) -> Result<String> {
        self.variable_value(lexical, namespaces)
            .cloned()
            .map(|value| value.into_string(&self.evaluator.source))
    }

    fn prepare_custom_function_calls(
        &mut self,
        expression: &Expression,
        node: &SourceNode,
        position: usize,
        size: usize,
    ) -> Result<(Expression, HashMap<ExpandedName, Value>, Option<Value>)> {
        const PRIVATE_NS: &str = "urn:structured-world:xml-sec:xslt:user-functions";
        let mut source = expression.source.clone();
        let mut variables = self.variables();
        let mut index = 0usize;
        while let Some(call) =
            innermost_namespaced_call(&source, &expression.namespaces, |namespace, local| {
                self.stylesheet.functions.iter().any(|function| {
                    function.name.namespace.as_deref() == Some(namespace)
                        && function.name.local == local
                })
            })
        {
            let name = ExpandedName::new(Some(call.namespace.clone()), call.local.clone());
            let function = self
                .stylesheet
                .functions
                .iter()
                .filter(|function| function.name == name)
                .max_by_key(|function| (function.precedence, function.order))
                .cloned()
                .ok_or_else(|| Error::Dynamic(format!("unknown function {}", call.display_name)))?;
            let mut arguments = Vec::with_capacity(call.arguments.len());
            for argument in &call.arguments {
                arguments.push(xpath_to_public(self.evaluate(
                    &expression.derived(argument.clone()),
                    node,
                    position,
                    size,
                )?));
            }
            let value = self.call_exslt_function(&function, arguments, node, position, size)?;
            if source[..call.start].trim().is_empty() && source[call.end..].trim().is_empty() {
                return Ok((expression.clone(), variables, Some(value)));
            }
            let local = format!("result{index}");
            index += 1;
            variables.insert(ExpandedName::new(Some(PRIVATE_NS), local.clone()), value);
            source.replace_range(call.start..call.end, &format!("$__xml_sec_func:{local}"));
        }
        let mut namespaces = expression.namespaces.clone();
        namespaces.push(("__xml_sec_func".into(), PRIVATE_NS.into()));
        let mut rewritten = expression.derived(source);
        rewritten.namespaces = namespaces;
        Ok((rewritten, variables, None))
    }

    fn call_exslt_function(
        &mut self,
        function: &ExsltFunction,
        arguments: Vec<Value>,
        node: &SourceNode,
        position: usize,
        size: usize,
    ) -> Result<Value> {
        if arguments.len() > function.params.len() {
            return Err(Error::Dynamic(format!(
                "EXSLT function {} accepts at most {} arguments, received {}",
                function.name.local,
                function.params.len(),
                arguments.len()
            )));
        }
        let binds_defaults = arguments.len() < function.params.len();
        if binds_defaults
            && self
                .binding_function_defaults
                .iter()
                .any(|name| name == &function.name)
        {
            return Err(Error::Dynamic(format!(
                "circular default parameter evaluation in EXSLT function {}",
                function.name.local
            )));
        }
        self.function_depth = self.function_depth.saturating_add(1);
        let depth = self.function_depth;
        let caller_scopes = self.scopes.split_off(1);
        self.scopes.push(HashMap::new());
        let previous_result = std::mem::replace(&mut self.result, Document::empty(None));
        let previous_stack = std::mem::replace(&mut self.output_stack, vec![NodeId(0)]);
        self.function_results.push(None);
        if binds_defaults {
            self.binding_function_defaults.push(function.name.clone());
        }
        let parameters = (|| {
            self.meter.recursion(depth)?;
            for (index, parameter) in function.params.iter().enumerate() {
                let value = if let Some(value) = arguments.get(index) {
                    value.clone()
                } else {
                    self.evaluate_variable(parameter, node, position, size, depth + 1)?
                };
                self.scopes
                    .last_mut()
                    .expect("function parameter scope exists")
                    .insert(parameter.name.clone(), value);
            }
            Ok(())
        })();
        if binds_defaults {
            self.binding_function_defaults.pop();
        }
        let execution = parameters.and_then(|()| {
            self.execute_sequence(&function.body, node, position, size, depth + 1, None)
        });
        let value = self.function_results.pop().flatten();
        self.result = previous_result;
        self.output_stack = previous_stack;
        self.scopes.pop();
        self.scopes.extend(caller_scopes);
        self.function_depth = self.function_depth.saturating_sub(1);
        execution?;
        value.ok_or_else(|| {
            Error::Dynamic(format!(
                "EXSLT function {} completed without func:result",
                function.name.local
            ))
        })
    }
    fn select_nodes(
        &mut self,
        expression: &crate::compiler::Expression,
        node: &SourceNode,
        position: usize,
        size: usize,
    ) -> Result<Vec<SourceNode>> {
        match expression.source.trim() {
            // These are the two hot selections used by identity transforms. They
            // are context child-axis expressions, so projecting them through the
            // general XPath engine for every source node is unnecessary work.
            "node()" => return Ok(self.evaluator.children(node)),
            "." => return Ok(vec![node.clone()]),
            "@*" => return Ok(self.evaluator.attributes(node)),
            "preceding-sibling::node()[normalize-space()][1][self::comment()]" => {
                return Ok(self.evaluator.preceding_nonempty_comment(node));
            }
            "@*|node()" | "node()|@*" => {
                let mut selected = self.evaluator.attributes(node);
                selected.extend(self.evaluator.children(node));
                return Ok(selected);
            }
            _ => {}
        }
        if let Some(nodes) = self.evaluator.select_child_axis(expression, node)? {
            return Ok(nodes);
        }
        match self.evaluate(expression, node, position, size)? {
            XPathValue::NodeSet(nodes) => Ok(nodes),
            value => Err(Error::Dynamic(format!(
                "XPath `{}` must return a node-set, received {}",
                expression.source,
                xpath_value_kind(&value),
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
        let value = if let Some(select) = &variable.select {
            xpath_to_public(self.evaluate(select, node, position, size)?)
        } else if variable.content.is_empty() {
            Value::String(String::new())
        } else {
            Value::ResultTreeFragment(self.capture_fragment(
                &variable.content,
                node,
                position,
                size,
                depth,
                None,
            )?)
        };
        // Selected XPath values become owned by a persistent lexical scope. Result-tree
        // fragments are already metered while their document is built, so only their binding
        // name is additional retained storage here.
        let retained = expanded_name_owned_bytes(&variable.name).saturating_add(
            variable
                .select
                .as_ref()
                .map_or(0, |_| value_owned_bytes(&value)),
        );
        self.meter.charge(BudgetKind::OwnedBytes, retained)?;
        Ok(value)
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
        frame: ApplyFrame,
        current_rule_precedence: Option<usize>,
    ) -> Result<()> {
        self.meter.recursion(frame.depth)?;
        self.meter.charge(BudgetKind::TemplateApplications, 1)?;
        let template = self
            .stylesheet
            .templates
            .iter()
            .filter(|template| template.name.as_ref() == Some(name))
            .max_by_key(|template| (template.precedence, template.order))
            .ok_or_else(|| Error::Dynamic(format!("named template {} not found", name.local)))?;
        self.execute_template(
            template,
            node.clone(),
            params,
            frame,
            current_rule_precedence,
        )
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
                AvtPart::Literal(value) => {
                    self.meter.check_additional(
                        BudgetKind::OwnedBytes,
                        output.len().saturating_add(value.len()),
                    )?;
                    output.push_str(value);
                }
                AvtPart::Expression(expression) => {
                    let value = self
                        .evaluate(expression, node, position, size)?
                        .string(&self.evaluator);
                    self.meter.check_additional(
                        BudgetKind::OwnedBytes,
                        output.len().saturating_add(value.len()),
                    )?;
                    output.push_str(&value)
                }
            }
        }
        Ok(output)
    }
    fn sort_nodes(
        &mut self,
        nodes: &mut [SourceNode],
        sorts: &[Sort],
        context_node: &SourceNode,
        context_position: usize,
        context_size: usize,
    ) -> Result<()> {
        if sorts.is_empty() {
            return Ok(());
        }
        self.meter.charge(
            BudgetKind::OwnedBytes,
            sort_workspace_bytes(nodes.len(), sorts.len()),
        )?;
        let specs = sorts
            .iter()
            .map(|sort| {
                let case_order = sort
                    .case_order
                    .as_ref()
                    .map(|value| {
                        self.evaluate_avt(value, context_node, context_position, context_size)
                    })
                    .transpose()?;
                let lang = sort
                    .lang
                    .as_ref()
                    .map(|value| {
                        self.evaluate_avt(value, context_node, context_position, context_size)
                    })
                    .transpose()?;
                let data_type = self.evaluate_avt(
                    &sort.data_type,
                    context_node,
                    context_position,
                    context_size,
                )?;
                if !matches!(data_type.as_str(), "text" | "number") {
                    return Err(Error::Dynamic(format!(
                        "xsl:sort data-type must evaluate to `text` or `number`, got `{data_type}`"
                    )));
                }
                let collator = lang
                    .as_deref()
                    .map(|lang| locale_collator(lang, case_order.as_deref()))
                    .transpose()?;
                let order =
                    self.evaluate_avt(&sort.order, context_node, context_position, context_size)?;
                if !matches!(order.as_str(), "ascending" | "descending") {
                    return Err(Error::Dynamic(format!(
                        "xsl:sort order must evaluate to `ascending` or `descending`, got `{order}`"
                    )));
                }
                Ok(EvaluatedSort {
                    data_type,
                    order,
                    case_order,
                    collator,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut keyed = Vec::with_capacity(nodes.len());
        for (index, node) in nodes.iter().enumerate() {
            let mut keys = vec![];
            for (sort, spec) in sorts.iter().zip(&specs) {
                let value = self.evaluate(&sort.select, node, index + 1, nodes.len())?;
                let key = if spec.data_type == "number" {
                    SortKey::Number(value.number(&self.evaluator))
                } else {
                    let key = SortKey::text(value.string(&self.evaluator));
                    self.meter
                        .charge(BudgetKind::OwnedBytes, key.owned_bytes())?;
                    key
                };
                keys.push(key);
            }
            keyed.push((node.clone(), keys, index));
        }
        let mut order = (0..keyed.len()).collect::<Vec<_>>();
        try_stable_sort_by(&mut order, |left, right| {
            let left = &keyed[*left];
            let right = &keyed[*right];
            self.meter.charge(BudgetKind::SortComparisons, 1)?;
            for ((l, r), spec) in left.1.iter().zip(&right.1).zip(&specs) {
                let mut ordering = l.compare(r, spec.case_order.as_deref(), spec.collator.as_ref());
                if spec.order == "descending" {
                    ordering = ordering.reverse()
                }
                if ordering != Ordering::Equal {
                    return Ok(ordering);
                }
            }
            Ok(left.2.cmp(&right.2))
        })?;
        for (target, index) in nodes.iter_mut().zip(order) {
            *target = keyed[index].0.clone()
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
        let previous = self.enter_temporary_result_tree();
        let result =
            self.execute_scoped_sequence(body, node, position, size, depth + 1, precedence);
        let captured = result.and_then(|()| {
            let root = self
                .result
                .node(self.result.root())
                .ok_or_else(|| Error::Dynamic("captured result has no root node".into()))?;
            let mut bytes = 0usize;
            for child in &root.children {
                let Some(NodeKind::Text { value, .. }) =
                    self.result.node(*child).map(|node| &node.kind)
                else {
                    return Err(Error::Dynamic(
                        "xsl:attribute, xsl:comment, and xsl:processing-instruction content may produce only text nodes".into(),
                    ));
                };
                bytes = bytes.saturating_add(value.len());
            }
            self.meter.charge(BudgetKind::OwnedBytes, bytes)?;
            let mut captured = String::with_capacity(bytes);
            for child in &root.children {
                if let Some(NodeKind::Text { value, .. }) =
                    self.result.node(*child).map(|node| &node.kind)
                {
                    captured.push_str(value);
                }
            }
            Ok(captured)
        });
        self.restore_result_tree(previous);
        captured
    }
    fn capture_fragment(
        &mut self,
        body: &[Instruction],
        node: &SourceNode,
        position: usize,
        size: usize,
        depth: usize,
        precedence: Option<usize>,
    ) -> Result<Document> {
        let previous = self.enter_temporary_result_tree();
        let result =
            self.execute_scoped_sequence(body, node, position, size, depth + 1, precedence);
        let captured = self.restore_result_tree(previous);
        result?;
        Ok(captured)
    }

    fn enter_temporary_result_tree(&mut self) -> ResultTreeState {
        ResultTreeState {
            document: std::mem::replace(&mut self.result, Document::empty(None)),
            output_stack: std::mem::replace(&mut self.output_stack, vec![NodeId(0)]),
            attribute_insert_position: self.attribute_insert_position.take(),
            attribute_overwrite_existing: std::mem::replace(
                &mut self.attribute_overwrite_existing,
                true,
            ),
        }
    }

    fn restore_result_tree(&mut self, previous: ResultTreeState) -> Document {
        let captured = std::mem::replace(&mut self.result, previous.document);
        self.output_stack = previous.output_stack;
        self.attribute_insert_position = previous.attribute_insert_position;
        self.attribute_overwrite_existing = previous.attribute_overwrite_existing;
        captured
    }
    fn copy_document(
        &mut self,
        document: &Document,
        source_id: NodeId,
        parent: NodeId,
        depth: usize,
    ) -> Result<()> {
        self.meter.recursion(depth)?;
        let source = document
            .node(source_id)
            .ok_or_else(|| Error::Dynamic("stale result-tree-fragment node".into()))?;
        if matches!(source.kind, NodeKind::Root) {
            for child in &source.children {
                self.copy_document(document, *child, parent, depth + 1)?;
            }
            return Ok(());
        }
        let target = self.push_node(parent, source.kind.clone())?;
        for child in &source.children {
            self.copy_document(document, *child, target, depth + 1)?;
        }
        Ok(())
    }
    fn copy_source(&mut self, node: &SourceNode, parent: NodeId, depth: usize) -> Result<()> {
        self.meter.recursion(depth)?;
        match node {
            SourceNode::Node(id) => {
                let (kind, children) = self
                    .evaluator
                    .source
                    .node(*id)
                    .map(|source| (source.kind.clone(), source.children.clone()))
                    .ok_or_else(|| Error::Dynamic("stale source node".into()))?;
                if matches!(kind, NodeKind::Root) {
                    for child in children {
                        self.copy_source(&SourceNode::Node(child), parent, depth + 1)?
                    }
                    return Ok(());
                }
                let target = self.push_node(parent, kind)?;
                for child in children {
                    self.copy_source(&SourceNode::Node(child), target, depth + 1)?
                }
            }
            SourceNode::Attribute { owner, index } => {
                self.copy_source_attribute(*owner, *index)?;
            }
            SourceNode::Namespace { owner, index } => {
                self.copy_source_namespace(*owner, *index)?;
            }
        }
        Ok(())
    }
    fn copy_source_attribute(&mut self, owner: NodeId, index: usize) -> Result<()> {
        let attribute = match self.evaluator.source.node(owner).map(|node| &node.kind) {
            Some(NodeKind::Element { attributes, .. }) => attributes.get(index).cloned(),
            _ => None,
        };
        if let Some(attribute) = attribute {
            self.add_attribute(attribute)?;
        }
        Ok(())
    }
    fn copy_source_namespace(&mut self, owner: NodeId, index: usize) -> Result<()> {
        let namespace = match self.evaluator.source.node(owner).map(|node| &node.kind) {
            Some(NodeKind::Element { namespaces, .. }) => namespaces.get(index).cloned(),
            _ => None,
        };
        if let Some(namespace) = namespace {
            self.add_namespace(namespace)?;
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
        let mut sets = self
            .stylesheet
            .attribute_sets
            .iter()
            .filter(|set| &set.name == name)
            .collect::<Vec<_>>();
        sets.sort_by_key(|set| (std::cmp::Reverse(set.precedence), set.order));
        let highest_precedence = sets.first().map(|set| set.precedence);
        for set in sets {
            let previous_overwrite = self.attribute_overwrite_existing;
            self.attribute_overwrite_existing =
                previous_overwrite && Some(set.precedence) == highest_precedence;
            let set_start = self.current_attribute_count()?;
            for used in &set.uses {
                self.meter.recursion(depth + 1)?;
                self.apply_attribute_set(used, node, position, size, depth + 1, active)?
            }
            let previous_position = self.attribute_insert_position.replace(set_start);
            let result =
                self.execute_sequence(&set.attributes, node, position, size, depth + 1, None);
            self.attribute_insert_position = previous_position;
            self.attribute_overwrite_existing = previous_overwrite;
            result?;
        }
        active.pop();
        Ok(())
    }
    fn parent(&self) -> NodeId {
        *self.output_stack.last().unwrap_or(&NodeId(0))
    }
    fn push_node(&mut self, parent: NodeId, kind: NodeKind) -> Result<NodeId> {
        self.meter
            .charge(BudgetKind::OwnedBytes, node_kind_owned_bytes(&kind))?;
        self.meter.charge(BudgetKind::ResultNodes, 1)?;
        Ok(self.result.push(parent, kind, None))
    }
    fn append_text(&mut self, value: &str, disable: bool) -> Result<()> {
        // XSLT's result tree never retains zero-length text nodes.
        if value.is_empty() {
            return Ok(());
        }
        let parent = self.parent();
        let previous = self
            .result
            .node(parent)
            .and_then(|node| node.children.last().copied());
        if let Some(previous) = previous
            && self.result.node(previous).is_some_and(|node| {
                matches!(
                    &node.kind,
                    NodeKind::Text {
                        disable_output_escaping,
                        ..
                    } if *disable_output_escaping == disable
                )
            })
        {
            self.meter.charge(BudgetKind::OwnedBytes, value.len())?;
            if let Some(NodeKind::Text { value: current, .. }) =
                self.result.node_mut(previous).map(|node| &mut node.kind)
            {
                current.push_str(value);
            }
            return Ok(());
        }
        self.push_node(
            parent,
            NodeKind::Text {
                value: value.into(),
                disable_output_escaping: disable,
            },
        )?;
        Ok(())
    }

    fn add_attribute(&mut self, attribute: Attribute) -> Result<()> {
        self.add_attribute_with_position(attribute, AttributePosition::Back)
    }

    fn add_attribute_with_position(
        &mut self,
        mut attribute: Attribute,
        position: AttributePosition,
    ) -> Result<()> {
        let parent = self.parent();
        let node = self
            .result
            .node_mut(parent)
            .ok_or_else(|| Error::Dynamic("attribute has no result parent".into()))?;
        let NodeKind::Element {
            attributes,
            namespaces,
            ..
        } = &mut node.kind
        else {
            return Err(Error::Dynamic(
                "attribute cannot be added after a non-element result".into(),
            ));
        };
        if !node.children.is_empty() {
            return Err(Error::Dynamic(
                "attribute cannot be added after result children".into(),
            ));
        }
        let generated_namespace = fixup_attribute_namespace(&mut attribute, namespaces);
        let owned_bytes = attribute_owned_bytes(&attribute).saturating_add(
            generated_namespace
                .as_ref()
                .map_or(0, namespace_owned_bytes),
        );
        self.meter.charge(BudgetKind::OwnedBytes, owned_bytes)?;
        namespaces.extend(generated_namespace);
        if let Some(existing) = attributes
            .iter_mut()
            .find(|existing| existing.name == attribute.name)
        {
            if self.attribute_overwrite_existing {
                *existing = attribute;
            }
        } else {
            match position {
                AttributePosition::Back => {
                    if let Some(index) = self.attribute_insert_position.as_mut() {
                        attributes.insert(*index, attribute);
                        *index += 1;
                    } else {
                        attributes.push(attribute);
                    }
                }
            }
        }
        Ok(())
    }

    fn current_attribute_count(&self) -> Result<usize> {
        let node = self
            .result
            .node(self.parent())
            .ok_or_else(|| Error::Dynamic("attribute has no result parent".into()))?;
        let NodeKind::Element { attributes, .. } = &node.kind else {
            return Err(Error::Dynamic(
                "attribute requires an element result".into(),
            ));
        };
        Ok(attributes.len())
    }
    fn add_namespace(&mut self, mut namespace: Namespace) -> Result<()> {
        let node = self
            .result
            .node(self.parent())
            .ok_or_else(|| Error::Dynamic("namespace has no result parent".into()))?;
        let NodeKind::Element {
            name,
            prefix,
            attributes,
            namespaces,
        } = &node.kind
        else {
            return Err(Error::Dynamic(
                "namespace requires an element result".into(),
            ));
        };
        if !node.children.is_empty() {
            return Err(Error::Dynamic(
                "namespace cannot be added after result children".into(),
            ));
        }
        // Namespace-node copying cannot retarget an existing result QName. Preserve the copied
        // URI under a fresh prefix whenever its lexical prefix is already semantically occupied.
        let conflicts_with_element = namespace.prefix == *prefix
            && name.namespace.as_deref() != Some(namespace.uri.as_str());
        let conflicts_with_attribute = attributes.iter().any(|attribute| {
            attribute.prefix == namespace.prefix
                && attribute.name.namespace.as_deref() != Some(namespace.uri.as_str())
        });
        if conflicts_with_element || conflicts_with_attribute {
            if namespaces
                .iter()
                .any(|existing| existing.uri == namespace.uri)
            {
                return Ok(());
            }
            namespace.prefix = Some(unused_namespace_prefix(namespaces));
        }
        // A non-empty default binding would change an unprefixed, no-namespace result element's
        // expanded name when serialized. There is no QName use for that binding to preserve.
        if namespace.prefix.is_none() && prefix.is_none() && name.namespace.is_none() {
            return Ok(());
        }
        self.meter
            .charge(BudgetKind::OwnedBytes, namespace_owned_bytes(&namespace))?;
        let node = self
            .result
            .node_mut(self.parent())
            .ok_or_else(|| Error::Dynamic("namespace has no result parent".into()))?;
        let NodeKind::Element { namespaces, .. } = &mut node.kind else {
            return Err(Error::Dynamic(
                "namespace requires an element result".into(),
            ));
        };
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
            alias.output_prefix.clone(),
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
            prefix: alias.output_prefix.clone(),
            uri: alias.result_namespace.clone().unwrap_or_default(),
        }
    }
    fn number_sequence(
        &mut self,
        instruction: &crate::compiler::NumberInstruction,
        node: &SourceNode,
    ) -> Result<Vec<f64>> {
        let mut lineage = vec![node.clone()];
        let mut cursor = match node {
            SourceNode::Node(id) => self.evaluator.source.node(*id).and_then(|node| node.parent),
            SourceNode::Attribute { owner, .. } | SourceNode::Namespace { owner, .. } => {
                Some(*owner)
            }
        };
        while let Some(id) = cursor {
            lineage.push(SourceNode::Node(id));
            cursor = self.evaluator.source.node(id).and_then(|node| node.parent);
        }
        let variables = self.variables();
        let mut matches = |this: &mut Self, candidate: &SourceNode| -> Result<bool> {
            if let Some(pattern) = &instruction.count {
                this.matches_pattern(pattern, candidate, &variables)
            } else {
                Ok(same_node_kind_and_name(
                    &this.evaluator.source,
                    node,
                    candidate,
                ))
            }
        };
        let from = |this: &mut Self, candidate: &SourceNode| -> Result<bool> {
            instruction.from.as_ref().map_or(Ok(false), |pattern| {
                this.matches_pattern(pattern, candidate, &variables)
            })
        };
        match instruction.level.as_str() {
            "single" => {
                for candidate in lineage {
                    if from(self, &candidate)? {
                        break;
                    }
                    if matches(self, &candidate)? {
                        return Ok(vec![self.sibling_number(&candidate, &mut matches)? as f64]);
                    }
                }
                Ok(Vec::new())
            }
            "multiple" => {
                let mut values = Vec::new();
                for candidate in lineage.into_iter().rev() {
                    if from(self, &candidate)? {
                        values.clear();
                        continue;
                    }
                    if matches(self, &candidate)? {
                        values.push(self.sibling_number(&candidate, &mut matches)? as f64);
                    }
                }
                Ok(values)
            }
            "any" => {
                let mut boundary = None::<NodeId>;
                for candidate in &lineage {
                    if from(self, candidate)? {
                        if let SourceNode::Node(id) = candidate {
                            boundary = Some(*id);
                        }
                        break;
                    }
                }
                let mut count = 0usize;
                let logical_root = self
                    .evaluator
                    .source
                    .logical_root_for(node)
                    .ok_or_else(|| Error::Dynamic("numbering node has no logical root".into()))?;
                let ids = self
                    .evaluator
                    .source
                    .subtree_in_document_order(logical_root);
                for id in ids {
                    let element = SourceNode::Node(id);
                    let candidates = std::iter::once(element.clone())
                        .chain(self.evaluator.attributes(&element))
                        .chain(self.evaluator.namespaces(&element));
                    for candidate in candidates {
                        if candidate == element && Some(id) == boundary {
                            count = 0;
                        } else if matches(self, &candidate)? {
                            count += 1;
                        }
                        if &candidate == node {
                            return Ok((count > 0).then_some(count as f64).into_iter().collect());
                        }
                    }
                }
                Err(Error::Dynamic(
                    "numbering node is outside its logical document".into(),
                ))
            }
            level => Err(Error::Static(format!(
                "unsupported xsl:number level {level}"
            ))),
        }
    }

    fn sibling_number(
        &mut self,
        node: &SourceNode,
        matches: &mut impl FnMut(&mut Self, &SourceNode) -> Result<bool>,
    ) -> Result<usize> {
        let siblings = match node {
            SourceNode::Node(id) => {
                let Some(parent) = self.evaluator.source.node(*id).and_then(|node| node.parent)
                else {
                    return Ok(1);
                };
                self.evaluator
                    .source
                    .node(parent)
                    .map(|node| {
                        node.children
                            .iter()
                            .copied()
                            .map(SourceNode::Node)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            }
            SourceNode::Attribute { owner, .. } => self
                .evaluator
                .source
                .node(*owner)
                .and_then(|node| match &node.kind {
                    NodeKind::Element { attributes, .. } => Some(
                        (0..attributes.len())
                            .map(|index| SourceNode::Attribute {
                                owner: *owner,
                                index,
                            })
                            .collect(),
                    ),
                    _ => None,
                })
                .unwrap_or_default(),
            SourceNode::Namespace { owner, .. } => self
                .evaluator
                .source
                .node(*owner)
                .and_then(|node| match &node.kind {
                    NodeKind::Element { namespaces, .. } => Some(
                        (0..namespaces.len())
                            .map(|index| SourceNode::Namespace {
                                owner: *owner,
                                index,
                            })
                            .collect(),
                    ),
                    _ => None,
                })
                .unwrap_or_default(),
        };
        let mut count = 0;
        for sibling in siblings {
            if matches(self, &sibling)? {
                count += 1;
            }
            if &sibling == node {
                break;
            }
        }
        Ok(count)
    }
}

fn remap_parameter_value(value: &Value, remap: &HashMap<NodeId, NodeId>) -> Value {
    let Value::NodeSet(nodes) = value else {
        return value.clone();
    };
    Value::NodeSet(
        nodes
            .iter()
            .filter_map(|node| match node {
                NodeReference::Node(id) => remap.get(id).copied().map(NodeReference::Node),
                NodeReference::Attribute { owner, index } => {
                    remap
                        .get(owner)
                        .copied()
                        .map(|owner| NodeReference::Attribute {
                            owner,
                            index: *index,
                        })
                }
                NodeReference::Namespace { owner, index } => {
                    remap
                        .get(owner)
                        .copied()
                        .map(|owner| NodeReference::Namespace {
                            owner,
                            index: *index,
                        })
                }
            })
            .collect(),
    )
}

fn normalize_xpath_space(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut pending_space = false;
    for character in value.chars() {
        if matches!(character, ' ' | '\t' | '\r' | '\n') {
            pending_space = !output.is_empty();
        } else {
            if pending_space {
                output.push(' ');
                pending_space = false;
            }
            output.push(character);
        }
    }
    output
}

fn try_stable_sort_by<T: Copy>(
    values: &mut [T],
    mut compare: impl FnMut(&T, &T) -> Result<Ordering>,
) -> Result<()> {
    let mut width = 1usize;
    let mut source = values.to_vec();
    let mut target = source.clone();
    while width < source.len() {
        let step = width.saturating_mul(2);
        for start in (0..source.len()).step_by(step) {
            let middle = start.saturating_add(width).min(source.len());
            let end = start.saturating_add(step).min(source.len());
            let (mut left, mut right, mut output) = (start, middle, start);
            while left < middle && right < end {
                if compare(&source[left], &source[right])? != Ordering::Greater {
                    target[output] = source[left];
                    left += 1;
                } else {
                    target[output] = source[right];
                    right += 1;
                }
                output += 1;
            }
            while left < middle {
                target[output] = source[left];
                left += 1;
                output += 1;
            }
            while right < end {
                target[output] = source[right];
                right += 1;
                output += 1;
            }
        }
        std::mem::swap(&mut source, &mut target);
        width = width.saturating_mul(2);
    }
    values.copy_from_slice(&source);
    Ok(())
}

fn sort_workspace_bytes(node_count: usize, sort_count: usize) -> usize {
    let specs = sort_count.saturating_mul(std::mem::size_of::<EvaluatedSort>());
    let keyed = node_count.saturating_mul(std::mem::size_of::<(SourceNode, Vec<SortKey>, usize)>());
    let keys = node_count
        .saturating_mul(sort_count)
        .saturating_mul(std::mem::size_of::<SortKey>());
    // The index order plus source and target merge buffers coexist during stable sorting.
    let order = node_count
        .saturating_mul(std::mem::size_of::<usize>())
        .saturating_mul(3);
    specs
        .saturating_add(keyed)
        .saturating_add(keys)
        .saturating_add(order)
}

fn xpath_calls_key(source: &str) -> bool {
    !crate::expression::unprefixed_function_calls(source, "key").is_empty()
}

fn literal_key_names(
    source: &str,
    namespaces: &[(String, String)],
) -> Result<Option<Vec<ExpandedName>>> {
    let mut names = Vec::new();
    for call in crate::expression::unprefixed_function_calls(source, "key") {
        let Some(argument) = call.arguments.first() else {
            return Ok(None);
        };
        let argument = argument.trim();
        let Some(quote @ ('\'' | '"')) = argument.chars().next() else {
            return Ok(None);
        };
        let Some(lexical) = argument
            .strip_prefix(quote)
            .and_then(|value| value.strip_suffix(quote))
        else {
            return Ok(None);
        };
        let (prefix, local) = lexical
            .split_once(':')
            .map_or((None, lexical), |(prefix, local)| (Some(prefix), local));
        if local.is_empty() || local.contains(':') {
            return Err(Error::Dynamic(format!("invalid key QName {lexical}")));
        }
        let namespace = prefix
            .map(|prefix| {
                static_namespace(namespaces, prefix)
                    .ok_or_else(|| Error::Dynamic(format!("unbound key prefix {prefix}")))
            })
            .transpose()?;
        let name = ExpandedName::new(namespace, local);
        if !names.contains(&name) {
            names.push(name);
        }
    }
    Ok(Some(names))
}

fn fixup_attribute_namespace(
    attribute: &mut Attribute,
    namespaces: &[Namespace],
) -> Option<Namespace> {
    const XML_NAMESPACE: &str = "http://www.w3.org/XML/1998/namespace";

    let Some(uri) = attribute.name.namespace.as_deref() else {
        attribute.prefix = None;
        return None;
    };
    if uri == XML_NAMESPACE {
        attribute.prefix = Some("xml".into());
        return None;
    }
    let requested = attribute.prefix.as_deref().filter(|prefix| {
        !matches!(*prefix, "xml" | "xmlns")
            && namespaces
                .iter()
                .find(|namespace| namespace.prefix.as_deref() == Some(*prefix))
                .is_none_or(|namespace| namespace.uri == uri)
    });
    let prefix = requested
        .map(str::to_owned)
        .or_else(|| {
            namespaces
                .iter()
                .find(|namespace| {
                    namespace.prefix.is_some()
                        && namespace.uri == uri
                        && !matches!(namespace.prefix.as_deref(), Some("xml" | "xmlns"))
                })
                .and_then(|namespace| namespace.prefix.clone())
        })
        .unwrap_or_else(|| unused_namespace_prefix(namespaces));
    if namespaces
        .iter()
        .all(|namespace| namespace.prefix.as_deref() != Some(&prefix))
    {
        let namespace = Namespace {
            prefix: Some(prefix.clone()),
            uri: uri.to_owned(),
        };
        attribute.prefix = Some(prefix);
        return Some(namespace);
    }
    attribute.prefix = Some(prefix);
    None
}

fn unused_namespace_prefix(namespaces: &[Namespace]) -> String {
    let mut index = 1usize;
    loop {
        let candidate = format!("ns_{index}");
        if namespaces
            .iter()
            .all(|namespace| namespace.prefix.as_deref() != Some(&candidate))
        {
            return candidate;
        }
        index = index.saturating_add(1);
    }
}

#[derive(Clone)]
enum SortKey {
    Text { value: String, default_key: String },
    Number(f64),
}

struct EvaluatedSort {
    data_type: String,
    order: String,
    case_order: Option<String>,
    collator: Option<CollatorBorrowed<'static>>,
}
impl SortKey {
    fn text(value: String) -> Self {
        let default_key = default_collation_key(&value);
        Self::Text { value, default_key }
    }

    fn owned_bytes(&self) -> usize {
        match self {
            Self::Text { value, default_key } => value.len().saturating_add(default_key.len()),
            Self::Number(_) => 0,
        }
    }

    fn compare(
        &self,
        other: &Self,
        case_order: Option<&str>,
        collator: Option<&CollatorBorrowed<'static>>,
    ) -> Ordering {
        match (self, other) {
            (
                Self::Text {
                    value: left,
                    default_key: left_key,
                },
                Self::Text {
                    value: right,
                    default_key: right_key,
                },
            ) => {
                if let Some(collator) = collator {
                    return collator.compare(left, right);
                }
                let primary = left_key.cmp(right_key);
                if primary != Ordering::Equal {
                    return primary;
                }
                let secondary = left.to_lowercase().cmp(&right.to_lowercase());
                if secondary != Ordering::Equal {
                    return secondary;
                }
                match case_order {
                    Some("upper-first") => left.cmp(right),
                    Some("lower-first") => right.cmp(left),
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

fn default_collation_key(value: &str) -> String {
    let mut key = String::with_capacity(value.len());
    for character in value.chars().flat_map(char::to_lowercase) {
        // libxslt's default collation orders an underscore after letters,
        // while punctuation such as a leading minus sign remains significant.
        // U+10FFFF is a stable internal sort sentinel and can never collide
        // with the underscore that it replaces.
        key.push(if character == '_' {
            char::MAX
        } else {
            character
        });
    }
    key
}

fn apply_secondary_output_property(
    definition: &mut crate::OutputDefinition,
    name: &str,
    value: &str,
) -> Result<()> {
    let yes_no = |value: &str| match value {
        "yes" => Ok(true),
        "no" => Ok(false),
        _ => Err(Error::Dynamic(format!(
            "secondary-output {name} must be yes or no"
        ))),
    };
    match name {
        "method" => {
            definition.method_explicit = true;
            definition.method = match value {
                "xml" => crate::OutputMethod::Xml,
                "html" => crate::OutputMethod::Html,
                "text" => crate::OutputMethod::Text,
                _ => {
                    return Err(Error::Dynamic(format!(
                        "unsupported secondary-output method {value:?}"
                    )));
                }
            };
        }
        "version" => definition.version = Some(value.to_owned()),
        "encoding" => {
            definition.encoding_explicit = true;
            definition.encoding = value.to_owned();
        }
        "omit-xml-declaration" => definition.omit_xml_declaration = yes_no(value)?,
        "standalone" => definition.standalone = Some(yes_no(value)?),
        "doctype-public" => definition.doctype_public = Some(value.to_owned()),
        "doctype-system" => definition.doctype_system = Some(value.to_owned()),
        "indent" => {
            definition.indent_explicit = true;
            definition.indent = yes_no(value)?;
        }
        "media-type" => definition.media_type = Some(value.to_owned()),
        _ => {
            return Err(Error::Dynamic(format!(
                "unsupported secondary-output property {name:?}"
            )));
        }
    }
    Ok(())
}

fn locale_collator(lang: &str, case_order: Option<&str>) -> Result<CollatorBorrowed<'static>> {
    let locale = lang.parse::<Locale>().map_err(|error| {
        Error::Dynamic(format!("xsl:sort lang value {lang:?} is invalid: {error}"))
    })?;
    let mut preferences = CollatorPreferences::from(locale);
    preferences.case_first = match case_order {
        Some("upper-first") => Some(CollationCaseFirst::Upper),
        Some("lower-first") => Some(CollationCaseFirst::Lower),
        _ => None,
    };
    Collator::try_new(preferences, CollatorOptions::default())
        .map_err(|error| Error::Dynamic(format!("xsl:sort lang {lang:?} is unavailable: {error}")))
}
fn xpath_to_public(value: XPathValue) -> Value {
    match value {
        XPathValue::NodeSet(nodes) => Value::NodeSet(nodes),
        XPathValue::ResultTreeFragment(document) => Value::ResultTreeFragment(document),
        XPathValue::Boolean(value) => Value::Boolean(value),
        XPathValue::Number(value) => Value::Number(value),
        XPathValue::String(value) => Value::String(value),
        XPathValue::StoredExpression(value) => Value::StoredExpression(value),
    }
}

fn xpath_value_kind(value: &XPathValue) -> &'static str {
    match value {
        XPathValue::NodeSet(_) => "node-set",
        XPathValue::ResultTreeFragment(_) => "result-tree-fragment",
        XPathValue::Boolean(_) => "boolean",
        XPathValue::Number(_) => "number",
        XPathValue::String(_) => "string",
        XPathValue::StoredExpression(_) => "stored-expression",
    }
}

fn public_to_xpath(value: Value) -> XPathValue {
    match value {
        Value::NodeSet(nodes) => XPathValue::NodeSet(nodes),
        Value::ResultTreeFragment(document) => XPathValue::ResultTreeFragment(document),
        Value::Boolean(value) => XPathValue::Boolean(value),
        Value::Number(value) => XPathValue::Number(value),
        Value::String(value) => XPathValue::String(value),
        Value::StoredExpression(value) => XPathValue::StoredExpression(value),
    }
}

fn direct_variable_reference(
    expression: &crate::compiler::Expression,
) -> Result<Option<ExpandedName>> {
    let source = expression.source.trim();
    let Some(lexical) = source.strip_prefix('$') else {
        return Ok(None);
    };
    if !is_lexical_variable_name(lexical) {
        return Ok(None);
    }
    expanded_variable_name(lexical, &expression.namespaces).map(Some)
}

fn expanded_variable_name(lexical: &str, namespaces: &[(String, String)]) -> Result<ExpandedName> {
    let (prefix, local) = lexical
        .split_once(':')
        .map_or((None, lexical), |(prefix, local)| (Some(prefix), local));
    let namespace = prefix
        .map(|prefix| {
            namespaces
                .iter()
                .find(|(candidate, _)| candidate == prefix)
                .map(|(_, namespace)| namespace.clone())
                .ok_or_else(|| Error::Static(format!("unbound variable prefix {prefix}")))
        })
        .transpose()?;
    Ok(ExpandedName::new(namespace, local))
}

fn is_lexical_variable_name(value: &str) -> bool {
    let mut parts = value.split(':');
    let Some(first) = parts.next() else {
        return false;
    };
    is_ncname(first) && parts.next().is_none_or(is_ncname) && parts.next().is_none()
}

fn quoted_literal(value: &str) -> Option<&str> {
    let quote = value.as_bytes().first().copied()?;
    if !matches!(quote, b'\'' | b'"') || value.as_bytes().last().copied() != Some(quote) {
        return None;
    }
    value.get(1..value.len().saturating_sub(1))
}

fn split_name(value: &str) -> Result<(Option<String>, String)> {
    if let Some((prefix, local)) = value.split_once(':') {
        if local.contains(':') || !is_ncname(prefix) || !is_ncname(local) {
            return Err(Error::Dynamic(format!("invalid computed QName {value}")));
        }
        Ok((Some(prefix.into()), local.into()))
    } else if !is_ncname(value) {
        Err(Error::Dynamic(format!("invalid computed QName {value}")))
    } else {
        Ok((None, value.into()))
    }
}

fn normalize_computed_namespace(
    prefix: Option<String>,
    namespace: Option<String>,
    lexical: &str,
) -> Result<(Option<String>, Option<String>)> {
    const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
    const XMLNS_NS: &str = "http://www.w3.org/2000/xmlns/";

    if namespace.as_deref() == Some("") {
        return Ok((None, None));
    }
    if namespace.as_deref() == Some(XMLNS_NS) {
        return Err(Error::Dynamic(format!(
            "computed QName `{lexical}` uses the reserved xmlns namespace"
        )));
    }
    if namespace.as_deref() == Some(XML_NS) {
        // XSLT permits changing the lexical prefix to construct the requested expanded name.
        return Ok((Some("xml".into()), namespace));
    }
    if matches!(prefix.as_deref(), Some("xml" | "xmlns")) {
        // Preserve the requested expanded name while letting namespace fixup choose a legal
        // replacement for a reserved lexical prefix.
        return Ok((None, namespace));
    }
    Ok((prefix, namespace))
}

fn static_namespace(namespaces: &[(String, String)], prefix: &str) -> Option<String> {
    namespaces
        .iter()
        .rev()
        .find(|(candidate, _)| candidate == prefix)
        .map(|(_, uri)| uri.clone())
}

fn computed_element_namespace(
    namespaces: &[(String, String)],
    prefix: Option<&str>,
) -> Option<String> {
    // XSLT 1.0 section 7.1.2 includes the default namespace when expanding an unprefixed
    // xsl:element name. This intentionally differs from xsl:attribute (section 7.1.3).
    static_namespace(namespaces, prefix.unwrap_or_default())
}

fn require_bound_computed_prefix(
    prefix: Option<&str>,
    namespace: Option<&str>,
    lexical: &str,
) -> Result<()> {
    if let Some(prefix) = prefix
        && namespace.is_none()
    {
        return Err(Error::Dynamic(format!(
            "computed QName `{lexical}` uses unbound prefix `{prefix}`"
        )));
    }
    Ok(())
}

fn validate_computed_attribute_name(
    prefix: Option<&str>,
    local: &str,
    namespace: Option<&str>,
) -> Result<()> {
    const XMLNS_NS: &str = "http://www.w3.org/2000/xmlns/";

    if (prefix.is_none() && local == "xmlns") || namespace == Some(XMLNS_NS) {
        return Err(Error::Dynamic(
            "xsl:attribute cannot construct an XML namespace declaration".into(),
        ));
    }
    Ok(())
}
fn format_number_sequence(
    values: &[f64],
    format: &str,
    _lang: Option<&str>,
    letter_value: Option<&str>,
    separator: Option<char>,
    size: Option<usize>,
) -> String {
    if values.is_empty() {
        return String::new();
    }
    let tokens = tokenize_number_format(format);
    if tokens.formats.is_empty() {
        return values
            .iter()
            .map(|value| format_number(*value, "1", letter_value, separator, size))
            .collect::<Vec<_>>()
            .join(".");
    }
    let mut output = tokens.prefix;
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            output.push_str(
                tokens
                    .separators
                    .get(index - 1)
                    .or_else(|| tokens.separators.last())
                    .map_or(".", String::as_str),
            );
        }
        let token = tokens
            .formats
            .get(index)
            .or_else(|| tokens.formats.last())
            .map_or("1", String::as_str);
        output.push_str(&format_number(*value, token, letter_value, separator, size));
    }
    output.push_str(&tokens.suffix);
    output
}

struct NumberFormatTokens {
    prefix: String,
    formats: Vec<String>,
    separators: Vec<String>,
    suffix: String,
}

fn expanded_name_owned_bytes(name: &ExpandedName) -> usize {
    name.namespace
        .as_ref()
        .map_or(0, String::len)
        .saturating_add(name.local.len())
}

fn attribute_owned_bytes(attribute: &Attribute) -> usize {
    expanded_name_owned_bytes(&attribute.name)
        .saturating_add(attribute.prefix.as_ref().map_or(0, String::len))
        .saturating_add(attribute.value.len())
}

fn namespace_owned_bytes(namespace: &Namespace) -> usize {
    namespace
        .prefix
        .as_ref()
        .map_or(0, String::len)
        .saturating_add(namespace.uri.len())
}

fn node_kind_owned_bytes(kind: &NodeKind) -> usize {
    match kind {
        NodeKind::Root => 0,
        NodeKind::Text { value, .. } | NodeKind::Comment(value) => value.len(),
        NodeKind::ProcessingInstruction { target, value } => target
            .len()
            .saturating_add(value.as_ref().map_or(0, String::len)),
        NodeKind::Element {
            name,
            prefix,
            attributes,
            namespaces,
        } => attributes
            .iter()
            .fold(
                expanded_name_owned_bytes(name)
                    .saturating_add(prefix.as_ref().map_or(0, String::len)),
                |total, attribute| total.saturating_add(attribute_owned_bytes(attribute)),
            )
            .saturating_add(namespaces.iter().fold(0usize, |total, namespace| {
                total.saturating_add(namespace_owned_bytes(namespace))
            })),
    }
}

fn value_owned_bytes(value: &Value) -> usize {
    match value {
        Value::NodeSet(nodes) => nodes
            .len()
            .saturating_mul(std::mem::size_of::<NodeReference>()),
        Value::Boolean(_) | Value::Number(_) => 0,
        Value::String(value) | Value::StoredExpression(value) => value.len(),
        Value::ResultTreeFragment(document) => document
            .source_xml()
            .map_or(0, str::len)
            .saturating_add(document.nodes().fold(0usize, |total, (_, node)| {
                total
                    .saturating_add(node_kind_owned_bytes(&node.kind))
                    .saturating_add(node.base_uri.as_ref().map_or(0, String::len))
                    .saturating_add(
                        node.children
                            .len()
                            .saturating_mul(std::mem::size_of::<NodeId>()),
                    )
            })),
    }
}

fn tokenize_number_format(format: &str) -> NumberFormatTokens {
    let mut runs = Vec::<(bool, String)>::new();
    for character in format.chars() {
        let alphanumeric = character.is_alphanumeric();
        if runs.last().is_some_and(|(kind, _)| *kind == alphanumeric) {
            runs.last_mut().expect("run exists").1.push(character);
        } else {
            runs.push((alphanumeric, character.to_string()));
        }
    }
    let prefix = runs
        .first()
        .filter(|(alphanumeric, _)| !*alphanumeric)
        .map(|(_, value)| value.clone())
        .unwrap_or_default();
    let suffix = runs
        .last()
        .filter(|(alphanumeric, _)| !*alphanumeric)
        .map(|(_, value)| value.clone())
        .unwrap_or_default();
    let formats = runs
        .iter()
        .filter(|(alphanumeric, _)| *alphanumeric)
        .map(|(_, value)| value.clone())
        .collect::<Vec<_>>();
    let separators = runs
        .iter()
        .skip_while(|(alphanumeric, _)| !*alphanumeric)
        .skip(1)
        .take_while(|_| true)
        .filter(|(alphanumeric, _)| !*alphanumeric)
        .map(|(_, value)| value.clone())
        .take(formats.len().saturating_sub(1))
        .collect();
    NumberFormatTokens {
        prefix,
        formats,
        separators,
        suffix,
    }
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
    if rounded <= 0.0 {
        let width = format
            .chars()
            .filter(|character| unicode_decimal_value(*character).is_some())
            .count()
            .max(1);
        return localize_decimal_digits(&"0".repeat(width), format);
    }
    let mut output = match format {
        "A" | "a" if letter_value != Some("traditional") => {
            alphabetic(rounded as usize, format == "A")
        }
        "I" | "i" => roman(rounded as usize, format == "I"),
        _ => {
            let width = format
                .chars()
                .filter(|character| unicode_decimal_value(*character).is_some())
                .count();
            let ascii = if width > 1 {
                format!("{rounded:0width$.0}")
            } else {
                format!("{rounded:.0}")
            };
            localize_decimal_digits(&ascii, format)
        }
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

fn localize_decimal_digits(value: &str, token: &str) -> String {
    let zero = token
        .chars()
        .filter_map(|character| {
            unicode_decimal_value(character).and_then(|digit| {
                u32::from(character)
                    .checked_sub(digit)
                    .and_then(char::from_u32)
            })
        })
        .next_back()
        .unwrap_or('0');
    value
        .chars()
        .map(|character| {
            character
                .to_digit(10)
                .and_then(|digit| char::from_u32(u32::from(zero) + digit))
                .unwrap_or(character)
        })
        .collect()
}

fn same_node_kind_and_name(document: &Document, left: &SourceNode, right: &SourceNode) -> bool {
    match (left, right) {
        (
            SourceNode::Attribute {
                owner: left_owner,
                index: left_index,
            },
            SourceNode::Attribute {
                owner: right_owner,
                index: right_index,
            },
        ) => {
            let attribute = |owner, index| {
                document.node(owner).and_then(|node| match &node.kind {
                    NodeKind::Element { attributes, .. } => attributes.get(index),
                    _ => None,
                })
            };
            attribute(*left_owner, *left_index).map(|attribute| &attribute.name)
                == attribute(*right_owner, *right_index).map(|attribute| &attribute.name)
        }
        (
            SourceNode::Namespace {
                owner: left_owner,
                index: left_index,
            },
            SourceNode::Namespace {
                owner: right_owner,
                index: right_index,
            },
        ) => {
            let namespace = |owner, index| {
                document.node(owner).and_then(|node| match &node.kind {
                    NodeKind::Element { namespaces, .. } => namespaces.get(index),
                    _ => None,
                })
            };
            namespace(*left_owner, *left_index).map(|namespace| &namespace.prefix)
                == namespace(*right_owner, *right_index).map(|namespace| &namespace.prefix)
        }
        (SourceNode::Node(left), SourceNode::Node(right)) => match (
            document.node(*left).map(|node| &node.kind),
            document.node(*right).map(|node| &node.kind),
        ) {
            (
                Some(NodeKind::Element { name: left, .. }),
                Some(NodeKind::Element { name: right, .. }),
            ) => left == right,
            (Some(NodeKind::Text { .. }), Some(NodeKind::Text { .. }))
            | (Some(NodeKind::Comment(_)), Some(NodeKind::Comment(_)))
            | (Some(NodeKind::Root), Some(NodeKind::Root)) => true,
            (
                Some(NodeKind::ProcessingInstruction { target: left, .. }),
                Some(NodeKind::ProcessingInstruction { target: right, .. }),
            ) => left == right,
            _ => false,
        },
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
