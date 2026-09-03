use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use icu_collator::preferences::CollationCaseFirst;
use icu_collator::{Collator, CollatorBorrowed, CollatorPreferences, options::CollatorOptions};
use icu_locale::Locale;

use crate::budget::{Meter, reserve_temporary_vec_slot};
use crate::compiler::{
    AttributeValueTemplate, AvtPart, Expression, ExsltFunction, Instruction, NameTest, Sort,
    Stylesheet, Template, Variable,
};
use crate::lexical::{is_ncname, is_xml_whitespace, unicode_decimal_value, xpath_string_literal};
use crate::serializer::{serialize, serialize_fragment};
use crate::xpath::{
    CustomCallSession, EXSLT_COMMON_NS, Evaluator, EvaluatorSourceOptions, PreparedEvaluatorSource,
    SourceNode, XPathValue, parse_xpath_number, prepare_evaluator_source, xpath_number,
};
use crate::{
    Attribute, BudgetKind, Document, Error, ExecutionBudget, ExecutionEnvironment, ExpandedName,
    Namespace, NodeId, NodeKind, NodeReference, Resolver, Result, SerializedOutput, Value,
};

/// Top-level stylesheet parameters supplied by the caller.
pub type Parameters = HashMap<ExpandedName, Value>;

struct SourceParameterRemap {
    identity: u64,
    mapping: Option<HashMap<NodeId, NodeId>>,
    owned_bytes: usize,
}

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
        let source_bytes = source.source_bytes();
        let source_identity = source.identity();
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
        let source_remap = SourceParameterRemap {
            identity: source_identity,
            mapping: prepared.remap.take(),
            owned_bytes: std::mem::take(&mut prepared.remap_owned_bytes),
        };
        let mut state = Execution::new(
            self,
            prepared,
            parameters,
            source_remap,
            environment,
            meter,
            source_options,
        )?;
        let root = SourceNode::Node(state.evaluator.source.root());
        if let Some(name) = options.initial_template {
            state.call_named(
                &name,
                Arc::new(EvaluatedParameters::default()),
                &root,
                ApplyFrame::new(1, 1, 1),
                None,
            )?;
        } else {
            state.apply_one(
                root,
                options.initial_mode.as_ref(),
                Arc::new(EvaluatedParameters::default()),
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
    meter: &mut Meter,
) -> Result<Option<(HashMap<NodeId, NodeId>, usize)>> {
    if rules.is_empty() {
        return Ok(None);
    }
    if !document
        .nodes()
        .any(|(_, node)| should_strip_whitespace(document, node, rules))
    {
        return Ok(None);
    }
    document
        .retain_nodes(meter, |source, _, node| {
            !should_strip_whitespace(source, node, rules)
        })
        .map(Some)
}

fn should_strip_whitespace(
    document: &Document,
    node: &crate::model::Node,
    rules: &[(NameTest, bool, usize, usize)],
) -> bool {
    let NodeKind::Text { value, .. } = &node.kind else {
        return false;
    };
    if !value
        .chars()
        .all(|character| matches!(character, '\t' | '\n' | '\r' | ' '))
    {
        return false;
    }
    let Some(parent) = node.parent.and_then(|parent| document.node(parent)) else {
        return false;
    };
    let NodeKind::Element { name, .. } = &parent.kind else {
        return false;
    };
    // XSLT 1.0 section 3.4 makes inherited xml:space="preserve" an independent
    // preservation condition, so a matching xsl:strip-space rule cannot override it.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#strip
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
        return false;
    }
    let decision = rules
        .iter()
        .filter(|(test, _, _, _)| test.matches(name))
        .max_by_key(|(test, _, precedence, order)| (*precedence, test.priority(), *order));
    matches!(decision, Some((_, false, _, _)))
}

struct Execution<'a> {
    stylesheet: &'a Stylesheet,
    evaluator: Evaluator,
    result: Document,
    output_stack: Vec<NodeId>,
    scopes: Vec<VariableScope>,
    // A global leaves this map before evaluation, so recursive access is detected without
    // replaying side effects or retrying a failed initializer.
    pending_globals: HashMap<ExpandedName, &'a crate::compiler::GlobalVariable>,
    initializing_globals: Vec<ExpandedName>,
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
    attribute_protected_names: Option<HashSet<ExpandedName>>,
}

#[derive(Default)]
struct VariableScope {
    values: HashMap<ExpandedName, Value>,
    retained_owned_bytes: usize,
}

impl VariableScope {
    fn insert_retained(&mut self, name: ExpandedName, value: Value, retained_owned_bytes: usize) {
        self.retained_owned_bytes = self
            .retained_owned_bytes
            .saturating_add(retained_owned_bytes);
        self.values.insert(name, value);
    }
}

impl Deref for VariableScope {
    type Target = HashMap<ExpandedName, Value>;

    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

impl DerefMut for VariableScope {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.values
    }
}

struct RetainedValue {
    value: Value,
    retained_owned_bytes: usize,
}

struct CapturedText {
    value: String,
    retained_owned_bytes: usize,
}

impl CapturedText {
    fn transfer(self, meter: &mut Meter) -> String {
        meter.release_owned_bytes(self.retained_owned_bytes);
        self.value
    }
}

#[derive(Default)]
struct EvaluatedParameters {
    values: HashMap<ExpandedName, Value>,
    retained_owned_bytes: usize,
}

impl Deref for EvaluatedParameters {
    type Target = HashMap<ExpandedName, Value>;

    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

struct ResultTreeState {
    document: Document,
    output_stack: Vec<NodeId>,
    attribute_insert_position: Option<usize>,
    attribute_protected_names: Option<HashSet<ExpandedName>>,
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
        params: Arc<EvaluatedParameters>,
        node: SourceNode,
        frame: ApplyFrame,
        current_rule_precedence: Option<usize>,
    },
    ApplyOne {
        node: SourceNode,
        mode: Option<ExpandedName>,
        params: Arc<EvaluatedParameters>,
        frame: ApplyFrame,
    },
    ApplyBatch {
        nodes: Vec<SourceNode>,
        next: usize,
        mode: Option<ExpandedName>,
        params: Arc<EvaluatedParameters>,
        depth: usize,
        reserved_owned_bytes: usize,
    },
    ForEachBatch {
        nodes: Vec<SourceNode>,
        next: usize,
        body: Arc<[Instruction]>,
        depth: usize,
        reserved_owned_bytes: usize,
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
    RestoreScopes(Vec<VariableScope>),
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
        source_remap: SourceParameterRemap,
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
        let result = Document::empty(None);
        meter.charge(
            BudgetKind::OwnedBytes,
            metered_document_owned_bytes(&result),
        )?;
        let result_root = result.root();
        let mut state = Self {
            stylesheet,
            evaluator,
            result,
            output_stack: vec![result_root],
            scopes: vec![VariableScope::default()],
            pending_globals: HashMap::new(),
            initializing_globals: Vec::new(),
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
            attribute_protected_names: None,
        };
        state.evaluator.initialize_xslt(
            &stylesheet.decimal_formats,
            stylesheet
                .functions
                .iter()
                .map(|function| function.name.clone()),
        );
        let SourceParameterRemap {
            identity,
            mapping,
            owned_bytes,
        } = source_remap;
        let initialized = state.initialize_globals(parameters, identity, mapping.as_ref());
        drop(mapping);
        state.meter.release_owned_bytes(owned_bytes);
        initialized?;
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

    fn ensure_key_indexes_for_all_documents(
        &mut self,
        source: &str,
        namespaces: &[(String, String)],
    ) -> Result<()> {
        let requested = literal_key_names(source, namespaces)?.unwrap_or_else(|| {
            self.stylesheet
                .keys
                .iter()
                .map(|declaration| declaration.name.clone())
                .collect()
        });
        let roots = self.evaluator.source.logical_roots().to_vec();
        for root in roots {
            for name in &requested {
                self.build_key(name, root)?;
            }
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
        let declarations = Arc::clone(&self.stylesheet.keys);
        let variables = HashMap::new();
        for declaration in declarations
            .iter()
            .filter(|declaration| &declaration.name == name)
        {
            let mut pending = Vec::new();
            let mut pending_reservation = 0usize;
            reserve_temporary_vec_slot(&mut pending, &mut self.meter, &mut pending_reservation)?;
            pending.push(logical_root);
            let result = (|| {
                while let Some(id) = pending.pop() {
                    let (child_count, attribute_count) =
                        self.evaluator.source.node(id).map_or((0, 0), |source| {
                            let attributes = if declaration.match_pattern.matches_attributes {
                                match &source.kind {
                                    NodeKind::Element { attributes, .. } => attributes.len(),
                                    _ => 0,
                                }
                            } else {
                                0
                            };
                            (source.children.len(), attributes)
                        });
                    for child_index in (0..child_count).rev() {
                        let Some(child) = self
                            .evaluator
                            .source
                            .node(id)
                            .and_then(|source| source.children.get(child_index))
                            .copied()
                        else {
                            continue;
                        };
                        reserve_temporary_vec_slot(
                            &mut pending,
                            &mut self.meter,
                            &mut pending_reservation,
                        )?;
                        pending.push(child);
                    }
                    self.append_key_values(declaration, SourceNode::Node(id), &variables)?;
                    for index in 0..attribute_count {
                        self.append_key_values(
                            declaration,
                            SourceNode::Attribute { owner: id, index },
                            &variables,
                        )?;
                    }
                }
                Ok(())
            })();
            drop(pending);
            self.meter.release_owned_bytes(pending_reservation);
            result?;
            self.evaluator.finish_key_index(&mut self.meter);
        }
        self.building_keys.remove(&identity);
        self.built_keys.insert(identity);
        Ok(())
    }

    fn append_key_values(
        &mut self,
        declaration: &crate::compiler::KeyDeclaration,
        node: SourceNode,
        variables: &HashMap<ExpandedName, Value>,
    ) -> Result<()> {
        if !self.matches_pattern(&declaration.match_pattern, &node, variables)? {
            return Ok(());
        }
        match self.evaluate(&declaration.use_expression, &node, 1, 1)? {
            XPathValue::NodeSet(nodes) => {
                for selected in nodes.iter() {
                    let value = self.evaluator.string_value(selected);
                    self.evaluator.append_key_entry(
                        declaration.name.clone(),
                        value,
                        &node,
                        &mut self.meter,
                    )?;
                }
            }
            value => {
                let value = value.string(&self.evaluator);
                self.evaluator.append_key_entry(
                    declaration.name.clone(),
                    value,
                    &node,
                    &mut self.meter,
                )?;
            }
        }
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
        source_identity: u64,
        source_remap: Option<&HashMap<NodeId, NodeId>>,
    ) -> Result<()> {
        let mut effective: HashMap<_, &crate::compiler::GlobalVariable> = HashMap::new();
        for global in self.stylesheet.globals.iter() {
            if let Some(current) = effective.get(&global.variable.name) {
                match global.precedence.cmp(&current.precedence) {
                    Ordering::Greater => {
                        effective.insert(global.variable.name.clone(), global);
                    }
                    Ordering::Equal => {
                        return Err(Error::Static(format!(
                            "duplicate global variable {} at equal import precedence",
                            global.variable.name.local
                        )));
                    }
                    Ordering::Less => {}
                }
            } else {
                effective.insert(global.variable.name.clone(), global);
            }
        }
        let mut order = effective.values().copied().collect::<Vec<_>>();
        order.sort_by_key(|global| global.order);
        for global in &order {
            let name = &global.variable.name;
            if global.is_parameter
                && let Some(value) = parameters.get(name)
            {
                validate_parameter_value(value, source_identity)?;
                let owned_bytes = expanded_name_owned_bytes(name)
                    .saturating_add(parameter_value_owned_bytes(value, source_remap));
                self.meter
                    .check_additional(BudgetKind::OwnedBytes, owned_bytes)?;
                let value = source_remap.map_or_else(
                    || value.clone(),
                    |remap| remap_parameter_value(value, remap),
                );
                self.meter.charge(BudgetKind::OwnedBytes, owned_bytes)?;
                self.scopes[0].insert_retained(name.clone(), value, owned_bytes);
                effective.remove(name);
            }
        }
        self.pending_globals = effective;
        for global in order {
            self.ensure_global(&global.variable.name)?;
        }
        Ok(())
    }

    fn ensure_global(&mut self, name: &ExpandedName) -> Result<()> {
        if self.scopes[0].contains_key(name) {
            return Ok(());
        }
        if self
            .initializing_globals
            .iter()
            .any(|active| active == name)
        {
            let mut names = self
                .initializing_globals
                .iter()
                .map(|active| active.local.as_str())
                .collect::<Vec<_>>();
            names.push(name.local.as_str());
            return Err(Error::Dynamic(format!(
                "circular global variable dependency: {}",
                names.join(" -> ")
            )));
        }
        let Some(global) = self.pending_globals.remove(name) else {
            return Ok(());
        };
        self.initializing_globals.push(name.clone());
        let value = self.evaluate_variable(
            &global.variable,
            &SourceNode::Node(self.evaluator.source.root()),
            1,
            1,
            1,
            None,
        );
        self.initializing_globals.pop();
        let retained = value?;
        self.scopes[0].insert_retained(name.clone(), retained.value, retained.retained_owned_bytes);
        Ok(())
    }

    fn ensure_expression_globals(&mut self, expression: &Expression) -> Result<()> {
        for name in expression.variable_references.iter() {
            if !self
                .scopes
                .iter()
                .rev()
                .any(|scope| scope.contains_key(name))
            {
                self.ensure_global(name)?;
            }
        }
        Ok(())
    }

    fn variables(&mut self) -> Result<(HashMap<ExpandedName, Value>, usize)> {
        let (capacity, reserved_owned_bytes) = visible_variable_snapshot_size(&self.scopes);
        self.meter
            .charge(BudgetKind::OwnedBytes, reserved_owned_bytes)?;
        let mut variables = HashMap::with_capacity(capacity);
        for scope in &self.scopes {
            variables.extend(
                scope
                    .iter()
                    .map(|(name, value)| (name.clone(), value.clone())),
            );
        }
        Ok((variables, reserved_owned_bytes))
    }

    fn pop_scope(&mut self) {
        let scope = self
            .scopes
            .pop()
            .expect("scope stack retains its global scope");
        self.meter.release_owned_bytes(scope.retained_owned_bytes);
    }

    fn release_parameters_if_last(&mut self, parameters: &Arc<EvaluatedParameters>) {
        if Arc::strong_count(parameters) == 1 {
            self.meter
                .release_owned_bytes(parameters.retained_owned_bytes);
        }
    }

    fn apply_one(
        &mut self,
        node: SourceNode,
        mode: Option<&ExpandedName>,
        params: Arc<EvaluatedParameters>,
        frame: ApplyFrame,
    ) -> Result<()> {
        self.run_template_tasks(vec![TemplateTask::ApplyOne {
            node,
            mode: mode.cloned(),
            params,
            frame,
        }])
    }

    fn execute_template(
        &mut self,
        template: &Template,
        node: SourceNode,
        params: Arc<EvaluatedParameters>,
        frame: ApplyFrame,
        current_rule_precedence: Option<usize>,
    ) -> Result<()> {
        self.run_template_tasks(vec![TemplateTask::EnterTemplate {
            template: Box::new(template.clone()),
            params,
            node,
            frame,
            current_rule_precedence,
        }])
    }

    fn run_template_tasks(&mut self, mut tasks: Vec<TemplateTask>) -> Result<()> {
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
                    params,
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
                TemplateTask::ApplyBatch {
                    nodes,
                    next,
                    mode,
                    params,
                    depth,
                    reserved_owned_bytes,
                } => {
                    let Some(selected) = nodes.get(next).cloned() else {
                        self.release_parameters_if_last(&params);
                        self.meter.release_owned_bytes(reserved_owned_bytes);
                        continue;
                    };
                    let total = nodes.len();
                    let selected_mode = mode.clone();
                    tasks.push(TemplateTask::ApplyBatch {
                        nodes,
                        next: next + 1,
                        mode,
                        params: Arc::clone(&params),
                        depth,
                        reserved_owned_bytes,
                    });
                    tasks.push(TemplateTask::ApplyOne {
                        node: selected,
                        mode: selected_mode,
                        params,
                        frame: ApplyFrame::new(next + 1, total, depth),
                    });
                }
                TemplateTask::ForEachBatch {
                    nodes,
                    next,
                    body,
                    depth,
                    reserved_owned_bytes,
                } => {
                    let Some(selected) = nodes.get(next).cloned() else {
                        self.meter.release_owned_bytes(reserved_owned_bytes);
                        continue;
                    };
                    let total = nodes.len();
                    tasks.push(TemplateTask::ForEachBatch {
                        nodes,
                        next: next + 1,
                        body: Arc::clone(&body),
                        depth,
                        reserved_owned_bytes,
                    });
                    push_scoped_sequence(
                        &mut tasks,
                        body,
                        selected,
                        ApplyFrame::new(next + 1, total, depth),
                        None,
                    );
                }
                TemplateTask::RestoreScopes(caller_scopes) => {
                    self.pop_scope();
                    self.scopes.extend(caller_scopes);
                }
                TemplateTask::RestoreMode => {
                    self.modes.pop();
                }
                TemplateTask::PopOutput => {
                    self.output_stack.pop();
                }
                TemplateTask::PushScope => self.scopes.push(VariableScope::default()),
                TemplateTask::PopScope => {
                    self.pop_scope();
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
                                precedence,
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
                                params: Arc::new(supplied),
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
                                precedence,
                            )?);
                            self.push_apply_batch(&mut tasks, nodes, mode, supplied, depth + 1)?;
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
                                params: Arc::new(EvaluatedParameters::default()),
                                frame: ApplyFrame {
                                    max_precedence: Some(current_rule_precedence),
                                    position,
                                    size,
                                    depth: depth + 1,
                                },
                            });
                        }
                        Instruction::LiteralElement {
                            base_uri,
                            name,
                            prefix,
                            attributes,
                            namespaces,
                            children,
                            attribute_sets,
                        } => {
                            let (name, prefix, result_namespaces) = self
                                .alias_literal_name_and_namespaces(
                                    &name,
                                    prefix.as_deref(),
                                    &namespaces,
                                );
                            let id = self.push_node_with_base(
                                self.parent(),
                                NodeKind::Element {
                                    name,
                                    prefix,
                                    attributes: vec![],
                                    namespaces: result_namespaces,
                                },
                                base_uri.clone(),
                            )?;
                            self.output_stack.push(id);
                            for set in &attribute_sets {
                                self.apply_attribute_set(
                                    set,
                                    &node,
                                    ApplyFrame::new(position, size, depth),
                                    precedence,
                                    &mut Vec::new(),
                                )?;
                            }
                            for attribute in &attributes {
                                let value =
                                    self.evaluate_avt(&attribute.value, &node, position, size)?;
                                let (name, prefix) = self.alias_attribute_name(
                                    &attribute.name,
                                    attribute.prefix.as_deref(),
                                );
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
                                let source =
                                    self.evaluator.source.node(*source_id).ok_or_else(|| {
                                        Error::Dynamic("stale source node".into())
                                    })?;
                                let kind = clone_for_xsl_copy(&source.kind, &self.meter)?;
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
                                                ApplyFrame::new(position, size, depth),
                                                precedence,
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
                            self.push_for_each_batch(&mut tasks, nodes, body.into(), depth + 1)?;
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
        params: Arc<EvaluatedParameters>,
        frame: ApplyFrame,
    ) -> Result<()> {
        self.meter.recursion(frame.depth)?;
        self.meter.charge(BudgetKind::TemplateApplications, 1)?;
        let variables = HashMap::new();
        let mut selected = None::<&Template>;
        for template in self.stylesheet.templates.iter() {
            if template.pattern.is_none()
                || template.mode != mode
                || frame
                    .max_precedence
                    .is_some_and(|max| template.precedence >= max)
            {
                continue;
            }
            let pattern = template.pattern.as_ref().expect("pattern was checked");
            if self.matches_pattern(pattern, &node, &variables)?
                && selected.is_none_or(|current| {
                    template.precedence > current.precedence
                        || (template.precedence == current.precedence
                            && (template.priority > current.priority
                                || (template.priority == current.priority
                                    && template.order > current.order)))
                })
            {
                selected = Some(template);
            }
        }
        let selected = selected.cloned();
        if let Some(template) = selected {
            self.modes.push(mode);
            tasks.push(TemplateTask::RestoreMode);
            let current_rule_precedence = Some(template.precedence);
            tasks.push(TemplateTask::EnterTemplate {
                template: Box::new(template),
                params,
                node,
                frame,
                current_rule_precedence,
            });
            return Ok(());
        }
        self.release_parameters_if_last(&params);
        match &node {
            SourceNode::Node(id) => {
                let kind = self.evaluator.source.node(*id).map(|source| &source.kind);
                match kind {
                    Some(NodeKind::Root | NodeKind::Element { .. }) => {
                        let children = self.evaluator.children(&node);
                        let built_in_params = Arc::new(EvaluatedParameters::default());
                        self.push_apply_batch(
                            tasks,
                            children,
                            mode,
                            built_in_params,
                            frame.depth + 1,
                        )
                    }
                    // Result text must own its payload; cloning only this leaf avoids cloning element
                    // attributes, namespaces, and child storage merely to choose a built-in rule.
                    Some(NodeKind::Text { value, .. }) => {
                        let value = value.clone();
                        self.append_owned_text(value, false)
                    }
                    _ => Ok(()),
                }
            }
            SourceNode::Attribute { .. } => {
                let value = self.evaluator.string_value(&node);
                self.append_text(&value, false)
            }
            SourceNode::Namespace { .. } => Ok(()),
        }
    }

    fn push_apply_batch(
        &mut self,
        tasks: &mut Vec<TemplateTask>,
        nodes: Vec<SourceNode>,
        mode: Option<ExpandedName>,
        params: Arc<EvaluatedParameters>,
        depth: usize,
    ) -> Result<()> {
        if nodes.is_empty() {
            self.release_parameters_if_last(&params);
            return Ok(());
        }
        let node_bytes = nodes
            .capacity()
            .saturating_mul(std::mem::size_of::<SourceNode>());
        // The batch retains one mode while one serial application can hold a second clone.
        let mode_bytes = mode
            .as_ref()
            .map_or(0, expanded_name_owned_bytes)
            .saturating_mul(2);
        let reserved_owned_bytes = node_bytes.saturating_add(mode_bytes);
        self.meter
            .charge(BudgetKind::OwnedBytes, reserved_owned_bytes)?;
        tasks.push(TemplateTask::ApplyBatch {
            nodes,
            next: 0,
            mode,
            params,
            depth,
            reserved_owned_bytes,
        });
        Ok(())
    }

    fn push_for_each_batch(
        &mut self,
        tasks: &mut Vec<TemplateTask>,
        nodes: Vec<SourceNode>,
        body: Arc<[Instruction]>,
        depth: usize,
    ) -> Result<()> {
        if nodes.is_empty() {
            return Ok(());
        }
        let reserved_owned_bytes = nodes
            .capacity()
            .saturating_mul(std::mem::size_of::<SourceNode>());
        self.meter
            .charge(BudgetKind::OwnedBytes, reserved_owned_bytes)?;
        tasks.push(TemplateTask::ForEachBatch {
            nodes,
            next: 0,
            body,
            depth,
            reserved_owned_bytes,
        });
        Ok(())
    }

    fn push_template_tasks(
        &mut self,
        tasks: &mut Vec<TemplateTask>,
        template: &Template,
        params: Arc<EvaluatedParameters>,
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
        self.scopes.push(VariableScope::default());
        for parameter in &template.params {
            let retained = if let Some(value) = params.get(&parameter.name) {
                let retained_owned_bytes = binding_owned_bytes(&parameter.name, value);
                self.meter
                    .check_additional(BudgetKind::OwnedBytes, retained_owned_bytes)?;
                let value = value.clone();
                self.meter
                    .charge(BudgetKind::OwnedBytes, retained_owned_bytes)?;
                RetainedValue {
                    value,
                    retained_owned_bytes,
                }
            } else {
                self.evaluate_variable(
                    parameter,
                    &node,
                    position,
                    size,
                    depth,
                    current_rule_precedence,
                )?
            };
            self.scopes
                .last_mut()
                .expect("template parameter scope exists")
                .insert_retained(
                    parameter.name.clone(),
                    retained.value,
                    retained.retained_owned_bytes,
                );
        }
        self.release_parameters_if_last(&params);
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

    fn execute_scoped_sequence(
        &mut self,
        instructions: &[Instruction],
        node: &SourceNode,
        position: usize,
        size: usize,
        depth: usize,
        current_precedence: Option<usize>,
    ) -> Result<()> {
        self.scopes.push(VariableScope::default());
        let result = self.execute_sequence(
            instructions,
            node,
            position,
            size,
            depth,
            current_precedence,
        );
        self.pop_scope();
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
                base_uri,
                name,
                prefix,
                attributes,
                namespaces,
                children,
                attribute_sets,
            } => {
                let (name, prefix, result_namespaces) =
                    self.alias_literal_name_and_namespaces(name, prefix.as_deref(), namespaces);
                let parent = self.parent();
                let id = self.push_node_with_base(
                    parent,
                    NodeKind::Element {
                        name,
                        prefix,
                        attributes: vec![],
                        namespaces: result_namespaces,
                    },
                    base_uri.clone(),
                )?;
                self.output_stack.push(id);
                for set in attribute_sets {
                    self.apply_attribute_set(
                        set,
                        node,
                        ApplyFrame::new(position, size, depth),
                        current_precedence,
                        &mut Vec::new(),
                    )?;
                }
                for attribute in attributes {
                    let value = self.evaluate_avt(&attribute.value, node, position, size)?;
                    let (name, prefix) =
                        self.alias_attribute_name(&attribute.name, attribute.prefix.as_deref());
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
                let supplied = Arc::new(self.evaluate_with_params(
                    parameters,
                    node,
                    position,
                    size,
                    depth,
                    current_precedence,
                )?);
                let total = nodes.len();
                for (index, selected) in nodes.into_iter().enumerate() {
                    self.apply_one(
                        selected,
                        mode.as_ref(),
                        Arc::clone(&supplied),
                        ApplyFrame::new(index + 1, total, depth + 1),
                    )?
                }
                self.release_parameters_if_last(&supplied);
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
                    Arc::new(EvaluatedParameters::default()),
                    ApplyFrame {
                        max_precedence: Some(current_rule_precedence),
                        position,
                        size,
                        depth: depth + 1,
                    },
                )
            }
            Instruction::CallTemplate { name, parameters } => {
                let supplied = Arc::new(self.evaluate_with_params(
                    parameters,
                    node,
                    position,
                    size,
                    depth,
                    current_precedence,
                )?);
                self.call_named(
                    name,
                    supplied,
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
                    self.scopes.push(VariableScope::default());
                    let result =
                        self.execute_sequence(body, selected, index + 1, total, depth + 1, None);
                    self.pop_scope();
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
                    .into_string(&self.evaluator);
                self.append_owned_text(value, *disable_output_escaping)
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
                        let text = value.into_string(&self.evaluator);
                        self.append_owned_text(text, false)?
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
                            let kind = clone_for_xsl_copy(&source.kind, &self.meter)?;
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
                                            ApplyFrame::new(position, size, depth),
                                            current_precedence,
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
                base_uri,
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
                let id = self.push_node_with_base(
                    self.parent(),
                    NodeKind::Element {
                        name: ExpandedName::new(namespace, local),
                        prefix,
                        namespaces,
                        attributes: vec![],
                    },
                    base_uri.clone(),
                )?;
                self.output_stack.push(id);
                for set in attribute_sets {
                    self.apply_attribute_set(
                        set,
                        node,
                        ApplyFrame::new(position, size, depth),
                        current_precedence,
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
                let value = value.transfer(&mut self.meter);
                self.add_attribute(Attribute {
                    name: ExpandedName::new(namespace, local),
                    prefix,
                    value,
                })
            }
            Instruction::Comment(body) => {
                let value =
                    self.capture_text(body, node, position, size, depth, current_precedence)?;
                let value = value.transfer(&mut self.meter);
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
                let mut value = value.transfer(&mut self.meter);
                let leading = value.len() - value.trim_start_matches([' ', '\t', '\r', '\n']).len();
                value.drain(..leading);
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
                    // XSLT 1.0 section 7.7 permits recovery from an invalid explicit value only by
                    // inserting its XPath string-value, before numbering tokens are considered.
                    // https://www.w3.org/TR/1999/REC-xslt-19991116#number
                    return self.append_text(&crate::value::format_xpath_number(*value), false);
                }
                let grouping_separator = number
                    .grouping_separator
                    .as_ref()
                    .map(|value| self.evaluate_avt(value, node, position, size))
                    .transpose()?
                    .map(|value| {
                        let mut characters = value.chars();
                        let Some(first) = characters.next() else {
                            // libxslt REC/test-7.7-6 classifies an explicit empty value as
                            // disabling grouping, distinct from malformed multi-character input.
                            return Ok(None);
                        };
                        if characters.next().is_some() {
                            return Err(Error::Dynamic(
                                "xsl:number grouping-separator must evaluate to at most one character"
                                    .into(),
                            ));
                        }
                        Ok(Some(first))
                    })
                    .transpose()?
                    .flatten();
                // XSLT 1.0 sections 7.7 and 7.7.1 define `grouping-size` as a numeric AVT;
                // libxslt converts its positive Number to an integral width by truncation.
                // https://www.w3.org/TR/1999/REC-xslt-19991116#number
                let grouping_size = number
                    .grouping_size
                    .as_ref()
                    .map(|value| self.evaluate_avt(value, node, position, size))
                    .transpose()?
                    .and_then(|value| parse_xpath_number(&value))
                    .filter(|value| value.is_finite())
                    .filter(|value| *value > 0.0)
                    .map(|value| value as usize)
                    .filter(|value| *value > 0);
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
                // XSLT 1.0 section 7.7 permits only these two evaluated AVT values. Section 2.5
                // requires an invalid optional value to be ignored in forwards-compatible mode.
                // https://www.w3.org/TR/1999/REC-xslt-19991116#number
                // https://www.w3.org/TR/1999/REC-xslt-19991116#forwards
                let letter_value = match letter_value.as_deref() {
                    None | Some("alphabetic" | "traditional") => letter_value.as_deref(),
                    Some(_) if number.forward_compatible => None,
                    Some(value) => {
                        return Err(Error::Dynamic(format!(
                            "xsl:number letter-value must evaluate to alphabetic or traditional, got `{value}`"
                        )));
                    }
                };
                let formatted = format_number_sequence(
                    &values,
                    &format,
                    lang.as_deref(),
                    letter_value,
                    grouping_separator,
                    grouping_size,
                    &self.meter,
                )?;
                self.append_owned_text(formatted, false)
            }
            Instruction::Variable(variable) => {
                let retained = self.evaluate_variable(
                    variable,
                    node,
                    position,
                    size,
                    depth,
                    current_precedence,
                )?;
                self.scopes
                    .last_mut()
                    .ok_or_else(|| Error::Dynamic("missing variable scope".into()))?
                    .insert_retained(
                        variable.name.clone(),
                        retained.value,
                        retained.retained_owned_bytes,
                    );
                Ok(())
            }
            Instruction::Message { terminate, body } => {
                self.meter.charge(BudgetKind::Messages, 1)?;
                let fragment = self.capture_fragment(
                    body,
                    node,
                    ApplyFrame::new(position, size, depth),
                    current_precedence,
                    None,
                )?;
                let mut content = self.consume_temporary_fragment(fragment, serialize_fragment)?;
                if *terminate {
                    const PREFIX: &str = "xsl:message terminated transformation: ";
                    self.meter
                        .check_additional(BudgetKind::OwnedBytes, PREFIX.len())?;
                    content.insert_str(0, PREFIX);
                    return Err(Error::Dynamic(content));
                }
                reserve_retained_vec_slot(&mut self.messages, &mut self.meter)?;
                self.messages.push(Message {
                    content,
                    terminate: false,
                });
                Ok(())
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
                self.meter.charge(BudgetKind::OwnedBytes, uri.len())?;
                let definition_owned_bytes = self.stylesheet.output.owned_bytes();
                self.meter
                    .charge(BudgetKind::OwnedBytes, definition_owned_bytes)?;
                let mut definition = self.stylesheet.output.clone();
                let output = (|| {
                    for (name, value) in properties {
                        let value = self.evaluate_avt(value, node, position, size)?;
                        apply_secondary_output_property(
                            &mut definition,
                            name,
                            value,
                            &mut self.meter,
                        )?;
                    }
                    let fragment = self.capture_fragment(
                        body,
                        node,
                        ApplyFrame::new(position, size, depth + 1),
                        current_precedence,
                        None,
                    )?;
                    let serialized = self
                        .consume_temporary_fragment(fragment, |fragment, meter| {
                            serialize(fragment, &definition, meter)
                        })?;
                    reserve_retained_vec_slot(&mut self.secondary_outputs, &mut self.meter)?;
                    self.secondary_outputs
                        .push(SecondaryOutput { uri, serialized });
                    Ok(())
                })();
                self.meter.release_owned_bytes(definition.owned_bytes());
                output
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
            Instruction::FunctionResult {
                select,
                content,
                base_uri,
            } => {
                self.ensure_function_result_is_pending()?;
                let value = if let Some(select) = select {
                    xpath_to_public(self.evaluate(select, node, position, size)?)
                } else {
                    Value::ResultTreeFragment(Arc::new(self.capture_fragment(
                        content,
                        node,
                        ApplyFrame::new(position, size, depth + 1),
                        current_precedence,
                        base_uri.as_deref(),
                    )?))
                };
                self.ensure_function_result_is_pending()?;
                *self
                    .function_results
                    .last_mut()
                    .expect("function result frame was checked") = Some(value);
                Ok(())
            }
        }
    }

    fn ensure_function_result_is_pending(&self) -> Result<()> {
        let Some(result) = self.function_results.last() else {
            return Err(Error::Dynamic(
                "func:result executed outside an EXSLT function".into(),
            ));
        };
        if result.is_some() {
            return Err(Error::Dynamic(
                "EXSLT function produced more than one result".into(),
            ));
        }
        Ok(())
    }

    fn evaluate(
        &mut self,
        expression: &crate::compiler::Expression,
        node: &SourceNode,
        position: usize,
        size: usize,
    ) -> Result<XPathValue> {
        self.meter.charge(BudgetKind::XPathEvaluations, 1)?;
        self.ensure_expression_globals(expression)?;
        let uses_key = xpath_calls_key(&expression.source);
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
        let (variables, reserved_owned_bytes) = self.variables()?;
        let custom_calls = CustomCallSession::default();
        loop {
            if uses_key {
                self.ensure_key_indexes_for_all_documents(
                    &expression.source,
                    &expression.namespaces,
                )?;
            }
            let document_count = self.evaluator.source.logical_roots().len();
            let value = self.evaluator.evaluate(
                expression,
                node,
                position,
                size,
                &variables,
                &mut self.meter,
                Some(&custom_calls),
            );
            if uses_key && self.evaluator.source.logical_roots().len() != document_count {
                // document() can import a logical document while evaluating the expression.
                // XSLT 1.0 section 12.2 defines key() relative to the dynamic context document,
                // so retry only after the new root has received the same key declarations.
                // https://www.w3.org/TR/1999/REC-xslt-19991116#key
                continue;
            }
            let call = self.evaluator.take_custom_function_call(
                &custom_calls,
                &variables,
                &mut self.meter,
            )?;
            let Some(call) = call else {
                self.meter
                    .release_owned_bytes(custom_calls.retained_bytes());
                self.meter.release_owned_bytes(reserved_owned_bytes);
                return value;
            };
            let function = self
                .stylesheet
                .functions
                .iter()
                .filter(|function| function.name == call.name)
                .max_by_key(|function| (function.precedence, function.order))
                .cloned()
                .ok_or_else(|| Error::Dynamic(format!("unknown function {}", call.name.local)))?;
            let result = self.call_exslt_function(
                &function,
                call.arguments,
                &call.node,
                call.position,
                call.size,
            )?;
            self.evaluator
                .complete_custom_function_call(&custom_calls, result, &mut self.meter)?;
            // Resuming replays the expression from its root. Account for every replay rather than
            // letting user-defined function count bypass the XPath evaluation budget.
            self.meter.charge(BudgetKind::XPathEvaluations, 1)?;
        }
    }

    fn evaluate_rtf_order(
        &mut self,
        expression: &Expression,
        node: &SourceNode,
    ) -> Result<Option<f64>> {
        if !expression
            .namespaces
            .iter()
            .any(|(prefix, namespace)| prefix == "exsl" && namespace == EXSLT_COMMON_NS)
        {
            return Ok(None);
        }
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
        let (mut targets, reserved_owned_bytes) = match target_expression.trim() {
            "name(current())" => collect_metered_strings(
                std::slice::from_ref(node),
                &self.evaluator,
                &mut self.meter,
                |evaluator, target, visit| evaluator.visit_qualified_name(target, visit),
            )?,
            path if path.starts_with("current()/") => {
                let Some((nodes, node_reservation)) = self.evaluator.relative_nodes(
                    path.trim_start_matches("current()/"),
                    node,
                    &expression.namespaces,
                    &mut self.meter,
                )?
                else {
                    return Ok(None);
                };
                let targets = collect_metered_strings(
                    &nodes,
                    &self.evaluator,
                    &mut self.meter,
                    |evaluator, target, visit| evaluator.visit_string_value(target, visit),
                );
                drop(nodes);
                self.meter.release_owned_bytes(node_reservation);
                targets?
            }
            _ => return Ok(None),
        };
        let result = (|| {
            targets.sort_unstable();
            targets.dedup();
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
                    // XPath 1.0 section 3.4 defines string-to-node-set equality as true when any
                    // selected node has the same string-value; reducing current()/path to its first
                    // node would change predicate semantics.
                    // https://www.w3.org/TR/1999/REC-xpath-19991116/#booleans
                    let matched = targets
                        .binary_search_by(|target| match prefix.as_deref() {
                            Some(prefix) => target.as_bytes().iter().copied().cmp(
                                prefix
                                    .bytes()
                                    .chain(std::iter::once(b':'))
                                    .chain(name.local.bytes()),
                            ),
                            None => target.as_str().cmp(name.local.as_str()),
                        })
                        .is_ok();
                    if matched {
                        // Preceding sibling sets are nested in document order, so the last
                        // matching element contributes the complete union.
                        union_count = preceding;
                    }
                    preceding += 1;
                }
            }
            Ok(Some(union_count as f64))
        })();
        self.meter.release_owned_bytes(reserved_owned_bytes);
        result
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
                let mut capacity = 0usize;
                let mut pending_space = false;
                self.evaluator.visit_string_value(node, |value| {
                    measure_normalized_xpath_space(value, &mut capacity, &mut pending_space);
                });
                self.meter
                    .check_additional(BudgetKind::OwnedBytes, capacity)?;
                let mut output = String::with_capacity(capacity);
                let mut pending_space = false;
                self.evaluator.visit_string_value(node, |value| {
                    append_normalized_xpath_space(value, &mut output, &mut pending_space);
                });
                return Ok(Some(XPathValue::String(output)));
            }
            "concat('<',name(.),'>')" => {
                return self
                    .formatted_qualified_name(node, "<", ">")
                    .map(XPathValue::String)
                    .map(Some);
            }
            "concat('</',name(.),'>')" => {
                return self
                    .formatted_qualified_name(node, "</", ">")
                    .map(XPathValue::String)
                    .map(Some);
            }
            _ => {}
        }
        if let Some((variable, increment)) = source
            .strip_prefix('$')
            .and_then(|value| value.split_once('+'))
            && let Some(variable) = lexical_variable_name(variable)
            && let Some(increment) = parse_xpath_number(increment)
        {
            let value = self.variable_value(variable, &expression.namespaces)?;
            let number = match value {
                Value::Boolean(value) => f64::from(u8::from(*value)),
                Value::Number(value) => *value,
                Value::String(value) | Value::StoredExpression(value) => xpath_number(value),
                Value::NodeSet(_) | Value::ResultTreeFragment(_) => {
                    xpath_number(&self.value_string(value, 0)?)
                }
            };
            return Ok(Some(XPathValue::Number(number + increment)));
        }
        if let Some(arguments) = source
            .strip_prefix("substring (")
            .and_then(|value| value.strip_suffix(')'))
            && let Some((literal, remainder)) = arguments.split_once(',')
            && let Some(literal) = xpath_string_literal(literal)
            && let Some((start, length)) = remainder.split_once(',')
            && start.trim() == "0"
            && let Some((variable, factor)) = length
                .trim()
                .strip_prefix('$')
                .and_then(|value| value.split_once('*'))
            && let Some(variable) = lexical_variable_name(variable)
            && let Some(factor) = parse_xpath_number(factor)
        {
            let length =
                xpath_number(&self.variable_string(variable, &expression.namespaces, 0)?) * factor;
            let take = length.round().max(1.0) as usize - 1;
            return Ok(Some(XPathValue::String(
                literal.chars().take(take).collect(),
            )));
        }
        if let Some(variable) = source
            .strip_prefix("string-length($")
            .and_then(|value| value.strip_suffix(") > 0"))
            && let Some(variable) = lexical_variable_name(variable)
        {
            let value = self.variable_string(variable, &expression.namespaces, 0)?;
            return Ok(Some(XPathValue::Boolean(!value.is_empty())));
        }
        if let Some(arguments) = source
            .strip_prefix("substring-before($")
            .and_then(|value| value.strip_suffix(')'))
            && let Some((variable, delimiter)) = arguments.split_once(',')
            && let Some(variable) = lexical_variable_name(variable)
            && let Some(delimiter) = xpath_string_literal(delimiter)
        {
            let value = self.variable_string(variable, &expression.namespaces, 0)?;
            let head = value.split_once(delimiter).map_or("", |(head, _)| head);
            let value_workspace = if matches!(&value, Cow::Owned(_)) {
                value.len()
            } else {
                0
            };
            self.meter.check_additional(
                BudgetKind::OwnedBytes,
                value_workspace.saturating_add(head.len()),
            )?;
            return Ok(Some(XPathValue::String(head.to_owned())));
        }
        if let Some(arguments) = source
            .strip_prefix("substring($")
            .and_then(|value| value.strip_suffix(')'))
            && let Some((variable, offset)) = arguments.split_once(',')
            && let Some(variable) = lexical_variable_name(variable)
            && let Some(offset) = offset.trim().strip_prefix("string-length($")
            && let Some((length_variable, increment)) = offset.split_once(")+")
            && let Some(length_variable) = lexical_variable_name(length_variable)
            && let Ok(increment) = increment.trim().parse::<usize>()
        {
            let value = self.variable_string(variable, &expression.namespaces, 0)?;
            let value_workspace = if matches!(&value, Cow::Owned(_)) {
                value.len()
            } else {
                0
            };
            let length = self
                .variable_string(length_variable, &expression.namespaces, value_workspace)?
                .chars()
                .count();
            let start = length.saturating_add(increment).saturating_sub(1);
            let start = value
                .char_indices()
                .nth(start)
                .map_or(value.len(), |(offset, _)| offset);
            let result = &value[start..];
            self.meter.check_additional(
                BudgetKind::OwnedBytes,
                value_workspace.saturating_add(result.len()),
            )?;
            return Ok(Some(XPathValue::String(result.to_owned())));
        }
        if let Some(variable) = source
            .strip_prefix("boolean($")
            .and_then(|value| value.strip_suffix(')'))
            && let Some(variable) = lexical_variable_name(variable)
        {
            let value = self.variable_value(variable, &expression.namespaces)?;
            return Ok(Some(XPathValue::Boolean(value.boolean())));
        }
        Ok(None)
    }

    fn formatted_qualified_name(
        &self,
        node: &SourceNode,
        opening: &str,
        closing: &str,
    ) -> Result<String> {
        let mut name_bytes = 0usize;
        self.evaluator.visit_qualified_name(node, |segment| {
            debug_assert!(name_bytes.checked_add(segment.len()).is_some());
            name_bytes += segment.len();
        });
        debug_assert!(
            opening
                .len()
                .checked_add(name_bytes)
                .and_then(|bytes| bytes.checked_add(closing.len()))
                .is_some()
        );
        let output_bytes = opening.len() + name_bytes + closing.len();
        self.meter
            .check_additional(BudgetKind::OwnedBytes, output_bytes)?;

        let mut output = String::with_capacity(output_bytes);
        output.push_str(opening);
        self.evaluator
            .visit_qualified_name(node, |segment| output.push_str(segment));
        output.push_str(closing);
        Ok(output)
    }

    fn variable_value(&self, lexical: &str, namespaces: &[(String, String)]) -> Result<&Value> {
        let name = expanded_variable_name(lexical, namespaces)?;
        self.scopes
            .iter()
            .rev()
            .find_map(|scope| scope.get(&name))
            .ok_or_else(|| Error::Dynamic(format!("undefined variable ${lexical}")))
    }

    fn variable_string<'value>(
        &'value self,
        lexical: &str,
        namespaces: &[(String, String)],
        concurrent_owned_bytes: usize,
    ) -> Result<Cow<'value, str>> {
        let value = self.variable_value(lexical, namespaces)?;
        self.value_string(value, concurrent_owned_bytes)
    }

    fn value_string<'value>(
        &'value self,
        value: &'value Value,
        concurrent_owned_bytes: usize,
    ) -> Result<Cow<'value, str>> {
        value_string(
            value,
            &self.evaluator.source,
            &self.meter,
            concurrent_owned_bytes,
        )
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
        self.scopes.push(VariableScope::default());
        let temporary_result = self.empty_metered_result(None)?;
        let temporary_root = temporary_result.root();
        let previous_result = std::mem::replace(&mut self.result, temporary_result);
        let previous_stack = std::mem::replace(&mut self.output_stack, vec![temporary_root]);
        self.function_results.push(None);
        if binds_defaults {
            self.binding_function_defaults.push(function.name.clone());
        }
        let parameters = (|| {
            self.meter.recursion(depth)?;
            for (index, parameter) in function.params.iter().enumerate() {
                let retained = if let Some(value) = arguments.get(index) {
                    let retained_owned_bytes = binding_owned_bytes(&parameter.name, value);
                    self.meter
                        .check_additional(BudgetKind::OwnedBytes, retained_owned_bytes)?;
                    let value = value.clone();
                    self.meter
                        .charge(BudgetKind::OwnedBytes, retained_owned_bytes)?;
                    RetainedValue {
                        value,
                        retained_owned_bytes,
                    }
                } else {
                    self.evaluate_variable(parameter, node, position, size, depth + 1, None)?
                };
                self.scopes
                    .last_mut()
                    .expect("function parameter scope exists")
                    .insert_retained(
                        parameter.name.clone(),
                        retained.value,
                        retained.retained_owned_bytes,
                    );
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
        let generated_result_nodes = self.result.node_count() > 1;
        let temporary_result = std::mem::replace(&mut self.result, previous_result);
        self.meter
            .release_owned_bytes(metered_document_owned_bytes(&temporary_result));
        self.output_stack = previous_stack;
        self.pop_scope();
        self.scopes.extend(caller_scopes);
        self.function_depth = self.function_depth.saturating_sub(1);
        execution?;
        // EXSLT func:function, "Function Results", makes generated result nodes an error and
        // defines an absent func:result as an empty string:
        // https://exslt.github.io/func/elements/function/index.html
        if generated_result_nodes {
            return Err(Error::Dynamic(format!(
                "EXSLT function {} generated result nodes outside func:result",
                function.name.local
            )));
        }
        Ok(value.unwrap_or_else(|| Value::String(String::new())))
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
        current_rule_precedence: Option<usize>,
    ) -> Result<RetainedValue> {
        let value = if let Some(select) = &variable.select {
            xpath_to_public(self.evaluate(select, node, position, size)?)
        } else if variable.content.is_empty() {
            Value::String(String::new())
        } else {
            // XSLT 1.0 section 5.6 keeps the current template rule while evaluating sequence
            // constructors in that rule; callers such as xsl:for-each explicitly pass None:
            // https://www.w3.org/TR/1999/REC-xslt-19991116#apply-imports
            Value::ResultTreeFragment(Arc::new(self.capture_fragment(
                &variable.content,
                node,
                ApplyFrame::new(position, size, depth),
                current_rule_precedence,
                variable.base_uri.as_deref(),
            )?))
        };
        // Selected XPath values become owned by a persistent lexical scope. Result-tree
        // fragments are already metered while their document is built, so only their binding
        // name is additional retained storage here.
        let additional_owned_bytes = expanded_name_owned_bytes(&variable.name).saturating_add(
            variable
                .select
                .as_ref()
                .map_or(0, |_| value_owned_bytes(&value)),
        );
        self.meter
            .charge(BudgetKind::OwnedBytes, additional_owned_bytes)?;
        let retained_owned_bytes = expanded_name_owned_bytes(&variable.name).saturating_add(
            if variable.select.is_some() {
                value_owned_bytes(&value)
            } else if let Value::ResultTreeFragment(document) = &value {
                metered_document_owned_bytes(document)
            } else {
                0
            },
        );
        Ok(RetainedValue {
            retained_owned_bytes,
            value,
        })
    }
    fn evaluate_with_params(
        &mut self,
        parameters: &[crate::compiler::WithParam],
        node: &SourceNode,
        position: usize,
        size: usize,
        depth: usize,
        current_rule_precedence: Option<usize>,
    ) -> Result<EvaluatedParameters> {
        let mut evaluated = EvaluatedParameters::default();
        for parameter in parameters {
            let retained = self.evaluate_variable(
                &parameter.variable,
                node,
                position,
                size,
                depth,
                current_rule_precedence,
            )?;
            evaluated.retained_owned_bytes = evaluated
                .retained_owned_bytes
                .saturating_add(retained.retained_owned_bytes);
            evaluated
                .values
                .insert(parameter.variable.name.clone(), retained.value);
        }
        Ok(evaluated)
    }
    fn call_named(
        &mut self,
        name: &ExpandedName,
        params: Arc<EvaluatedParameters>,
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
                    let value = self.evaluate(expression, node, position, size)?;
                    append_avt_expression_value(
                        &mut output,
                        value,
                        &self.evaluator,
                        &mut self.meter,
                    )?;
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
        let workspace_bytes = sort_workspace_bytes(nodes.len(), sorts.len());
        self.meter.charge(BudgetKind::OwnedBytes, workspace_bytes)?;
        let mut retained_bytes = 0usize;
        let result = (|| {
            let mut specs = Vec::with_capacity(sorts.len());
            for sort in sorts {
                let case_order = sort
                    .case_order
                    .as_ref()
                    .map(|value| {
                        self.evaluate_avt(value, context_node, context_position, context_size)
                    })
                    .transpose()?;
                let case_order = match case_order {
                    Some(value) if matches!(value.as_str(), "upper-first" | "lower-first") => {
                        Some(value)
                    }
                    Some(_) if sort.forward_compatible => None,
                    Some(value) => {
                        return Err(Error::Dynamic(format!(
                            "xsl:sort case-order must evaluate to `upper-first` or `lower-first`, got `{value}`"
                        )));
                    }
                    None => None,
                };
                let lang = sort
                    .lang
                    .as_ref()
                    .map(|value| {
                        self.evaluate_avt(value, context_node, context_position, context_size)
                    })
                    .transpose()?;
                let mut data_type = self.evaluate_avt(
                    &sort.data_type,
                    context_node,
                    context_position,
                    context_size,
                )?;
                if !matches!(data_type.as_str(), "text" | "number") {
                    if sort.forward_compatible {
                        data_type.clear();
                        data_type.push_str("text");
                    } else {
                        return Err(Error::Dynamic(format!(
                            "xsl:sort data-type must evaluate to `text` or `number`, got `{data_type}`"
                        )));
                    }
                }
                let collator = match lang.as_deref() {
                    Some(lang) => match locale_collator(lang, case_order.as_deref()) {
                        Ok(collator) => Some(collator),
                        Err(_) if sort.forward_compatible => None,
                        Err(error) => return Err(error),
                    },
                    None => None,
                };
                let mut order =
                    self.evaluate_avt(&sort.order, context_node, context_position, context_size)?;
                if !matches!(order.as_str(), "ascending" | "descending") {
                    if sort.forward_compatible {
                        order.clear();
                        order.push_str("ascending");
                    } else {
                        return Err(Error::Dynamic(format!(
                            "xsl:sort order must evaluate to `ascending` or `descending`, got `{order}`"
                        )));
                    }
                }
                let spec = EvaluatedSort {
                    data_type,
                    order,
                    case_order,
                    collator,
                };
                let bytes = spec.owned_bytes();
                self.meter.charge(BudgetKind::OwnedBytes, bytes)?;
                retained_bytes = retained_bytes
                    .checked_add(bytes)
                    .expect("charged sort storage fits usize");
                specs.push(spec);
            }

            let mut keyed = Vec::with_capacity(nodes.len());
            for (index, node) in nodes.iter().enumerate() {
                let mut keys = Vec::with_capacity(sorts.len());
                for (sort, spec) in sorts.iter().zip(&specs) {
                    let value = self.evaluate(&sort.select, node, index + 1, nodes.len())?;
                    let key = if spec.data_type == "number" {
                        SortKey::Number(value.number(&self.evaluator))
                    } else {
                        SortKey::text(value.into_string(&self.evaluator), &mut self.meter)?
                    };
                    retained_bytes = retained_bytes
                        .checked_add(key.owned_bytes())
                        .expect("charged sort storage fits usize");
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
                    let mut ordering =
                        l.compare(r, spec.case_order.as_deref(), spec.collator.as_ref());
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
        })();
        self.meter
            .release_owned_bytes(workspace_bytes.saturating_add(retained_bytes));
        result
    }
    fn capture_text(
        &mut self,
        body: &[Instruction],
        node: &SourceNode,
        position: usize,
        size: usize,
        depth: usize,
        precedence: Option<usize>,
    ) -> Result<CapturedText> {
        let previous = self.enter_temporary_result_tree(None)?;
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
            Ok(CapturedText {
                value: captured,
                retained_owned_bytes: bytes,
            })
        });
        let temporary = self.restore_result_tree(previous);
        self.meter
            .release_owned_bytes(metered_document_owned_bytes(&temporary));
        captured
    }

    fn consume_temporary_fragment<T>(
        &mut self,
        fragment: Document,
        consume: impl FnOnce(&Document, &mut Meter) -> Result<T>,
    ) -> Result<T> {
        let fragment_owned_bytes = metered_document_owned_bytes(&fragment);
        let result = consume(&fragment, &mut self.meter);
        self.meter.release_owned_bytes(fragment_owned_bytes);
        result
    }
    fn capture_fragment(
        &mut self,
        body: &[Instruction],
        node: &SourceNode,
        frame: ApplyFrame,
        precedence: Option<usize>,
        base_uri: Option<&str>,
    ) -> Result<Document> {
        let previous = self.enter_temporary_result_tree(base_uri)?;
        let result = self.execute_scoped_sequence(
            body,
            node,
            frame.position,
            frame.size,
            frame.depth + 1,
            precedence,
        );
        let mut captured = self.restore_result_tree(previous);
        let finalized = result.and_then(|()| captured.finalize_xml_ids(&mut self.meter));
        match finalized {
            Ok(()) => Ok(captured),
            Err(error) => {
                self.meter
                    .release_owned_bytes(metered_document_owned_bytes(&captured));
                Err(error)
            }
        }
    }

    fn empty_metered_result(&mut self, base_uri: Option<&str>) -> Result<Document> {
        let document = Document::empty(base_uri.map(str::to_owned));
        self.meter.charge(
            BudgetKind::OwnedBytes,
            metered_document_owned_bytes(&document),
        )?;
        Ok(document)
    }

    fn enter_temporary_result_tree(&mut self, base_uri: Option<&str>) -> Result<ResultTreeState> {
        let temporary = self.empty_metered_result(base_uri)?;
        let temporary_root = temporary.root();
        Ok(ResultTreeState {
            document: std::mem::replace(&mut self.result, temporary),
            output_stack: std::mem::replace(&mut self.output_stack, vec![temporary_root]),
            attribute_insert_position: self.attribute_insert_position.take(),
            attribute_protected_names: self.attribute_protected_names.take(),
        })
    }

    fn restore_result_tree(&mut self, previous: ResultTreeState) -> Document {
        let captured = std::mem::replace(&mut self.result, previous.document);
        self.output_stack = previous.output_stack;
        self.attribute_insert_position = previous.attribute_insert_position;
        self.attribute_protected_names = previous.attribute_protected_names;
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
        let clone_bytes = node_kind_owned_bytes(&source.kind)
            .saturating_add(source.base_uri.as_deref().map_or(0, str::len));
        self.result
            .reserve_metered_push_containers(parent, &mut self.meter)?;
        self.meter.check_additional(
            BudgetKind::ResultNodes,
            1usize.saturating_add(node_kind_embedded_nodes(&source.kind)),
        )?;
        self.meter
            .check_additional(BudgetKind::OwnedBytes, clone_bytes)?;
        let target =
            self.push_node_with_base(parent, source.kind.clone(), source.base_uri.clone())?;
        for child in &source.children {
            self.copy_document(document, *child, target, depth + 1)?;
        }
        Ok(())
    }
    fn copy_source(&mut self, node: &SourceNode, parent: NodeId, depth: usize) -> Result<()> {
        self.meter.recursion(depth)?;
        match node {
            SourceNode::Node(id) => {
                let source = self
                    .evaluator
                    .source
                    .node(*id)
                    .ok_or_else(|| Error::Dynamic("stale source node".into()))?;
                let child_count = source.children.len();
                if matches!(source.kind, NodeKind::Root) {
                    for index in 0..child_count {
                        let child = self
                            .evaluator
                            .source
                            .node(*id)
                            .and_then(|source| source.children.get(index).copied())
                            .ok_or_else(|| Error::Dynamic("stale source child".into()))?;
                        self.copy_source(&SourceNode::Node(child), parent, depth + 1)?
                    }
                    return Ok(());
                }
                let clone_bytes = node_kind_owned_bytes(&source.kind)
                    .saturating_add(source.base_uri.as_deref().map_or(0, str::len));
                self.result
                    .reserve_metered_push_containers(parent, &mut self.meter)?;
                self.meter.check_additional(
                    BudgetKind::ResultNodes,
                    1usize.saturating_add(node_kind_embedded_nodes(&source.kind)),
                )?;
                self.meter
                    .check_additional(BudgetKind::OwnedBytes, clone_bytes)?;
                let kind = source.kind.clone();
                let base_uri = source.base_uri.clone();
                let target = self.push_node_with_base(parent, kind, base_uri)?;
                for index in 0..child_count {
                    let child = self
                        .evaluator
                        .source
                        .node(*id)
                        .and_then(|source| source.children.get(index).copied())
                        .ok_or_else(|| Error::Dynamic("stale source child".into()))?;
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
            Some(NodeKind::Element { attributes, .. }) => attributes.get(index),
            _ => None,
        };
        if let Some(attribute) = attribute {
            self.meter
                .check_additional(BudgetKind::OwnedBytes, attribute_owned_bytes(attribute))?;
            self.add_attribute(attribute.clone())?;
        }
        Ok(())
    }
    fn copy_source_namespace(&mut self, owner: NodeId, index: usize) -> Result<()> {
        let namespace = match self.evaluator.source.node(owner).map(|node| &node.kind) {
            Some(NodeKind::Element { namespaces, .. }) => namespaces.get(index),
            _ => None,
        };
        if let Some(namespace) = namespace {
            self.meter
                .check_additional(BudgetKind::OwnedBytes, namespace_owned_bytes(namespace))?;
            self.add_namespace(namespace.clone())?;
        }
        Ok(())
    }
    fn apply_attribute_set(
        &mut self,
        name: &ExpandedName,
        node: &SourceNode,
        frame: ApplyFrame,
        current_precedence: Option<usize>,
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
        if sets.is_empty() {
            active.pop();
            return Err(Error::Static(format!(
                "undefined attribute-set {}",
                name.local
            )));
        }
        sets.sort_by_key(|set| (std::cmp::Reverse(set.precedence), set.order));
        let previous_protected = self.attribute_protected_names.take();
        let result = (|| {
            let mut cursor = 0;
            while cursor < sets.len() {
                let precedence = sets[cursor].precedence;
                if cursor == 0 {
                    self.attribute_protected_names = previous_protected.clone();
                } else {
                    self.attribute_protected_names = Some(self.current_attribute_names()?);
                }
                while cursor < sets.len() && sets[cursor].precedence == precedence {
                    let set = sets[cursor];
                    let set_start = self.current_attribute_count()?;
                    for used in &set.uses {
                        self.meter.recursion(frame.depth + 1)?;
                        self.apply_attribute_set(
                            used,
                            node,
                            ApplyFrame::new(frame.position, frame.size, frame.depth + 1),
                            current_precedence,
                            active,
                        )?
                    }
                    let previous_position = self.attribute_insert_position.replace(set_start);
                    let execution = self.execute_sequence(
                        &set.attributes,
                        node,
                        frame.position,
                        frame.size,
                        frame.depth + 1,
                        current_precedence,
                    );
                    self.attribute_insert_position = previous_position;
                    execution?;
                    cursor += 1;
                }
            }
            Ok(())
        })();
        self.attribute_protected_names = previous_protected;
        result?;
        active.pop();
        Ok(())
    }
    fn parent(&self) -> NodeId {
        self.output_stack
            .last()
            .copied()
            .unwrap_or_else(|| self.result.root())
    }
    fn push_node(&mut self, parent: NodeId, kind: NodeKind) -> Result<NodeId> {
        let base_uri = self
            .result
            .node(parent)
            .and_then(|node| node.base_uri.clone());
        self.push_node_with_base(parent, kind, base_uri)
    }

    fn push_node_with_base(
        &mut self,
        parent: NodeId,
        kind: NodeKind,
        base_uri: Option<String>,
    ) -> Result<NodeId> {
        self.result
            .reserve_metered_push_containers(parent, &mut self.meter)?;
        self.meter
            .charge(BudgetKind::OwnedBytes, node_kind_owned_bytes(&kind))?;
        self.meter.charge(
            BudgetKind::OwnedBytes,
            base_uri.as_deref().map_or(0, str::len),
        )?;
        self.meter.charge(
            BudgetKind::ResultNodes,
            1usize.saturating_add(node_kind_embedded_nodes(&kind)),
        )?;
        Ok(self.result.push(parent, kind, base_uri))
    }
    fn append_text(&mut self, value: &str, disable: bool) -> Result<()> {
        self.append_text_value(Cow::Borrowed(value), disable)
    }
    fn append_owned_text(&mut self, value: String, disable: bool) -> Result<()> {
        self.append_text_value(Cow::Owned(value), disable)
    }
    fn append_text_value(&mut self, value: Cow<'_, str>, disable: bool) -> Result<()> {
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
            let temporary_bytes = matches!(&value, Cow::Owned(_)).then_some(value.len());
            if let Some(bytes) = temporary_bytes {
                self.meter.charge(BudgetKind::OwnedBytes, bytes)?;
            }
            if let Err(error) = self.meter.charge(BudgetKind::OwnedBytes, value.len()) {
                if let Some(bytes) = temporary_bytes {
                    self.meter.release_owned_bytes(bytes);
                }
                return Err(error);
            }
            if let Some(NodeKind::Text { value: current, .. }) =
                self.result.node_mut(previous).map(|node| &mut node.kind)
            {
                current.push_str(&value);
            }
            if let Some(bytes) = temporary_bytes {
                self.meter.release_owned_bytes(bytes);
            }
            return Ok(());
        }
        self.meter
            .check_additional(BudgetKind::OwnedBytes, value.len())?;
        self.push_node(
            parent,
            NodeKind::Text {
                value: value.into_owned(),
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
        let protected = self
            .attribute_protected_names
            .as_ref()
            .is_some_and(|protected| protected.contains(&attribute.name));
        if protected
            && self.result.node(parent).is_some_and(|node| {
                matches!(
                    &node.kind,
                    NodeKind::Element { attributes, .. }
                        if attributes.iter().any(|existing| existing.name == attribute.name)
                )
            })
        {
            return Ok(());
        }
        const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
        let effective_base = if attribute.name.namespace.as_deref() == Some(XML_NS)
            && attribute.name.local == "base"
        {
            let inherited = self
                .result
                .node(parent)
                .and_then(|node| node.parent)
                .and_then(|parent| self.result.node(parent))
                .and_then(|node| node.base_uri.as_deref());
            Some(crate::resolver::resolve_uri_reference(
                inherited,
                &attribute.value,
            )?)
        } else {
            None
        };
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
        if generated_namespace.is_some() {
            self.meter.charge(BudgetKind::ResultNodes, 1)?;
            reserve_retained_vec_slot(namespaces, &mut self.meter)?;
        }
        let existing_index = attributes
            .iter()
            .position(|existing| existing.name == attribute.name);
        if existing_index.is_none() {
            self.meter.charge(BudgetKind::ResultNodes, 1)?;
            reserve_retained_vec_slot(attributes, &mut self.meter)?;
        }
        let owned_bytes = attribute_owned_bytes(&attribute).saturating_add(
            generated_namespace
                .as_ref()
                .map_or(0, namespace_owned_bytes),
        );
        self.meter.charge(BudgetKind::OwnedBytes, owned_bytes)?;
        if let Some(base_uri) = &effective_base {
            self.meter.charge(BudgetKind::OwnedBytes, base_uri.len())?;
        }
        namespaces.extend(generated_namespace);
        let mut replaced_owned_bytes = 0usize;
        if let Some(existing) = existing_index.map(|index| &mut attributes[index]) {
            let replaced = std::mem::replace(existing, attribute);
            replaced_owned_bytes = attribute_owned_bytes(&replaced);
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
        if let Some(base_uri) = effective_base
            && let Some(replaced) = node.base_uri.replace(base_uri)
        {
            replaced_owned_bytes = replaced_owned_bytes.saturating_add(replaced.len());
        }
        self.meter.release_owned_bytes(replaced_owned_bytes);
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

    fn current_attribute_names(&self) -> Result<HashSet<ExpandedName>> {
        let node = self
            .result
            .node(self.parent())
            .ok_or_else(|| Error::Dynamic("attribute has no result parent".into()))?;
        let NodeKind::Element { attributes, .. } = &node.kind else {
            return Err(Error::Dynamic(
                "attribute requires an element result".into(),
            ));
        };
        Ok(attributes
            .iter()
            .map(|attribute| attribute.name.clone())
            .collect())
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
        let replaced_owned_bytes = {
            let node = self
                .result
                .node_mut(self.parent())
                .ok_or_else(|| Error::Dynamic("namespace has no result parent".into()))?;
            let NodeKind::Element { namespaces, .. } = &mut node.kind else {
                return Err(Error::Dynamic(
                    "namespace requires an element result".into(),
                ));
            };
            let existing_index = namespaces
                .iter()
                .position(|existing| existing.prefix == namespace.prefix);
            if existing_index.is_none() {
                self.meter.charge(BudgetKind::ResultNodes, 1)?;
                reserve_retained_vec_slot(namespaces, &mut self.meter)?;
            }
            if let Some(existing) = existing_index.map(|index| &mut namespaces[index]) {
                let replaced_owned_bytes = namespace_owned_bytes(existing);
                *existing = namespace;
                replaced_owned_bytes
            } else {
                namespaces.push(namespace);
                0
            }
        };
        self.meter.release_owned_bytes(replaced_owned_bytes);
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
            .find(|alias| alias.stylesheet_namespace.as_deref() == name.namespace.as_deref())
        else {
            return (name.clone(), prefix.map(str::to_owned));
        };
        (
            ExpandedName::new(alias.result_namespace.clone(), name.local.clone()),
            alias.output_prefix.clone(),
        )
    }

    fn alias_attribute_name(
        &self,
        name: &ExpandedName,
        prefix: Option<&str>,
    ) -> (ExpandedName, Option<String>) {
        // Namespaces in XML 1.0 section 6.2 leaves unprefixed attributes in no namespace, so a
        // default-namespace alias applies to literal elements but not their unprefixed attributes.
        // https://www.w3.org/TR/REC-xml-names/#defaulting
        if prefix.is_none() {
            return (ExpandedName::new(None::<String>, name.local.clone()), None);
        }
        self.alias_name(name, prefix)
    }

    fn alias_literal_name_and_namespaces(
        &self,
        name: &ExpandedName,
        prefix: Option<&str>,
        namespaces: &[Namespace],
    ) -> (ExpandedName, Option<String>, Vec<Namespace>) {
        let (name, mut prefix) = self.alias_name(name, prefix);
        let mut result_namespaces = Vec::<Namespace>::with_capacity(namespaces.len());
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
        fixup_element_namespace(&name, &mut prefix, &mut result_namespaces);
        (name, prefix, result_namespaces)
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
        let (variables, reserved_owned_bytes) = self.variables()?;
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
        let result = (|| match instruction.level.as_str() {
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
                let mut count = 0usize;
                let logical_root = self
                    .evaluator
                    .source
                    .logical_root_for(node)
                    .ok_or_else(|| Error::Dynamic("numbering node has no logical root".into()))?;
                let node_bytes = std::mem::size_of::<NodeId>();
                let mut traversal_bytes = 0usize;
                let result = (|| {
                    self.meter.charge(BudgetKind::OwnedBytes, node_bytes)?;
                    traversal_bytes = node_bytes;
                    let mut pending = Vec::with_capacity(1);
                    pending.push(logical_root);
                    while let Some(id) = pending.pop() {
                        if let Some(source) = self.evaluator.source.node(id) {
                            let required = pending.len().saturating_add(source.children.len());
                            if required > pending.capacity() {
                                let growth = required - pending.capacity();
                                let growth_bytes = growth.saturating_mul(node_bytes);
                                self.meter.charge(BudgetKind::OwnedBytes, growth_bytes)?;
                                traversal_bytes = traversal_bytes.saturating_add(growth_bytes);
                                pending.reserve_exact(source.children.len());
                            }
                            pending.extend(source.children.iter().rev().copied());
                        }
                        let candidate = SourceNode::Node(id);
                        if from(self, &candidate)? {
                            count = 0;
                        } else if matches(self, &candidate)? {
                            count += 1;
                        }
                        if &candidate == node {
                            return Ok((count > 0).then_some(count as f64).into_iter().collect());
                        }
                        let is_current_owner = matches!(
                            node,
                            SourceNode::Attribute { owner, .. } | SourceNode::Namespace { owner, .. }
                                if *owner == id
                        );
                        if is_current_owner {
                            // XSLT 1.0 section 7.7 excludes preceding attribute and namespace nodes;
                            // only the current non-ordinary node joins preceding/ancestor-or-self.
                            // https://www.w3.org/TR/1999/REC-xslt-19991116#number
                            if from(self, node)? {
                                count = 0;
                            } else if matches(self, node)? {
                                count += 1;
                            }
                            return Ok((count > 0).then_some(count as f64).into_iter().collect());
                        }
                    }
                    Err(Error::Dynamic(
                        "numbering node is outside its logical document".into(),
                    ))
                })();
                self.meter.release_owned_bytes(traversal_bytes);
                result
            }
            level => Err(Error::Static(format!(
                "unsupported xsl:number level {level}"
            ))),
        })();
        self.meter.release_owned_bytes(reserved_owned_bytes);
        result
    }

    fn sibling_number(
        &mut self,
        node: &SourceNode,
        matches: &mut impl FnMut(&mut Self, &SourceNode) -> Result<bool>,
    ) -> Result<usize> {
        #[derive(Clone, Copy)]
        enum SiblingAxis {
            Children { parent: NodeId, count: usize },
            Attributes { owner: NodeId, count: usize },
            Namespaces { owner: NodeId, count: usize },
        }

        let axis = match node {
            SourceNode::Node(id) => {
                let Some(parent) = self.evaluator.source.node(*id).and_then(|node| node.parent)
                else {
                    return Ok(1);
                };
                let count = self
                    .evaluator
                    .source
                    .node(parent)
                    .map_or(0, |node| node.children.len());
                SiblingAxis::Children { parent, count }
            }
            SourceNode::Attribute { owner, .. } => {
                let count = self
                    .evaluator
                    .source
                    .node(*owner)
                    .map_or(0, |node| match &node.kind {
                        NodeKind::Element { attributes, .. } => attributes.len(),
                        _ => 0,
                    });
                SiblingAxis::Attributes {
                    owner: *owner,
                    count,
                }
            }
            SourceNode::Namespace { owner, .. } => {
                let count = self
                    .evaluator
                    .source
                    .node(*owner)
                    .map_or(0, |node| match &node.kind {
                        NodeKind::Element { namespaces, .. } => namespaces.len(),
                        _ => 0,
                    });
                SiblingAxis::Namespaces {
                    owner: *owner,
                    count,
                }
            }
        };
        let mut count = 0;
        let sibling_count = match axis {
            SiblingAxis::Children { count, .. }
            | SiblingAxis::Attributes { count, .. }
            | SiblingAxis::Namespaces { count, .. } => count,
        };
        for index in 0..sibling_count {
            let sibling = match axis {
                SiblingAxis::Children { parent, .. } => {
                    let Some(child) = self
                        .evaluator
                        .source
                        .node(parent)
                        .and_then(|node| node.children.get(index))
                    else {
                        break;
                    };
                    SourceNode::Node(*child)
                }
                SiblingAxis::Attributes { owner, .. } => SourceNode::Attribute { owner, index },
                SiblingAxis::Namespaces { owner, .. } => SourceNode::Namespace { owner, index },
            };
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

fn append_avt_expression_value(
    output: &mut String,
    value: XPathValue,
    evaluator: &Evaluator,
    meter: &mut Meter,
) -> Result<()> {
    let (value, temporary_bytes) = value.into_temporary_string(evaluator, meter)?;
    let check = meter.check_additional(
        BudgetKind::OwnedBytes,
        output.len().saturating_add(value.len()),
    );
    if let Err(error) = check {
        meter.release_owned_bytes(temporary_bytes);
        return Err(error);
    }
    output.push_str(&value);
    meter.release_owned_bytes(temporary_bytes);
    Ok(())
}

fn remap_parameter_value(value: &Value, remap: &HashMap<NodeId, NodeId>) -> Value {
    let Value::NodeSet(nodes) = value else {
        return value.clone();
    };
    Value::NodeSet(
        nodes
            .iter()
            .filter_map(|node| remap_parameter_node(node, remap))
            .collect(),
    )
}

fn validate_parameter_value(value: &Value, source_identity: u64) -> Result<()> {
    let Value::NodeSet(nodes) = value else {
        return Ok(());
    };
    if nodes
        .iter()
        .any(|node| node_reference_owner(node).document_identity() != source_identity)
    {
        return Err(Error::Dynamic(
            "node-set parameter contains a reference from a foreign document".into(),
        ));
    }
    Ok(())
}

fn node_reference_owner(node: &NodeReference) -> NodeId {
    match node {
        NodeReference::Node(id) => *id,
        NodeReference::Attribute { owner, .. } | NodeReference::Namespace { owner, .. } => *owner,
    }
}

fn parameter_value_owned_bytes(value: &Value, remap: Option<&HashMap<NodeId, NodeId>>) -> usize {
    match (value, remap) {
        (Value::NodeSet(nodes), Some(remap)) => nodes
            .iter()
            .filter(|node| remap_parameter_node(node, remap).is_some())
            .count()
            .saturating_mul(std::mem::size_of::<NodeReference>()),
        _ => value_owned_bytes(value),
    }
}

fn remap_parameter_node(
    node: &NodeReference,
    remap: &HashMap<NodeId, NodeId>,
) -> Option<NodeReference> {
    match node {
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
    }
}

fn append_normalized_xpath_space(value: &str, output: &mut String, pending_space: &mut bool) {
    for character in value.chars() {
        if matches!(character, ' ' | '\t' | '\r' | '\n') {
            *pending_space = !output.is_empty();
        } else {
            if *pending_space {
                output.push(' ');
                *pending_space = false;
            }
            output.push(character);
        }
    }
}

fn measure_normalized_xpath_space(value: &str, bytes: &mut usize, pending_space: &mut bool) {
    for character in value.chars() {
        if matches!(character, ' ' | '\t' | '\r' | '\n') {
            *pending_space = *bytes != 0;
        } else {
            if *pending_space {
                *bytes = bytes.saturating_add(1);
                *pending_space = false;
            }
            *bytes = bytes.saturating_add(character.len_utf8());
        }
    }
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
        let Some(lexical) = xpath_string_literal(argument) else {
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

fn fixup_element_namespace(
    name: &ExpandedName,
    prefix: &mut Option<String>,
    namespaces: &mut Vec<Namespace>,
) {
    const XML_NAMESPACE: &str = "http://www.w3.org/XML/1998/namespace";

    let Some(uri) = name.namespace.as_deref() else {
        *prefix = None;
        return;
    };
    if uri == XML_NAMESPACE {
        *prefix = Some("xml".into());
        return;
    }
    if matches!(prefix.as_deref(), Some("xml" | "xmlns")) {
        *prefix = Some(unused_namespace_prefix(namespaces));
    }
    let binding = namespaces
        .iter()
        .position(|namespace| namespace.prefix == *prefix);
    match binding {
        Some(index) if namespaces[index].uri == uri => {}
        Some(index) => {
            let replacement = unused_namespace_prefix(namespaces);
            namespaces[index].prefix = Some(replacement);
            namespaces.push(Namespace {
                prefix: prefix.clone(),
                uri: uri.to_owned(),
            });
        }
        None => namespaces.push(Namespace {
            prefix: prefix.clone(),
            uri: uri.to_owned(),
        }),
    }
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
impl EvaluatedSort {
    fn owned_bytes(&self) -> usize {
        self.data_type
            .len()
            .saturating_add(self.order.len())
            .saturating_add(self.case_order.as_ref().map_or(0, String::len))
    }
}
impl SortKey {
    fn text(value: String, meter: &mut Meter) -> Result<Self> {
        let key_bytes = default_collation_key_bytes(&value);
        meter.charge(
            BudgetKind::OwnedBytes,
            value.len().saturating_add(key_bytes),
        )?;
        let default_key = default_collation_key(&value, key_bytes);
        Ok(Self::Text { value, default_key })
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
                let secondary = left
                    .chars()
                    .flat_map(char::to_lowercase)
                    .cmp(right.chars().flat_map(char::to_lowercase));
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

fn default_collation_key_bytes(value: &str) -> usize {
    value
        .chars()
        .flat_map(char::to_lowercase)
        .try_fold(0usize, |bytes, character| {
            bytes.checked_add(if character == '_' {
                char::MAX.len_utf8()
            } else {
                character.len_utf8()
            })
        })
        .unwrap_or(usize::MAX)
}

fn default_collation_key(value: &str, key_bytes: usize) -> String {
    let mut key = String::with_capacity(key_bytes);
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
    value: String,
    meter: &mut Meter,
) -> Result<()> {
    let replaced_owned_bytes = secondary_output_property_owned_bytes(definition, name)?;
    let retains_value = secondary_output_property_retains_value(name)?;
    let value_owned_bytes = value.len();
    meter.charge(BudgetKind::OwnedBytes, value_owned_bytes)?;
    let result = set_secondary_output_property(definition, name, value);
    match result {
        Ok(()) => {
            meter.release_owned_bytes(replaced_owned_bytes);
            if !retains_value {
                meter.release_owned_bytes(value_owned_bytes);
            }
            Ok(())
        }
        Err(error) => {
            meter.release_owned_bytes(value_owned_bytes);
            Err(error)
        }
    }
}

fn set_secondary_output_property(
    definition: &mut crate::OutputDefinition,
    name: &str,
    value: String,
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
            let method = match value.as_str() {
                "xml" => crate::OutputMethod::Xml,
                "html" => crate::OutputMethod::Html,
                "text" => crate::OutputMethod::Text,
                _ => {
                    return Err(Error::Dynamic(format!(
                        "unsupported secondary-output method {value:?}"
                    )));
                }
            };
            definition.method_explicit = true;
            definition.method = method;
        }
        "version" => definition.version = Some(value),
        "encoding" => {
            definition.encoding_explicit = true;
            definition.encoding = value;
        }
        "omit-xml-declaration" => definition.omit_xml_declaration = yes_no(&value)?,
        "standalone" => definition.standalone = Some(yes_no(&value)?),
        "doctype-public" => definition.doctype_public = Some(value),
        "doctype-system" => definition.doctype_system = Some(value),
        "indent" => {
            definition.indent_explicit = true;
            definition.indent = yes_no(&value)?;
        }
        "media-type" => definition.media_type = Some(value),
        _ => {
            return Err(Error::Dynamic(format!(
                "unsupported secondary-output property {name:?}"
            )));
        }
    }
    Ok(())
}

fn secondary_output_property_owned_bytes(
    definition: &crate::OutputDefinition,
    name: &str,
) -> Result<usize> {
    match name {
        "method" | "omit-xml-declaration" | "standalone" | "indent" => Ok(0),
        "version" => Ok(definition.version.as_ref().map_or(0, String::len)),
        "encoding" => Ok(definition.encoding.len()),
        "doctype-public" => Ok(definition.doctype_public.as_ref().map_or(0, String::len)),
        "doctype-system" => Ok(definition.doctype_system.as_ref().map_or(0, String::len)),
        "media-type" => Ok(definition.media_type.as_ref().map_or(0, String::len)),
        _ => Err(Error::Dynamic(format!(
            "unsupported secondary-output property {name:?}"
        ))),
    }
}

fn secondary_output_property_retains_value(name: &str) -> Result<bool> {
    match name {
        "version" | "encoding" | "doctype-public" | "doctype-system" | "media-type" => Ok(true),
        "method" | "omit-xml-declaration" | "standalone" | "indent" => Ok(false),
        _ => Err(Error::Dynamic(format!(
            "unsupported secondary-output property {name:?}"
        ))),
    }
}

fn reserve_retained_vec_slot<T>(items: &mut Vec<T>, meter: &mut Meter) -> Result<()> {
    if std::mem::size_of::<T>() == 0 || items.len() < items.capacity() {
        return Ok(());
    }
    let old_capacity = items.capacity();
    let requested_slots = old_capacity.max(4);
    let requested_bytes = requested_slots.saturating_mul(std::mem::size_of::<T>());
    meter.charge(BudgetKind::OwnedBytes, requested_bytes)?;
    if let Err(error) = items.try_reserve_exact(requested_slots) {
        meter.release_owned_bytes(requested_bytes);
        return Err(Error::Dynamic(format!(
            "failed to reserve retained result storage: {error}"
        )));
    }
    let actual_bytes = items
        .capacity()
        .saturating_sub(old_capacity)
        .saturating_mul(std::mem::size_of::<T>());
    if actual_bytes < requested_bytes {
        meter.release_owned_bytes(requested_bytes - actual_bytes);
    } else if actual_bytes > requested_bytes {
        meter.charge(BudgetKind::OwnedBytes, actual_bytes - requested_bytes)?;
    }
    Ok(())
}

fn collect_metered_strings(
    nodes: &[SourceNode],
    evaluator: &Evaluator,
    meter: &mut Meter,
    mut visit: impl FnMut(&Evaluator, &SourceNode, &mut dyn FnMut(&str)),
) -> Result<(Vec<String>, usize)> {
    let mut string_bytes = 0usize;
    for node in nodes {
        visit(evaluator, node, &mut |segment| {
            string_bytes = string_bytes.saturating_add(segment.len());
        });
    }
    let vector_bytes = nodes.len().saturating_mul(std::mem::size_of::<String>());
    let expected_bytes = vector_bytes.saturating_add(string_bytes);
    meter.charge(BudgetKind::OwnedBytes, expected_bytes)?;
    let mut reserved_owned_bytes = expected_bytes;
    let result = (|| {
        let mut values = Vec::new();
        values
            .try_reserve_exact(nodes.len())
            .map_err(|error| Error::Dynamic(format!("failed to reserve XPath strings: {error}")))?;
        reconcile_temporary_capacity(
            meter,
            &mut reserved_owned_bytes,
            vector_bytes,
            values
                .capacity()
                .saturating_mul(std::mem::size_of::<String>()),
        )?;
        for node in nodes {
            let mut bytes = 0usize;
            visit(evaluator, node, &mut |segment| {
                bytes = bytes.saturating_add(segment.len());
            });
            let mut value = String::new();
            value.try_reserve_exact(bytes).map_err(|error| {
                Error::Dynamic(format!("failed to reserve XPath string value: {error}"))
            })?;
            reconcile_temporary_capacity(
                meter,
                &mut reserved_owned_bytes,
                bytes,
                value.capacity(),
            )?;
            visit(evaluator, node, &mut |segment| value.push_str(segment));
            values.push(value);
        }
        Ok((values, reserved_owned_bytes))
    })();
    if result.is_err() {
        meter.release_owned_bytes(reserved_owned_bytes);
    }
    result
}

fn reconcile_temporary_capacity(
    meter: &mut Meter,
    reserved_owned_bytes: &mut usize,
    expected: usize,
    actual: usize,
) -> Result<()> {
    if actual < expected {
        let released = expected - actual;
        meter.release_owned_bytes(released);
        *reserved_owned_bytes -= released;
    } else if actual > expected {
        let additional = actual - expected;
        meter.charge(BudgetKind::OwnedBytes, additional)?;
        *reserved_owned_bytes = reserved_owned_bytes.saturating_add(additional);
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

fn lexical_variable_name(value: &str) -> Option<&str> {
    let value = value.trim_matches(is_xml_whitespace);
    is_lexical_variable_name(value).then_some(value)
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
    _letter_value: Option<&str>,
    separator: Option<char>,
    size: Option<usize>,
    meter: &Meter,
) -> Result<String> {
    if values.is_empty() {
        return Ok(String::new());
    }
    let (runs, formats, separators) = number_format_run_counts(format);
    let token_workspace = runs
        .saturating_mul(std::mem::size_of::<(bool, &str)>())
        .saturating_add(formats.saturating_mul(std::mem::size_of::<&str>()))
        .saturating_add(separators.saturating_mul(std::mem::size_of::<&str>()));
    meter.check_additional(BudgetKind::OwnedBytes, token_workspace)?;
    let tokens = tokenize_number_format(format);
    if tokens.formats.is_empty() {
        let mut output = String::new();
        append_metered(&mut output, tokens.prefix, meter)?;
        for (index, value) in values.iter().enumerate() {
            if index > 0 {
                append_metered(&mut output, ".", meter)?;
            }
            format_number_into(&mut output, *value, "1", separator, size, meter)?;
        }
        return Ok(output);
    }
    let mut output = String::new();
    append_metered(&mut output, tokens.prefix, meter)?;
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            let separator = tokens
                .separators
                .get(index - 1)
                .or_else(|| tokens.separators.last())
                .copied()
                .unwrap_or(".");
            append_metered(&mut output, separator, meter)?;
        }
        let token = tokens
            .formats
            .get(index)
            .or_else(|| tokens.formats.last())
            .copied()
            .unwrap_or("1");
        format_number_into(&mut output, *value, token, separator, size, meter)?;
    }
    append_metered(&mut output, tokens.suffix, meter)?;
    Ok(output)
}

fn append_metered(output: &mut String, value: &str, meter: &Meter) -> Result<()> {
    meter.check_additional(
        BudgetKind::OwnedBytes,
        output.len().saturating_add(value.len()),
    )?;
    output.push_str(value);
    Ok(())
}

struct NumberFormatTokens<'a> {
    prefix: &'a str,
    formats: Vec<&'a str>,
    separators: Vec<&'a str>,
    suffix: &'a str,
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
                    .saturating_add(prefix.as_ref().map_or(0, String::len))
                    .saturating_add(
                        attributes
                            .capacity()
                            .saturating_mul(std::mem::size_of::<Attribute>()),
                    )
                    .saturating_add(
                        namespaces
                            .capacity()
                            .saturating_mul(std::mem::size_of::<Namespace>()),
                    ),
                |total, attribute| total.saturating_add(attribute_owned_bytes(attribute)),
            )
            .saturating_add(namespaces.iter().fold(0usize, |total, namespace| {
                total.saturating_add(namespace_owned_bytes(namespace))
            })),
    }
}

fn node_kind_embedded_nodes(kind: &NodeKind) -> usize {
    match kind {
        NodeKind::Element {
            attributes,
            namespaces,
            ..
        } => attributes.len().saturating_add(namespaces.len()),
        _ => 0,
    }
}

fn value_string<'a>(
    value: &'a Value,
    source: &'a Document,
    meter: &Meter,
    concurrent_owned_bytes: usize,
) -> Result<Cow<'a, str>> {
    match value {
        Value::NodeSet(nodes) => nodes
            .iter()
            .filter_map(|node| source.document_order_key(node).map(|key| (key, node)))
            .min_by_key(|(key, _)| *key)
            .map_or_else(
                || Ok(Cow::Borrowed("")),
                |(_, node)| node_reference_string(node, source, meter, concurrent_owned_bytes),
            ),
        Value::Boolean(true) => Ok(Cow::Borrowed("true")),
        Value::Boolean(false) => Ok(Cow::Borrowed("false")),
        Value::Number(value) => {
            let value = crate::value::format_xpath_number(*value);
            meter.check_additional(
                BudgetKind::OwnedBytes,
                concurrent_owned_bytes.saturating_add(value.len()),
            )?;
            Ok(Cow::Owned(value))
        }
        Value::String(value) | Value::StoredExpression(value) => Ok(Cow::Borrowed(value)),
        Value::ResultTreeFragment(document) => {
            metered_document_string(document, document.root(), meter, concurrent_owned_bytes)
        }
    }
}

fn node_reference_string<'a>(
    node: &NodeReference,
    document: &'a Document,
    meter: &Meter,
    concurrent_owned_bytes: usize,
) -> Result<Cow<'a, str>> {
    match node {
        NodeReference::Node(id) => {
            metered_document_string(document, *id, meter, concurrent_owned_bytes)
        }
        NodeReference::Attribute { owner, index } => Ok(document
            .node(*owner)
            .and_then(|node| match &node.kind {
                NodeKind::Element { attributes, .. } => attributes.get(*index),
                _ => None,
            })
            .map_or(Cow::Borrowed(""), |attribute| {
                Cow::Borrowed(attribute.value.as_str())
            })),
        NodeReference::Namespace { owner, index } => Ok(document
            .node(*owner)
            .and_then(|node| match &node.kind {
                NodeKind::Element { namespaces, .. } => namespaces.get(*index),
                _ => None,
            })
            .map_or(Cow::Borrowed(""), |namespace| {
                Cow::Borrowed(namespace.uri.as_str())
            })),
    }
}

fn metered_document_string<'a>(
    document: &'a Document,
    id: NodeId,
    meter: &Meter,
    concurrent_owned_bytes: usize,
) -> Result<Cow<'a, str>> {
    let Some(node) = document.node(id) else {
        return Ok(Cow::Borrowed(""));
    };
    match &node.kind {
        NodeKind::Text { value, .. } | NodeKind::Comment(value) => Ok(Cow::Borrowed(value)),
        NodeKind::ProcessingInstruction { value, .. } => {
            Ok(Cow::Borrowed(value.as_deref().unwrap_or("")))
        }
        NodeKind::Root | NodeKind::Element { .. } => {
            let mut output_bytes = 0usize;
            document.visit_string_value(id, |value| {
                output_bytes = output_bytes.saturating_add(value.len());
            });
            meter.check_additional(
                BudgetKind::OwnedBytes,
                concurrent_owned_bytes.saturating_add(output_bytes),
            )?;
            let mut output = String::with_capacity(output_bytes);
            document.visit_string_value(id, |value| output.push_str(value));
            Ok(Cow::Owned(output))
        }
    }
}

fn clone_for_xsl_copy(kind: &NodeKind, meter: &Meter) -> Result<NodeKind> {
    let copied_bytes = match kind {
        NodeKind::Element {
            name,
            prefix,
            namespaces,
            ..
        } => expanded_name_owned_bytes(name)
            .saturating_add(prefix.as_ref().map_or(0, String::len))
            .saturating_add(namespaces.iter().fold(0usize, |total, namespace| {
                total.saturating_add(namespace_owned_bytes(namespace))
            })),
        kind => node_kind_owned_bytes(kind),
    };
    meter.check_additional(BudgetKind::OwnedBytes, copied_bytes)?;
    Ok(match kind {
        // xsl:copy copies an element's expanded name and namespace nodes, but attributes are
        // selected only by the sequence constructor. Never clone source attributes just to drop
        // them before constructing the result element.
        NodeKind::Element {
            name,
            prefix,
            namespaces,
            ..
        } => NodeKind::Element {
            name: name.clone(),
            prefix: prefix.clone(),
            attributes: Vec::new(),
            namespaces: namespaces.clone(),
        },
        kind => kind.clone(),
    })
}

fn value_owned_bytes(value: &Value) -> usize {
    match value {
        Value::NodeSet(nodes) => nodes
            .len()
            .saturating_mul(std::mem::size_of::<NodeReference>()),
        Value::Boolean(_) | Value::Number(_) => 0,
        Value::String(value) | Value::StoredExpression(value) => value.len(),
        Value::ResultTreeFragment(_) => std::mem::size_of::<Arc<Document>>(),
    }
}

fn metered_document_owned_bytes(document: &Document) -> usize {
    document.nodes().fold(
        document
            .retained_tree_container_bytes()
            .saturating_add(document.retained_identity_index_bytes()),
        |total, (_, node)| {
            total
                .saturating_add(node_kind_owned_bytes(&node.kind))
                .saturating_add(node.base_uri.as_ref().map_or(0, String::len))
        },
    )
}

fn binding_owned_bytes(name: &ExpandedName, value: &Value) -> usize {
    expanded_name_owned_bytes(name).saturating_add(value_owned_bytes(value))
}

fn visible_variable_snapshot_size(scopes: &[VariableScope]) -> (usize, usize) {
    let mut count = 0usize;
    let mut payload = 0usize;
    for (scope_index, scope) in scopes.iter().enumerate() {
        for (name, value) in scope.iter() {
            if scopes[scope_index + 1..]
                .iter()
                .any(|inner| inner.contains_key(name))
            {
                continue;
            }
            count = count.saturating_add(1);
            payload = payload
                .saturating_add(expanded_name_owned_bytes(name))
                .saturating_add(value_owned_bytes(value));
        }
    }
    // Account conservatively for hash-table control bytes and spare capacity in addition to
    // cloned key/value payloads. The reservation is transient and released after XPath returns.
    let table = count
        .saturating_mul(std::mem::size_of::<(ExpandedName, Value)>())
        .saturating_mul(2);
    (count, payload.saturating_add(table))
}

fn tokenize_number_format(format: &str) -> NumberFormatTokens<'_> {
    let (run_count, format_count, separator_count) = number_format_run_counts(format);
    let mut runs = Vec::<(bool, &str)>::with_capacity(run_count);
    let mut run_start = 0usize;
    let mut run_kind = None;
    for (index, character) in format.char_indices() {
        let alphanumeric = character.is_alphanumeric();
        if let Some(kind) = run_kind
            && kind != alphanumeric
        {
            runs.push((kind, &format[run_start..index]));
            run_start = index;
        }
        run_kind = Some(alphanumeric);
    }
    if let Some(kind) = run_kind {
        runs.push((kind, &format[run_start..]));
    }
    let prefix = runs
        .first()
        .filter(|(alphanumeric, _)| !*alphanumeric)
        .map(|(_, value)| *value)
        .unwrap_or_default();
    let suffix = runs
        .last()
        .filter(|(alphanumeric, _)| !*alphanumeric)
        .map(|(_, value)| *value)
        .unwrap_or_default();
    let mut formats = Vec::with_capacity(format_count);
    formats.extend(
        runs.iter()
            .filter(|(alphanumeric, _)| *alphanumeric)
            .map(|(_, value)| *value),
    );
    let mut separators = Vec::with_capacity(separator_count);
    separators.extend(
        runs.iter()
            .skip_while(|(alphanumeric, _)| !*alphanumeric)
            .skip(1)
            .take_while(|_| true)
            .filter(|(alphanumeric, _)| !*alphanumeric)
            .map(|(_, value)| *value)
            .take(format_count.saturating_sub(1)),
    );
    NumberFormatTokens {
        prefix,
        formats,
        separators,
        suffix,
    }
}

fn number_format_run_counts(format: &str) -> (usize, usize, usize) {
    let mut previous = None;
    let mut runs = 0usize;
    let mut formats = 0usize;
    let mut separators = 0usize;
    for character in format.chars() {
        let alphanumeric = character.is_alphanumeric();
        if previous != Some(alphanumeric) {
            runs = runs.saturating_add(1);
            if alphanumeric {
                formats = formats.saturating_add(1);
            } else {
                separators = separators.saturating_add(1);
            }
            previous = Some(alphanumeric);
        }
    }
    (runs, formats, separators)
}
fn format_number_into(
    output: &mut String,
    value: f64,
    format: &str,
    separator: Option<char>,
    size: Option<usize>,
    meter: &Meter,
) -> Result<()> {
    debug_assert!(value.is_nan() || value.round() > 0.0);
    if value.is_nan() {
        return append_metered(output, "NaN", meter);
    }
    let rounded = value.round();
    if rounded <= 0.0 {
        let width = format
            .chars()
            .filter(|character| unicode_decimal_value(*character).is_some())
            .count()
            .max(1);
        let zero = decimal_zero(format);
        return append_localized_decimal(output, "0", width, zero, None, None, meter);
    }
    match format {
        // XSLT 1.0 section 7.7.1 fixes the A/a sequences explicitly; letter-value only
        // disambiguates language-specific letter tokens.
        // https://www.w3.org/TR/1999/REC-xslt-19991116#convert
        "A" | "a" => {
            let decimal = crate::value::format_xpath_number(rounded);
            let value = alphabetic_decimal(&decimal, format == "A");
            append_metered(output, &value, meter)
        }
        "I" | "i" => {
            let value = if rounded <= 3999.0 {
                roman(rounded as usize, format == "I")
            } else {
                crate::value::format_xpath_number(rounded)
            };
            append_metered(output, &value, meter)
        }
        _ => {
            let width = format
                .chars()
                .filter(|character| unicode_decimal_value(*character).is_some())
                .count();
            let ascii = format!("{rounded:.0}");
            append_localized_decimal(
                output,
                &ascii,
                width,
                decimal_zero(format),
                separator,
                size,
                meter,
            )
        }
    }
}

fn decimal_zero(token: &str) -> char {
    token
        .chars()
        .filter_map(|character| {
            unicode_decimal_value(character).and_then(|digit| {
                u32::from(character)
                    .checked_sub(digit)
                    .and_then(char::from_u32)
            })
        })
        .next_back()
        .unwrap_or('0')
}

fn append_localized_decimal(
    output: &mut String,
    ascii: &str,
    width: usize,
    zero: char,
    separator: Option<char>,
    size: Option<usize>,
    meter: &Meter,
) -> Result<()> {
    let ascii_digits = ascii.chars().count();
    let digits = width.max(ascii_digits);
    let padding = digits.saturating_sub(ascii_digits);
    let grouping_size = size.filter(|size| *size > 0);
    let groups = grouping_size.map_or(0, |size| digits.saturating_sub(1) / size);
    let separator_bytes = separator.zip(grouping_size).map_or(0, |(separator, _)| {
        groups.saturating_mul(separator.len_utf8())
    });
    let digit_bytes = padding
        .saturating_mul(zero.len_utf8())
        .saturating_add(ascii.chars().fold(0usize, |total, character| {
            total.saturating_add(
                character
                    .to_digit(10)
                    .and_then(|digit| char::from_u32(u32::from(zero) + digit))
                    .unwrap_or(character)
                    .len_utf8(),
            )
        }));
    let additional = digit_bytes.saturating_add(separator_bytes);
    meter.check_additional(
        BudgetKind::OwnedBytes,
        output.len().saturating_add(additional),
    )?;
    output.reserve(additional);
    let mut characters = std::iter::repeat_n(zero, padding).chain(ascii.chars().map(|character| {
        character
            .to_digit(10)
            .and_then(|digit| char::from_u32(u32::from(zero) + digit))
            .unwrap_or(character)
    }));
    for index in 0..digits {
        if index > 0
            && let Some((separator, size)) = separator.zip(grouping_size)
            && (digits - index).is_multiple_of(size)
        {
            output.push(separator);
        }
        output.push(characters.next().expect("decimal width matches iterator"));
    }
    Ok(())
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

fn alphabetic_decimal(decimal: &str, upper: bool) -> String {
    let mut digits = decimal
        .bytes()
        .map(|digit| digit - b'0')
        .collect::<Vec<_>>();
    let mut start = 0usize;
    let mut reversed = Vec::with_capacity(decimal.len());
    while start < digits.len() {
        let mut borrow = 1u8;
        for digit in digits[start..].iter_mut().rev() {
            if borrow == 0 {
                break;
            }
            if *digit == 0 {
                *digit = 9;
            } else {
                *digit -= 1;
                borrow = 0;
            }
        }
        let mut remainder = 0u16;
        for digit in &mut digits[start..] {
            let dividend = remainder * 10 + u16::from(*digit);
            *digit = (dividend / 26) as u8;
            remainder = dividend % 26;
        }
        let base = if upper { b'A' } else { b'a' };
        reversed.push(base + remainder as u8);
        while start < digits.len() && digits[start] == 0 {
            start += 1;
        }
    }
    reversed.reverse();
    String::from_utf8(reversed).expect("alphabetic digits are ASCII")
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

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;
    use std::sync::Arc;

    use super::{SortKey, append_localized_decimal, apply_whitespace_rules, value_string};
    use crate::budget::Meter;
    use crate::{
        BudgetKind, CompileBudget, Compiler, Document, Error, ExecutionBudget, NoResolver, Value,
    };

    fn meter(owned_bytes: usize) -> Meter {
        Meter::new(
            ExecutionBudget {
                source_bytes: usize::MAX,
                external_documents: usize::MAX,
                recursion_depth: usize::MAX,
                xpath_evaluations: usize::MAX,
                template_applications: usize::MAX,
                sort_comparisons: usize::MAX,
                key_entries: usize::MAX,
                result_nodes: usize::MAX,
                serialized_bytes: usize::MAX,
                messages: usize::MAX,
                owned_bytes,
            },
            0,
        )
        .expect("empty source fits")
    }

    fn minimum_execution_owned_bytes(stylesheet: &crate::Stylesheet, source: &Document) -> usize {
        let mut rejected = 0usize;
        let mut accepted = 1usize << 20;
        while rejected + 1 < accepted {
            let candidate = rejected + (accepted - rejected) / 2;
            let budget = ExecutionBudget {
                source_bytes: usize::MAX,
                external_documents: usize::MAX,
                recursion_depth: usize::MAX,
                xpath_evaluations: usize::MAX,
                template_applications: usize::MAX,
                sort_comparisons: usize::MAX,
                key_entries: usize::MAX,
                result_nodes: usize::MAX,
                serialized_bytes: usize::MAX,
                messages: usize::MAX,
                owned_bytes: candidate,
            };
            match stylesheet.execute(
                source,
                &crate::Parameters::new(),
                Arc::new(NoResolver),
                crate::ExecutionOptions {
                    budget,
                    initial_mode: None,
                    initial_template: None,
                },
            ) {
                Ok(_) => accepted = candidate,
                Err(Error::Budget {
                    kind: BudgetKind::OwnedBytes,
                    ..
                }) => rejected = candidate,
                Err(error) => panic!("unexpected execution error: {error}"),
            }
        }
        accepted
    }

    #[test]
    fn avt_nodeset_conversion_reserves_both_live_copies() {
        // XPath node-set conversion and the growing AVT output coexist until the converted value
        // is appended, so the owned-byte gate must cover both allocations before conversion.
        let compile = |attribute: &str| {
            Compiler::new(
                Arc::new(NoResolver),
                CompileBudget::new(1 << 20, 4, 16, 1 << 20),
            )
            .compile(
                &format!(r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><out value="{attribute}"/></xsl:template></xsl:stylesheet>"#),
                None,
            )
            .expect("stylesheet compiles")
        };
        let payload = "x".repeat(4_096);
        let source =
            Document::parse(&format!("<root>{payload}</root>"), None).expect("source parses");
        let literal = compile("");
        let avt = compile("{/root}");

        let literal_minimum = minimum_execution_owned_bytes(&literal, &source);
        let avt_minimum = minimum_execution_owned_bytes(&avt, &source);
        assert!(avt_minimum >= literal_minimum.saturating_add(payload.len() * 2));
    }

    #[test]
    fn new_result_attributes_consume_result_node_budget() {
        // XPath 1.0 section 5.2 models attributes as nodes, so the result-node ceiling must count
        // a newly inserted expanded name while allowing replacement of that same node.
        // https://www.w3.org/TR/1999/REC-xpath-19991116/#attribute-nodes
        let stylesheet = Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(1 << 20, 4, 16, 1 << 20),
        )
        .compile(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><root><xsl:attribute name="a"/><xsl:attribute name="a"/><xsl:attribute name="b"/></root></xsl:template></xsl:stylesheet>"#,
            None,
        )
        .expect("stylesheet compiles");
        let source = Document::parse("<source/>", None).expect("source parses");
        let budget = ExecutionBudget {
            source_bytes: usize::MAX,
            external_documents: usize::MAX,
            recursion_depth: usize::MAX,
            xpath_evaluations: usize::MAX,
            template_applications: usize::MAX,
            sort_comparisons: usize::MAX,
            key_entries: usize::MAX,
            result_nodes: 2,
            serialized_bytes: usize::MAX,
            messages: usize::MAX,
            owned_bytes: usize::MAX,
        };
        let error = stylesheet
            .execute(
                &source,
                &crate::Parameters::new(),
                Arc::new(NoResolver),
                crate::ExecutionOptions {
                    budget,
                    initial_mode: None,
                    initial_template: None,
                },
            )
            .expect_err("one element plus two unique attributes exceed two result nodes");
        assert!(matches!(
            error,
            Error::Budget {
                kind: BudgetKind::ResultNodes,
                limit: 2,
                actual: 3,
            }
        ));
    }

    #[test]
    fn whitespace_stripping_reserves_and_releases_its_workspaces() {
        // The retained remap remains charged after in-place compaction, while the DFS and indexed
        // remap workspaces are released before transformation execution continues.
        let source_xml = format!("<root>{}</root>", "<item> </item>".repeat(2_048));
        let stylesheet = Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(1 << 20, 4, 16, 1 << 20),
        )
        .compile(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:strip-space elements="*"/></xsl:stylesheet>"#,
            None,
        )
        .expect("strip-space stylesheet compiles");
        let mut document = Document::parse(&source_xml, None).expect("wide source parses");
        let mut unbounded = meter(usize::MAX);
        let (remap, retained_bytes) =
            apply_whitespace_rules(&mut document, &stylesheet.whitespace, &mut unbounded)
                .expect("workspace fits")
                .expect("whitespace nodes are removed");
        assert_eq!(
            unbounded
                .usage(BudgetKind::OwnedBytes)
                .expect("usage is available")
                .0,
            retained_bytes
        );
        assert!(retained_bytes >= 2_048 * std::mem::size_of::<(crate::NodeId, crate::NodeId)>());
        drop(remap);
        unbounded.release_owned_bytes(retained_bytes);
        assert_eq!(
            unbounded
                .usage(BudgetKind::OwnedBytes)
                .expect("usage is available")
                .0,
            0
        );

        let mut constrained_document =
            Document::parse(&source_xml, None).expect("wide source parses again");
        let mut constrained = meter(retained_bytes - 1);
        assert!(matches!(
            apply_whitespace_rules(
                &mut constrained_document,
                &stylesheet.whitespace,
                &mut constrained,
            ),
            Err(Error::Budget {
                kind: BudgetKind::OwnedBytes,
                ..
            })
        ));
    }

    #[test]
    fn grouped_decimal_writer_checks_before_writing() {
        let mut rejected = String::new();
        let error = append_localized_decimal(
            &mut rejected,
            "1",
            4096,
            '0',
            Some(','),
            Some(1),
            &meter(4096),
        )
        .expect_err("wide grouped number exceeds its allocation budget");
        assert!(matches!(
            error,
            Error::Budget {
                kind: BudgetKind::OwnedBytes,
                ..
            }
        ));
        assert!(rejected.is_empty(), "budget rejection precedes all writes");
    }

    #[test]
    fn text_sort_key_reserves_its_exact_retained_payload() {
        // The underscore sentinel expands from one to four UTF-8 bytes, so the pre-allocation
        // accounting must use the produced collation key rather than the source byte length.
        let value = "A_".to_owned();
        assert!(matches!(
            SortKey::text(value.clone(), &mut meter(value.len() + 4)),
            Err(Error::Budget {
                kind: BudgetKind::OwnedBytes,
                ..
            })
        ));
        SortKey::text(value.clone(), &mut meter(value.len() + 5))
            .expect("the exact retained sort-key payload fits");
    }

    #[test]
    fn text_sort_key_resolves_internal_sentinel_collisions_without_allocation() {
        let left = SortKey::text("_".into(), &mut meter(64)).expect("left key fits");
        let right = SortKey::text(char::MAX.to_string(), &mut meter(64)).expect("right key fits");
        assert_eq!(
            left.compare(&right, Some("lower-first"), None),
            Ordering::Less
        );
    }

    #[test]
    fn value_string_preflights_owned_projection_but_borrows_existing_strings() {
        let payload = "x".repeat(4096);
        let fragment = Value::ResultTreeFragment(Arc::new(
            Document::parse(&format!("<fragment>{payload}</fragment>"), None)
                .expect("fragment parses"),
        ));
        let source = Document::parse("<source/>", None).expect("source parses");
        assert!(matches!(
            value_string(&fragment, &source, &meter(payload.len() - 1), 0),
            Err(Error::Budget {
                kind: BudgetKind::OwnedBytes,
                ..
            })
        ));

        let retained = Value::String(payload);
        let borrowed = value_string(&retained, &source, &meter(0), 0)
            .expect("an existing string needs no projection allocation");
        assert!(matches!(borrowed, std::borrow::Cow::Borrowed(_)));
    }
}
