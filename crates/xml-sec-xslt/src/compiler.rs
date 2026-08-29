use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::budget::ensure;
use crate::{
    BudgetKind, CompileBudget, Error, ExpandedName, Namespace, OutputDefinition, OutputMethod,
    ResolvePurpose, ResolvedResource, Resolver, ResourceIdentity, Result,
};

pub(crate) const XSLT_NS: &str = "http://www.w3.org/1999/XSL/Transform";

/// XSLT compiler with an explicit resource boundary and compile budget.
pub struct Compiler<R> {
    resolver: Arc<R>,
    budget: CompileBudget,
}

impl<R: Resolver> Compiler<R> {
    #[must_use]
    pub fn new(resolver: Arc<R>, budget: CompileBudget) -> Self {
        Self { resolver, budget }
    }

    /// Compile a complete stylesheet graph into immutable executable IR.
    pub fn compile(&self, xml: &str, base_uri: Option<&str>) -> Result<Stylesheet> {
        ensure(
            BudgetKind::StylesheetBytes,
            self.budget.stylesheet_bytes,
            xml.len(),
        )?;
        let mut state = CompileState::new(self.budget);
        self.compile_module(xml, base_uri, None, &mut state, 1)?;
        state.finish()
    }

    fn compile_module(
        &self,
        xml: &str,
        base_uri: Option<&str>,
        inherited_precedence: Option<usize>,
        state: &mut CompileState,
        depth: usize,
    ) -> Result<()> {
        ensure(
            BudgetKind::RecursionDepth,
            state.budget.recursion_depth,
            depth,
        )?;
        let document =
            roxmltree::Document::parse(xml).map_err(|error| Error::Xml(error.to_string()))?;
        let root = document.root_element();
        if root.tag_name().namespace() != Some(XSLT_NS)
            || !matches!(root.tag_name().name(), "stylesheet" | "transform")
        {
            let precedence = inherited_precedence.unwrap_or_else(|| state.next_precedence());
            return self.compile_literal_result_stylesheet(root, precedence, state, depth);
        }
        let forward = module_forward_compatible(root)?;
        let mut saw_non_import = false;
        self.compile_effective_imports(root, base_uri, state, depth, &mut saw_non_import)?;
        let local_precedence = inherited_precedence.unwrap_or_else(|| state.next_precedence());
        self.compile_effective_declarations(root, base_uri, local_precedence, forward, state, depth)
    }

    fn compile_effective_imports(
        &self,
        root: roxmltree::Node<'_, '_>,
        base_uri: Option<&str>,
        state: &mut CompileState,
        depth: usize,
        saw_non_import: &mut bool,
    ) -> Result<()> {
        for child in root.children().filter(roxmltree::Node::is_element) {
            let is_import = child.has_tag_name((XSLT_NS, "import"));
            if is_import && *saw_non_import {
                return Err(Error::Static(
                    "xsl:import must precede all other top-level declarations".into(),
                ));
            }
            if is_import {
                let resource =
                    self.resolve_module(child, base_uri, ResolvePurpose::Import, state)?;
                self.enter_resource(&resource, state, |state| {
                    let source = resource_source(&resource)?;
                    self.compile_module(
                        source,
                        Some(&resource.canonical_uri),
                        None,
                        state,
                        depth + 1,
                    )
                })?;
            } else if child.has_tag_name((XSLT_NS, "include")) {
                let resource =
                    self.resolve_module(child, base_uri, ResolvePurpose::Include, state)?;
                self.enter_resource(&resource, state, |state| {
                    let source = resource_source(&resource)?;
                    let document = roxmltree::Document::parse(source)
                        .map_err(|error| Error::Xml(error.to_string()))?;
                    let included_root = document.root_element();
                    require_stylesheet_module(included_root)?;
                    module_forward_compatible(included_root)?;
                    self.compile_effective_imports(
                        included_root,
                        Some(&resource.canonical_uri),
                        state,
                        depth + 1,
                        saw_non_import,
                    )
                })?;
            } else {
                *saw_non_import = true;
            }
        }
        Ok(())
    }

    fn compile_effective_declarations(
        &self,
        root: roxmltree::Node<'_, '_>,
        base_uri: Option<&str>,
        precedence: usize,
        forward: bool,
        state: &mut CompileState,
        depth: usize,
    ) -> Result<()> {
        for child in root.children().filter(roxmltree::Node::is_element) {
            if child.has_tag_name((XSLT_NS, "import")) {
                continue;
            }
            if child.has_tag_name((XSLT_NS, "include")) {
                let resource =
                    self.resolve_module(child, base_uri, ResolvePurpose::Include, state)?;
                self.enter_resource(&resource, state, |state| {
                    let source = resource_source(&resource)?;
                    let document = roxmltree::Document::parse(source)
                        .map_err(|error| Error::Xml(error.to_string()))?;
                    let included_root = document.root_element();
                    require_stylesheet_module(included_root)?;
                    let included_forward = module_forward_compatible(included_root)?;
                    self.compile_effective_declarations(
                        included_root,
                        Some(&resource.canonical_uri),
                        precedence,
                        included_forward,
                        state,
                        depth + 1,
                    )
                })?;
                continue;
            }
            self.compile_top_level(child, precedence, forward, state, depth)?;
        }
        Ok(())
    }

    fn resolve_module(
        &self,
        node: roxmltree::Node<'_, '_>,
        base_uri: Option<&str>,
        purpose: ResolvePurpose,
        state: &mut CompileState,
    ) -> Result<Arc<ResolvedResource>> {
        let href = required_attr(node, "href")?;
        let effective_base = effective_base_uri(node, base_uri)?;
        let request = ResolveRequest {
            href: href.to_owned(),
            base_uri: effective_base.clone(),
            purpose,
        };
        if let Some(resource) = state.resolved_requests.get(&request) {
            return Ok(Arc::clone(resource));
        }
        state.imported_modules = state.imported_modules.saturating_add(1);
        ensure(
            BudgetKind::ImportedModules,
            state.budget.imported_modules,
            state.imported_modules,
        )?;
        let resource = Arc::new(
            self.resolver
                .resolve(href, effective_base.as_deref(), purpose)?,
        );
        if let Some(previous) = state.resolved_identities.get(&resource.identity)
            && (previous.canonical_uri != resource.canonical_uri
                || previous.bytes != resource.bytes)
        {
            return Err(Error::StaleResource {
                identity: resource.identity.clone(),
            });
        }
        state.owned_bytes = state.owned_bytes.saturating_add(resource.bytes.len());
        ensure(
            BudgetKind::OwnedBytes,
            state.budget.owned_bytes,
            state.owned_bytes,
        )?;
        state
            .resolved_identities
            .entry(resource.identity.clone())
            .or_insert_with(|| Arc::clone(&resource));
        state
            .resolved_requests
            .insert(request, Arc::clone(&resource));
        if state.resource_set.insert(resource.identity.clone()) {
            state.resources.push(resource.identity.clone());
        }
        Ok(resource)
    }

    fn enter_resource<T>(
        &self,
        resource: &ResolvedResource,
        state: &mut CompileState,
        compile: impl FnOnce(&mut CompileState) -> Result<T>,
    ) -> Result<T> {
        if !state.active_resources.insert(resource.identity.clone()) {
            return Err(Error::Static(format!(
                "stylesheet include/import cycle at {}",
                resource.canonical_uri
            )));
        }
        let result = compile(state);
        state.active_resources.remove(&resource.identity);
        result
    }

    fn compile_literal_result_stylesheet(
        &self,
        root: roxmltree::Node<'_, '_>,
        precedence: usize,
        state: &mut CompileState,
        depth: usize,
    ) -> Result<()> {
        let version = root.attribute((XSLT_NS, "version")).ok_or_else(|| {
            Error::Static("literal result stylesheet requires xsl:version".into())
        })?;
        if version != "1.0" && version.parse::<f64>().map_or(true, |value| value < 1.0) {
            return Err(Error::Static(format!("unsupported XSLT version {version}")));
        }
        let order = state.next_order();
        state.templates.push(Template {
            name: None,
            pattern: Some(Pattern::new("/", root)?),
            mode: None,
            priority: 0.5,
            precedence,
            order,
            params: Vec::new(),
            body: vec![compile_literal_element(
                root,
                CompileContext::new(version != "1.0", depth, state.budget.recursion_depth)?,
            )?],
        });
        Ok(())
    }

    fn compile_top_level(
        &self,
        node: roxmltree::Node<'_, '_>,
        precedence: usize,
        forward: bool,
        state: &mut CompileState,
        depth: usize,
    ) -> Result<()> {
        if node.tag_name().namespace() != Some(XSLT_NS) {
            return Ok(());
        }
        match node.tag_name().name() {
            "template" => {
                let name = optional_qname_attr(node, "name")?;
                let patterns = node
                    .attribute("match")
                    .map(|value| Pattern::template_branches(value, node))
                    .transpose()?
                    .unwrap_or_default();
                if name.is_none() && patterns.is_empty() {
                    return Err(Error::Static("xsl:template requires name or match".into()));
                }
                let explicit_priority = node
                    .attribute("priority")
                    .map(str::parse::<f64>)
                    .transpose()
                    .map_err(|_| Error::Static("template priority must be a number".into()))?;
                let mode = optional_qname_attr(node, "mode")?;
                let mut children = node.children().peekable();
                let mut params = Vec::new();
                while let Some(child) = children.peek().copied() {
                    if child.has_tag_name((XSLT_NS, "param")) {
                        params.push(compile_variable(
                            child,
                            CompileContext::new(forward, depth, state.budget.recursion_depth)?,
                        )?);
                        children.next();
                    } else if (child.is_text()
                        && child.text().is_none_or(|text| text.trim().is_empty()))
                        || child.is_comment()
                        || child.is_pi()
                    {
                        children.next();
                    } else {
                        break;
                    }
                }
                let body = compile_sequence(
                    children,
                    CompileContext::new(forward, depth, state.budget.recursion_depth)?,
                )?;
                let order = state.next_order();
                if patterns.is_empty() {
                    state.templates.push(Template {
                        name,
                        pattern: None,
                        mode,
                        priority: explicit_priority.unwrap_or(0.0),
                        precedence,
                        order,
                        params,
                        body,
                    });
                } else {
                    for (index, pattern) in patterns.into_iter().enumerate() {
                        state.templates.push(Template {
                            name: (index == 0).then(|| name.clone()).flatten(),
                            priority: explicit_priority
                                .unwrap_or_else(|| pattern.default_priority()),
                            pattern: Some(pattern),
                            mode: mode.clone(),
                            precedence,
                            order,
                            params: params.clone(),
                            body: body.clone(),
                        });
                    }
                }
            }
            "variable" | "param" => {
                let variable = compile_variable(
                    node,
                    CompileContext::new(forward, depth, state.budget.recursion_depth)?,
                )?;
                let order = state.next_order();
                state.globals.push(GlobalVariable {
                    variable,
                    precedence,
                    order,
                    is_parameter: node.tag_name().name() == "param",
                });
            }
            "output" => merge_output(&mut state.output, node)?,
            "strip-space" | "preserve-space" => {
                let preserve = node.tag_name().name() == "preserve-space";
                for token in required_attr(node, "elements")?.split_ascii_whitespace() {
                    let order = state.next_order();
                    state.whitespace.push((
                        NameTest::parse(token, node)?,
                        preserve,
                        precedence,
                        order,
                    ));
                }
            }
            "key" => state.keys.push(KeyDeclaration {
                name: required_qname_attr(node, "name")?,
                match_pattern: Pattern::new(required_attr(node, "match")?, node)?,
                use_expression: Expression::new(required_attr(node, "use")?, node)?,
            }),
            "decimal-format" => state.decimal_formats.push(DecimalFormat::parse(node)?),
            "namespace-alias" => state.namespace_aliases.push(NamespaceAlias {
                stylesheet_namespace: alias_namespace(
                    node,
                    required_attr(node, "stylesheet-prefix")?,
                )?,
                result_namespace: alias_namespace(node, required_attr(node, "result-prefix")?)?,
            }),
            "attribute-set" => state.attribute_sets.push(AttributeSet::parse(
                node,
                CompileContext::new(forward, depth, state.budget.recursion_depth)?,
            )?),
            _unknown if forward => {}
            unknown => return Err(Error::Static(format!("unknown top-level xsl:{unknown}"))),
        }
        Ok(())
    }
}

/// Immutable compiled XSLT stylesheet.
#[derive(Debug, Clone)]
pub struct Stylesheet {
    pub(crate) templates: Arc<[Template]>,
    pub(crate) globals: Arc<[GlobalVariable]>,
    pub(crate) output: OutputDefinition,
    pub(crate) whitespace: Arc<[(NameTest, bool, usize, usize)]>,
    pub(crate) keys: Arc<[KeyDeclaration]>,
    pub(crate) decimal_formats: Arc<[DecimalFormat]>,
    pub(crate) namespace_aliases: Arc<[NamespaceAlias]>,
    pub(crate) attribute_sets: Arc<[AttributeSet]>,
    pub(crate) resource_identities: Arc<[ResourceIdentity]>,
}

impl Stylesheet {
    #[must_use]
    pub fn output_definition(&self) -> &OutputDefinition {
        &self.output
    }
    #[must_use]
    pub fn resource_identities(&self) -> &[ResourceIdentity] {
        &self.resource_identities
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Template {
    pub name: Option<ExpandedName>,
    pub pattern: Option<Pattern>,
    pub mode: Option<ExpandedName>,
    pub priority: f64,
    pub precedence: usize,
    pub order: usize,
    pub params: Vec<Variable>,
    pub body: Vec<Instruction>,
}
#[derive(Debug, Clone)]
pub(crate) struct GlobalVariable {
    pub variable: Variable,
    pub precedence: usize,
    pub order: usize,
    pub is_parameter: bool,
}
#[derive(Debug, Clone)]
pub(crate) struct Variable {
    pub name: ExpandedName,
    pub select: Option<Expression>,
    pub content: Vec<Instruction>,
}
#[derive(Debug, Clone)]
pub(crate) struct Expression {
    pub source: String,
    pub namespaces: Vec<(String, String)>,
}
#[derive(Debug, Clone)]
pub(crate) struct Pattern {
    pub source: String,
    pub namespaces: Vec<(String, String)>,
}
#[derive(Debug, Clone)]
pub(crate) struct Sort {
    pub select: Expression,
    pub data_type: AttributeValueTemplate,
    pub order: AttributeValueTemplate,
    pub case_order: Option<AttributeValueTemplate>,
    pub lang: Option<AttributeValueTemplate>,
}
#[derive(Debug, Clone)]
pub(crate) struct WithParam {
    pub variable: Variable,
}
#[derive(Debug, Clone)]
pub(crate) enum Instruction {
    Text(String, bool),
    LiteralElement {
        name: ExpandedName,
        prefix: Option<String>,
        attributes: Vec<LiteralAttribute>,
        namespaces: Vec<Namespace>,
        children: Vec<Instruction>,
        attribute_sets: Vec<ExpandedName>,
    },
    ApplyTemplates {
        select: Expression,
        mode: Option<ExpandedName>,
        sorts: Vec<Sort>,
        parameters: Vec<WithParam>,
    },
    ApplyImports,
    CallTemplate {
        name: ExpandedName,
        parameters: Vec<WithParam>,
    },
    ForEach {
        select: Expression,
        sorts: Vec<Sort>,
        body: Vec<Instruction>,
    },
    If {
        test: Expression,
        body: Vec<Instruction>,
    },
    Choose {
        branches: Vec<(Expression, Vec<Instruction>)>,
        otherwise: Vec<Instruction>,
    },
    ValueOf {
        select: Expression,
        disable_output_escaping: bool,
    },
    CopyOf(Expression),
    Copy {
        body: Vec<Instruction>,
        attribute_sets: Vec<ExpandedName>,
    },
    Element {
        name: AttributeValueTemplate,
        namespace: Option<AttributeValueTemplate>,
        namespaces: Vec<(String, String)>,
        body: Vec<Instruction>,
        attribute_sets: Vec<ExpandedName>,
    },
    Attribute {
        name: AttributeValueTemplate,
        namespace: Option<AttributeValueTemplate>,
        namespaces: Vec<(String, String)>,
        body: Vec<Instruction>,
    },
    Comment(Vec<Instruction>),
    Processing {
        name: AttributeValueTemplate,
        body: Vec<Instruction>,
    },
    Number(NumberInstruction),
    Variable(Variable),
    Message {
        terminate: bool,
        body: Vec<Instruction>,
    },
    Fallback(Vec<Instruction>),
}

#[derive(Debug, Clone)]
pub(crate) struct LiteralAttribute {
    pub name: ExpandedName,
    pub prefix: Option<String>,
    pub value: AttributeValueTemplate,
}
#[derive(Debug, Clone)]
pub(crate) struct AttributeValueTemplate(pub Vec<AvtPart>);
#[derive(Debug, Clone)]
pub(crate) enum AvtPart {
    Literal(String),
    Expression(Expression),
}
#[derive(Debug, Clone)]
pub(crate) struct NumberInstruction {
    pub value: Option<Expression>,
    pub count: Option<Pattern>,
    pub from: Option<Pattern>,
    pub level: String,
    pub format: String,
    pub lang: Option<String>,
    pub letter_value: Option<String>,
    pub grouping_separator: Option<AttributeValueTemplate>,
    pub grouping_size: Option<AttributeValueTemplate>,
}
#[derive(Debug, Clone)]
pub(crate) struct KeyDeclaration {
    pub name: ExpandedName,
    pub match_pattern: Pattern,
    pub use_expression: Expression,
}
#[derive(Debug, Clone)]
pub(crate) struct NamespaceAlias {
    pub stylesheet_namespace: Option<String>,
    pub result_namespace: Option<String>,
}
#[derive(Debug, Clone)]
pub(crate) struct AttributeSet {
    pub name: ExpandedName,
    pub uses: Vec<ExpandedName>,
    pub attributes: Vec<Instruction>,
}
#[derive(Debug, Clone)]
pub(crate) struct DecimalFormat {
    pub name: Option<ExpandedName>,
    pub decimal_separator: char,
    pub grouping_separator: char,
    pub infinity: String,
    pub minus_sign: char,
    pub nan: String,
    pub percent: char,
    pub per_mille: char,
    pub zero_digit: char,
    pub digit: char,
    pub pattern_separator: char,
}
#[derive(Debug, Clone)]
pub(crate) struct NameTest {
    pub namespace: NamespaceTest,
    pub local: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NamespaceTest {
    Any,
    None,
    Exact(String),
}

impl Expression {
    fn new(source: &str, node: roxmltree::Node<'_, '_>) -> Result<Self> {
        sxd_xpath_no_unsafe::Factory::new()
            .build(source)
            .map_err(|error| {
                Error::Static(format!("invalid XPath expression `{source}`: {error}"))
            })?;
        Ok(Self {
            source: source.to_owned(),
            namespaces: namespaces(node),
        })
    }
}
impl Pattern {
    fn new(source: &str, node: roxmltree::Node<'_, '_>) -> Result<Self> {
        if source.trim().is_empty() {
            return Err(Error::Static("empty template pattern".into()));
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
            sxd_xpath_no_unsafe::Factory::new()
                .build(&expression)
                .map_err(|error| {
                    Error::Static(format!("invalid match pattern `{branch}`: {error}"))
                })?;
        }
        Ok(Self {
            source: source.to_owned(),
            namespaces: namespaces(node),
        })
    }

    fn template_branches(source: &str, node: roxmltree::Node<'_, '_>) -> Result<Vec<Self>> {
        split_pattern_branches(source)
            .into_iter()
            .map(|branch| Self::new(branch.trim(), node))
            .collect()
    }
    fn default_priority(&self) -> f64 {
        let value = self.source.trim();
        if value == "*"
            || matches!(
                value,
                "node()" | "text()" | "comment()" | "processing-instruction()"
            )
        {
            -0.5
        } else if value.ends_with(":*") {
            -0.25
        } else if !value.contains(['/', '[', '|']) {
            0.0
        } else {
            0.5
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

impl NameTest {
    pub(crate) fn matches(&self, name: &ExpandedName) -> bool {
        self.local.as_ref().is_none_or(|local| local == &name.local)
            && match &self.namespace {
                NamespaceTest::Any => true,
                NamespaceTest::None => name.namespace.is_none(),
                NamespaceTest::Exact(namespace) => {
                    name.namespace.as_deref() == Some(namespace.as_str())
                }
            }
    }

    pub(crate) const fn priority(&self) -> i8 {
        match (&self.namespace, &self.local) {
            (NamespaceTest::Any, None) => -2,
            (NamespaceTest::Exact(_), None) => -1,
            (_, Some(_)) => 0,
            (NamespaceTest::None, None) => -2,
        }
    }
}

fn alias_namespace(node: roxmltree::Node<'_, '_>, prefix: &str) -> Result<Option<String>> {
    let prefix = (prefix != "#default").then_some(prefix);
    node.lookup_namespace_uri(prefix)
        .map(|uri| Some(uri.to_owned()))
        .ok_or_else(|| {
            Error::Static(format!(
                "namespace-alias prefix {} is not bound",
                prefix.unwrap_or("#default")
            ))
        })
}

struct CompileState {
    budget: CompileBudget,
    templates: Vec<Template>,
    globals: Vec<GlobalVariable>,
    output: OutputDefinition,
    whitespace: Vec<(NameTest, bool, usize, usize)>,
    keys: Vec<KeyDeclaration>,
    decimal_formats: Vec<DecimalFormat>,
    namespace_aliases: Vec<NamespaceAlias>,
    attribute_sets: Vec<AttributeSet>,
    resources: Vec<ResourceIdentity>,
    resource_set: HashSet<ResourceIdentity>,
    active_resources: HashSet<ResourceIdentity>,
    resolved_requests: HashMap<ResolveRequest, Arc<ResolvedResource>>,
    resolved_identities: HashMap<ResourceIdentity, Arc<ResolvedResource>>,
    imported_modules: usize,
    owned_bytes: usize,
    precedence: usize,
    order: usize,
}
impl CompileState {
    fn new(budget: CompileBudget) -> Self {
        Self {
            budget,
            templates: vec![],
            globals: vec![],
            output: OutputDefinition::default(),
            whitespace: vec![],
            keys: vec![],
            decimal_formats: vec![],
            namespace_aliases: vec![],
            attribute_sets: vec![],
            resources: vec![],
            resource_set: HashSet::new(),
            active_resources: HashSet::new(),
            resolved_requests: HashMap::new(),
            resolved_identities: HashMap::new(),
            imported_modules: 0,
            owned_bytes: 0,
            precedence: 0,
            order: 0,
        }
    }
    fn next_precedence(&mut self) -> usize {
        self.precedence += 1;
        self.precedence
    }
    fn next_order(&mut self) -> usize {
        self.order += 1;
        self.order
    }
    fn finish(mut self) -> Result<Stylesheet> {
        self.templates
            .sort_by_key(|template| (template.precedence, template.order));
        let mut named = HashSet::new();
        for template in self
            .templates
            .iter()
            .filter(|template| template.name.is_some())
        {
            if !named.insert((template.name.clone(), template.precedence)) {
                return Err(Error::Static(
                    "duplicate named template at equal import precedence".into(),
                ));
            }
        }
        let mut globals = HashSet::new();
        for global in &self.globals {
            if !globals.insert((&global.variable.name, global.precedence)) {
                return Err(Error::Static(format!(
                    "duplicate global variable {} at equal import precedence",
                    global.variable.name.local
                )));
            }
        }
        Ok(Stylesheet {
            templates: self.templates.into(),
            globals: self.globals.into(),
            output: self.output,
            whitespace: self.whitespace.into(),
            keys: self.keys.into(),
            decimal_formats: self.decimal_formats.into(),
            namespace_aliases: self.namespace_aliases.into(),
            attribute_sets: self.attribute_sets.into(),
            resource_identities: self.resources.into(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ResolveRequest {
    href: String,
    base_uri: Option<String>,
    purpose: ResolvePurpose,
}

#[derive(Debug, Clone, Copy)]
struct CompileContext {
    forward: bool,
    depth: usize,
    max_depth: usize,
}

impl CompileContext {
    fn new(forward: bool, depth: usize, max_depth: usize) -> Result<Self> {
        ensure(BudgetKind::RecursionDepth, max_depth, depth)?;
        Ok(Self {
            forward,
            depth,
            max_depth,
        })
    }

    fn descend(self) -> Result<Self> {
        Self::new(self.forward, self.depth.saturating_add(1), self.max_depth)
    }
}

fn resource_source(resource: &ResolvedResource) -> Result<&str> {
    std::str::from_utf8(&resource.bytes).map_err(|_| {
        Error::Xml(format!(
            "stylesheet {} is not UTF-8",
            resource.canonical_uri
        ))
    })
}

fn require_stylesheet_module(root: roxmltree::Node<'_, '_>) -> Result<()> {
    if root.tag_name().namespace() == Some(XSLT_NS)
        && matches!(root.tag_name().name(), "stylesheet" | "transform")
    {
        Ok(())
    } else {
        Err(Error::Static(
            "included stylesheet must have an xsl:stylesheet root".into(),
        ))
    }
}

fn module_forward_compatible(root: roxmltree::Node<'_, '_>) -> Result<bool> {
    match root.attribute("version") {
        Some("1.0") => Ok(false),
        Some(version) => version
            .parse::<f64>()
            .ok()
            .filter(|value| *value > 1.0)
            .map(|_| true)
            .ok_or_else(|| Error::Static(format!("unsupported XSLT version {version}"))),
        None => Err(Error::Static("xsl:stylesheet requires version".into())),
    }
}

fn effective_base_uri(
    node: roxmltree::Node<'_, '_>,
    module_base: Option<&str>,
) -> Result<Option<String>> {
    const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
    let mut base = module_base.map(str::to_owned);
    let mut ancestors = node
        .ancestors()
        .filter(roxmltree::Node::is_element)
        .collect::<Vec<_>>();
    ancestors.reverse();
    for ancestor in ancestors {
        if let Some(reference) = ancestor.attribute((XML_NS, "base")) {
            base = Some(resolve_uri_reference(base.as_deref(), reference)?);
        }
    }
    Ok(base)
}

fn resolve_uri_reference(base: Option<&str>, reference: &str) -> Result<String> {
    if let Ok(absolute) = url::Url::parse(reference) {
        return Ok(absolute.to_string());
    }
    if let Some(base) = base {
        if let Ok(base) = url::Url::parse(base)
            && let Ok(joined) = base.join(reference)
        {
            return Ok(joined.to_string());
        }
        if let Some((directory, _)) = base.rsplit_once('/') {
            return Ok(format!("{directory}/{reference}"));
        }
    }
    Ok(reference.to_owned())
}

fn compile_sequence<'a>(
    nodes: impl Iterator<Item = roxmltree::Node<'a, 'a>>,
    context: CompileContext,
) -> Result<Vec<Instruction>> {
    let mut out = Vec::new();
    for node in nodes {
        if node.is_text() {
            if let Some(text) = node.text() {
                // XSLT strips whitespace-only stylesheet nodes unless explicitly
                // preserved by xsl:text; retaining indentation changes result trees.
                if !text.trim().is_empty() {
                    out.push(Instruction::Text(text.to_owned(), false));
                }
            }
        } else if node.is_element() {
            out.push(compile_instruction(node, context.descend()?)?);
        }
    }
    Ok(out)
}
fn compile_instruction(
    node: roxmltree::Node<'_, '_>,
    context: CompileContext,
) -> Result<Instruction> {
    if node.tag_name().namespace() != Some(XSLT_NS) {
        if is_extension_element(node)? {
            let mut fallback = Vec::new();
            for child in node
                .children()
                .filter(|child| child.has_tag_name((XSLT_NS, "fallback")))
            {
                fallback.extend(compile_sequence(child.children(), context.descend()?)?);
            }
            return Ok(Instruction::Fallback(fallback));
        }
        return compile_literal_element(node, context);
    }
    let sequence = || compile_sequence(node.children(), context);
    Ok(match node.tag_name().name() {
        "apply-templates" => {
            let mut sorts = vec![];
            let mut parameters = vec![];
            let mut saw_parameter = false;
            for child in node.children().filter(roxmltree::Node::is_element) {
                if child.has_tag_name((XSLT_NS, "sort")) && !saw_parameter {
                    sorts.push(compile_sort(child)?)
                } else if child.has_tag_name((XSLT_NS, "with-param")) {
                    saw_parameter = true;
                    parameters.push(WithParam {
                        variable: compile_variable(child, context.descend()?)?,
                    })
                } else {
                    return Err(Error::Static(
                        "xsl:apply-templates accepts only xsl:sort and xsl:with-param".into(),
                    ));
                }
            }
            Instruction::ApplyTemplates {
                select: Expression::new(node.attribute("select").unwrap_or("node()"), node)?,
                mode: optional_qname_attr(node, "mode")?,
                sorts,
                parameters,
            }
        }
        "apply-imports" => {
            if node.children().any(|child| {
                child.is_element() || child.text().is_some_and(|text| !text.trim().is_empty())
            }) {
                return Err(Error::Static("xsl:apply-imports must be empty".into()));
            }
            Instruction::ApplyImports
        }
        "call-template" => {
            let parameters = node
                .children()
                .filter(roxmltree::Node::is_element)
                .map(|child| {
                    if !child.has_tag_name((XSLT_NS, "with-param")) {
                        return Err(Error::Static(
                            "xsl:call-template accepts only xsl:with-param".into(),
                        ));
                    }
                    compile_variable(child, context.descend()?)
                        .map(|variable| WithParam { variable })
                })
                .collect::<Result<_>>()?;
            Instruction::CallTemplate {
                name: required_qname_attr(node, "name")?,
                parameters,
            }
        }
        "for-each" => {
            let mut sorts = vec![];
            let mut body = vec![];
            let mut sorting = true;
            for child in node.children() {
                if child.has_tag_name((XSLT_NS, "sort")) && sorting {
                    sorts.push(compile_sort(child)?)
                } else if child.is_text() && child.text().is_none_or(|text| text.trim().is_empty())
                {
                    continue;
                } else {
                    sorting = false;
                    if child.is_text() {
                        if let Some(text) = child.text()
                            && !text.trim().is_empty()
                        {
                            body.push(Instruction::Text(text.into(), false));
                        }
                    } else if child.is_element() {
                        body.push(compile_instruction(child, context.descend()?)?);
                    }
                }
            }
            Instruction::ForEach {
                select: Expression::new(required_attr(node, "select")?, node)?,
                sorts,
                body,
            }
        }
        "if" => Instruction::If {
            test: Expression::new(required_attr(node, "test")?, node)?,
            body: sequence()?,
        },
        "choose" => {
            let mut branches = vec![];
            let mut otherwise = vec![];
            let mut saw_otherwise = false;
            for child in node.children().filter(roxmltree::Node::is_element) {
                if child.has_tag_name((XSLT_NS, "when")) && !saw_otherwise {
                    branches.push((
                        Expression::new(required_attr(child, "test")?, child)?,
                        compile_sequence(child.children(), context.descend()?)?,
                    ));
                } else if child.has_tag_name((XSLT_NS, "otherwise")) {
                    if saw_otherwise {
                        return Err(Error::Static(
                            "xsl:choose permits only one xsl:otherwise".into(),
                        ));
                    }
                    saw_otherwise = true;
                    otherwise = compile_sequence(child.children(), context.descend()?)?;
                } else {
                    return Err(Error::Static(
                        "xsl:choose accepts only xsl:when and xsl:otherwise".into(),
                    ));
                }
            }
            if branches.is_empty() {
                return Err(Error::Static("xsl:choose requires xsl:when".into()));
            }
            Instruction::Choose {
                branches,
                otherwise,
            }
        }
        "value-of" => Instruction::ValueOf {
            select: Expression::new(required_attr(node, "select")?, node)?,
            disable_output_escaping: yes_no(node.attribute("disable-output-escaping"))?,
        },
        "copy-of" => Instruction::CopyOf(Expression::new(required_attr(node, "select")?, node)?),
        "copy" => Instruction::Copy {
            body: sequence()?,
            attribute_sets: qname_list_attr(node, "use-attribute-sets")?,
        },
        "element" => Instruction::Element {
            name: parse_avt(required_attr(node, "name")?, node)?,
            namespace: node
                .attribute("namespace")
                .map(|v| parse_avt(v, node))
                .transpose()?,
            body: sequence()?,
            attribute_sets: qname_list_attr(node, "use-attribute-sets")?,
            namespaces: namespaces(node),
        },
        "attribute" => Instruction::Attribute {
            name: parse_avt(required_attr(node, "name")?, node)?,
            namespace: node
                .attribute("namespace")
                .map(|v| parse_avt(v, node))
                .transpose()?,
            body: sequence()?,
            namespaces: namespaces(node),
        },
        "text" => Instruction::Text(
            node.text().unwrap_or_default().into(),
            yes_no(node.attribute("disable-output-escaping"))?,
        ),
        "comment" => Instruction::Comment(sequence()?),
        "processing-instruction" => Instruction::Processing {
            name: parse_avt(required_attr(node, "name")?, node)?,
            body: sequence()?,
        },
        "number" => Instruction::Number(compile_number(node)?),
        "variable" => Instruction::Variable(compile_variable(node, context)?),
        "param" => {
            return Err(Error::Static(
                "xsl:param must precede template content".into(),
            ));
        }
        "message" => Instruction::Message {
            terminate: yes_no(node.attribute("terminate"))?,
            body: sequence()?,
        },
        "fallback" => Instruction::Fallback(sequence()?),
        _unknown if context.forward => {
            let mut fallback = Vec::new();
            for child in node
                .children()
                .filter(|child| child.has_tag_name((XSLT_NS, "fallback")))
            {
                fallback.extend(compile_sequence(child.children(), context.descend()?)?);
            }
            Instruction::Fallback(fallback)
        }
        unknown => {
            return Err(Error::Static(format!(
                "unknown XSLT instruction xsl:{unknown}"
            )));
        }
    })
}

fn is_extension_element(node: roxmltree::Node<'_, '_>) -> Result<bool> {
    let Some(namespace) = node.tag_name().namespace() else {
        return Ok(false);
    };
    for ancestor in node.ancestors().filter(roxmltree::Node::is_element) {
        let Some(prefixes) = ancestor
            .attribute((XSLT_NS, "extension-element-prefixes"))
            .or_else(|| ancestor.attribute("extension-element-prefixes"))
        else {
            continue;
        };
        for prefix in prefixes.split_ascii_whitespace() {
            let resolved = if prefix == "#default" {
                ancestor.lookup_namespace_uri(None)
            } else {
                ancestor.lookup_namespace_uri(Some(prefix))
            };
            if resolved == Some(namespace) {
                return Ok(true);
            }
            if resolved.is_none() {
                return Err(Error::Static(format!(
                    "unbound extension-element-prefixes prefix {prefix}"
                )));
            }
        }
    }
    Ok(false)
}
fn compile_literal_element(
    node: roxmltree::Node<'_, '_>,
    context: CompileContext,
) -> Result<Instruction> {
    let prefix = node
        .lookup_prefix(node.tag_name().namespace().unwrap_or(""))
        .map(str::to_owned);
    let attributes = node
        .attributes()
        .filter(|a| a.namespace() != Some(XSLT_NS))
        .map(|a| {
            Ok(LiteralAttribute {
                name: ExpandedName::new(a.namespace(), a.name()),
                prefix: attribute_prefix(node, a),
                value: parse_avt(a.value(), node)?,
            })
        })
        .collect::<Result<_>>()?;
    let (exclude_all, excluded) = excluded_result_namespaces(node)?;
    let used_namespaces = std::iter::once(node.tag_name().namespace())
        .chain(node.attributes().map(|attribute| attribute.namespace()))
        .flatten()
        .collect::<HashSet<_>>();
    let namespaces = node
        .namespaces()
        .filter(|n| n.uri() != XSLT_NS)
        .filter(|namespace| {
            used_namespaces.contains(namespace.uri())
                || !(exclude_all || excluded.contains(namespace.uri()))
        })
        .map(|n| Namespace {
            prefix: n.name().map(str::to_owned),
            uri: n.uri().to_owned(),
        })
        .collect();
    let attribute_sets = node
        .attribute((XSLT_NS, "use-attribute-sets"))
        .map(|v| {
            v.split_ascii_whitespace()
                .map(|q| required_qname(node, q))
                .collect()
        })
        .transpose()?
        .unwrap_or_default();
    Ok(Instruction::LiteralElement {
        name: ExpandedName::new(node.tag_name().namespace(), node.tag_name().name()),
        prefix,
        attributes,
        namespaces,
        children: compile_sequence(node.children(), context)?,
        attribute_sets,
    })
}

fn excluded_result_namespaces(node: roxmltree::Node<'_, '_>) -> Result<(bool, HashSet<String>)> {
    let mut exclude_all = false;
    let mut excluded = HashSet::new();
    let mut ancestors = node
        .ancestors()
        .filter(roxmltree::Node::is_element)
        .collect::<Vec<_>>();
    ancestors.reverse();
    for ancestor in ancestors {
        for attribute in ["exclude-result-prefixes", "extension-element-prefixes"] {
            let value = if ancestor.tag_name().namespace() == Some(XSLT_NS) {
                ancestor.attribute(attribute)
            } else if attribute == "extension-element-prefixes" {
                ancestor.attribute((XSLT_NS, attribute))
            } else {
                None
            };
            let Some(value) = value else {
                continue;
            };
            for token in value.split_ascii_whitespace() {
                if token == "#all" {
                    exclude_all = true;
                    continue;
                }
                let prefix = (token != "#default").then_some(token);
                let namespace = ancestor.lookup_namespace_uri(prefix).ok_or_else(|| {
                    Error::Static(format!("excluded result prefix {token} is not bound"))
                })?;
                excluded.insert(namespace.to_owned());
            }
        }
    }
    Ok((exclude_all, excluded))
}
fn compile_variable(node: roxmltree::Node<'_, '_>, context: CompileContext) -> Result<Variable> {
    let select = node
        .attribute("select")
        .map(|value| Expression::new(value, node))
        .transpose()?;
    let content = compile_sequence(node.children(), context)?;
    if select.is_some() && !content.is_empty() {
        return Err(Error::Static(
            "variable with select cannot have content".into(),
        ));
    }
    Ok(Variable {
        name: required_qname_attr(node, "name")?,
        select,
        content,
    })
}
fn compile_sort(node: roxmltree::Node<'_, '_>) -> Result<Sort> {
    Ok(Sort {
        select: Expression::new(node.attribute("select").unwrap_or("."), node)?,
        data_type: parse_avt(node.attribute("data-type").unwrap_or("text"), node)?,
        order: parse_avt(node.attribute("order").unwrap_or("ascending"), node)?,
        case_order: node
            .attribute("case-order")
            .map(|value| parse_avt(value, node))
            .transpose()?,
        lang: node
            .attribute("lang")
            .map(|value| parse_avt(value, node))
            .transpose()?,
    })
}
fn compile_number(node: roxmltree::Node<'_, '_>) -> Result<NumberInstruction> {
    Ok(NumberInstruction {
        value: node
            .attribute("value")
            .map(|value| Expression::new(value, node))
            .transpose()?,
        count: node
            .attribute("count")
            .map(|v| Pattern::new(v, node))
            .transpose()?,
        from: node
            .attribute("from")
            .map(|v| Pattern::new(v, node))
            .transpose()?,
        level: node.attribute("level").unwrap_or("single").into(),
        format: node.attribute("format").unwrap_or("1").into(),
        lang: node.attribute("lang").map(str::to_owned),
        letter_value: node.attribute("letter-value").map(str::to_owned),
        grouping_separator: node
            .attribute("grouping-separator")
            .map(|value| parse_avt(value, node))
            .transpose()?,
        grouping_size: node
            .attribute("grouping-size")
            .map(|value| parse_avt(value, node))
            .transpose()?,
    })
}
fn parse_avt(value: &str, node: roxmltree::Node<'_, '_>) -> Result<AttributeValueTemplate> {
    let mut parts = vec![];
    let mut literal = String::new();
    let mut chars = value.char_indices().peekable();
    while let Some((_, ch)) = chars.next() {
        match ch {
            '{' if chars.peek().is_some_and(|(_, c)| *c == '{') => {
                chars.next();
                literal.push('{')
            }
            '}' if chars.peek().is_some_and(|(_, c)| *c == '}') => {
                chars.next();
                literal.push('}')
            }
            '{' => {
                if !literal.is_empty() {
                    parts.push(AvtPart::Literal(std::mem::take(&mut literal)));
                }
                let mut expression = String::new();
                let mut quote = None;
                loop {
                    let Some((_, c)) = chars.next() else {
                        return Err(Error::Static(
                            "unterminated attribute value template".into(),
                        ));
                    };
                    if matches!(c, '\'' | '"') {
                        if quote == Some(c) {
                            quote = None
                        } else if quote.is_none() {
                            quote = Some(c)
                        }
                    }
                    if c == '}' && quote.is_none() {
                        break;
                    }
                    expression.push(c)
                }
                parts.push(AvtPart::Expression(Expression::new(
                    expression.trim(),
                    node,
                )?));
            }
            '}' => {
                return Err(Error::Static(
                    "unescaped } in attribute value template".into(),
                ));
            }
            _ => literal.push(ch),
        }
    }
    if !literal.is_empty() {
        parts.push(AvtPart::Literal(literal));
    }
    Ok(AttributeValueTemplate(parts))
}
fn merge_output(out: &mut OutputDefinition, node: roxmltree::Node<'_, '_>) -> Result<()> {
    if let Some(method) = node.attribute("method") {
        out.method_explicit = true;
        out.method = match method {
            "xml" => OutputMethod::Xml,
            "html" => OutputMethod::Html,
            "text" => OutputMethod::Text,
            _ => return Err(Error::Static(format!("unsupported output method {method}"))),
        }
    }
    if let Some(v) = node.attribute("version") {
        out.version = Some(v.into())
    }
    if let Some(v) = node.attribute("encoding") {
        out.encoding_explicit = true;
        out.encoding = v.into()
    }
    if node.attribute("omit-xml-declaration").is_some() {
        out.omit_xml_declaration = yes_no(node.attribute("omit-xml-declaration"))?
    }
    if let Some(v) = node.attribute("standalone") {
        out.standalone = Some(yes_no(Some(v))?)
    }
    if let Some(v) = node.attribute("doctype-public") {
        out.doctype_public = Some(v.into())
    }
    if let Some(v) = node.attribute("doctype-system") {
        out.doctype_system = Some(v.into())
    }
    if node.attribute("indent").is_some() {
        out.indent_explicit = true;
        out.indent = yes_no(node.attribute("indent"))?
    }
    if let Some(v) = node.attribute("media-type") {
        out.media_type = Some(v.into())
    }
    if let Some(v) = node.attribute("cdata-section-elements") {
        for name in v.split_ascii_whitespace() {
            out.cdata_section_elements
                .insert(required_qname(node, name)?);
        }
    }
    Ok(())
}
impl NameTest {
    fn parse(value: &str, node: roxmltree::Node<'_, '_>) -> Result<Self> {
        if value == "*" {
            return Ok(Self {
                namespace: NamespaceTest::Any,
                local: None,
            });
        }
        if let Some((prefix, local)) = value.split_once(':') {
            let namespace = node
                .lookup_namespace_uri(Some(prefix))
                .ok_or_else(|| Error::Static(format!("unbound prefix {prefix}")))?;
            Ok(Self {
                namespace: NamespaceTest::Exact(namespace.into()),
                local: (local != "*").then(|| local.into()),
            })
        } else {
            Ok(Self {
                namespace: NamespaceTest::None,
                local: Some(value.into()),
            })
        }
    }
}
impl DecimalFormat {
    fn parse(node: roxmltree::Node<'_, '_>) -> Result<Self> {
        fn one(node: roxmltree::Node<'_, '_>, name: &str, default: char) -> Result<char> {
            node.attribute(name).map_or(Ok(default), |v| {
                let mut c = v.chars();
                let first = c
                    .next()
                    .ok_or_else(|| Error::Static(format!("empty {name}")))?;
                if c.next().is_some() {
                    return Err(Error::Static(format!("{name} must be one character")));
                }
                Ok(first)
            })
        }
        Ok(Self {
            name: optional_qname_attr(node, "name")?,
            decimal_separator: one(node, "decimal-separator", '.')?,
            grouping_separator: one(node, "grouping-separator", ',')?,
            infinity: node.attribute("infinity").unwrap_or("Infinity").into(),
            minus_sign: one(node, "minus-sign", '-')?,
            nan: node.attribute("NaN").unwrap_or("NaN").into(),
            percent: one(node, "percent", '%')?,
            per_mille: one(node, "per-mille", '‰')?,
            zero_digit: one(node, "zero-digit", '0')?,
            digit: one(node, "digit", '#')?,
            pattern_separator: one(node, "pattern-separator", ';')?,
        })
    }
}
impl AttributeSet {
    fn parse(node: roxmltree::Node<'_, '_>, context: CompileContext) -> Result<Self> {
        let uses = node
            .attribute("use-attribute-sets")
            .map(|v| {
                v.split_ascii_whitespace()
                    .map(|q| required_qname(node, q))
                    .collect()
            })
            .transpose()?
            .unwrap_or_default();
        let attributes = node
            .children()
            .filter(roxmltree::Node::is_element)
            .map(|child| compile_instruction(child, context.descend()?))
            .collect::<Result<Vec<_>>>()?;
        if attributes
            .iter()
            .any(|i| !matches!(i, Instruction::Attribute { .. }))
        {
            return Err(Error::Static(
                "xsl:attribute-set may contain only xsl:attribute".into(),
            ));
        }
        Ok(Self {
            name: required_qname_attr(node, "name")?,
            uses,
            attributes,
        })
    }
}
fn namespaces(node: roxmltree::Node<'_, '_>) -> Vec<(String, String)> {
    node.namespaces()
        .filter_map(|n| n.name().map(|p| (p.into(), n.uri().into())))
        .collect()
}
fn required_attr<'a>(node: roxmltree::Node<'a, '_>, name: &str) -> Result<&'a str> {
    node.attribute(name)
        .ok_or_else(|| Error::Static(format!("xsl:{} requires {name}", node.tag_name().name())))
}
fn required_qname_attr(node: roxmltree::Node<'_, '_>, name: &str) -> Result<ExpandedName> {
    required_qname(node, required_attr(node, name)?)
}
fn qname_list_attr(node: roxmltree::Node<'_, '_>, name: &str) -> Result<Vec<ExpandedName>> {
    node.attribute(name)
        .map(|value| {
            value
                .split_ascii_whitespace()
                .map(|name| required_qname(node, name))
                .collect()
        })
        .transpose()
        .map(Option::unwrap_or_default)
}
fn optional_qname_attr(node: roxmltree::Node<'_, '_>, name: &str) -> Result<Option<ExpandedName>> {
    node.attribute(name)
        .map(|v| required_qname(node, v))
        .transpose()
}
fn required_qname(node: roxmltree::Node<'_, '_>, value: &str) -> Result<ExpandedName> {
    if let Some((prefix, local)) = value.split_once(':') {
        if prefix.is_empty() || local.is_empty() || local.contains(':') {
            return Err(Error::Static(format!("invalid QName {value}")));
        }
        let uri = node
            .lookup_namespace_uri(Some(prefix))
            .ok_or_else(|| Error::Static(format!("unbound prefix {prefix}")))?;
        Ok(ExpandedName::new(Some(uri), local))
    } else {
        Ok(ExpandedName::new(None::<String>, value))
    }
}
fn attribute_prefix(
    node: roxmltree::Node<'_, '_>,
    attribute: roxmltree::Attribute<'_, '_>,
) -> Option<String> {
    attribute
        .namespace()
        .and_then(|uri| node.lookup_prefix(uri))
        .map(str::to_owned)
}
fn yes_no(value: Option<&str>) -> Result<bool> {
    match value.unwrap_or("no") {
        "yes" => Ok(true),
        "no" => Ok(false),
        other => Err(Error::Static(format!("expected yes or no, got {other}"))),
    }
}
