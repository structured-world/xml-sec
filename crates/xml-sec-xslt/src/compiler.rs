use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::budget::ensure;
use crate::lexical::{is_ncname, unicode_decimal_value};
use crate::resolver::decode_resource;
use crate::{
    BudgetKind, CompileBudget, Document, Error, ExpandedName, Namespace, OutputDefinition,
    OutputMethod, ResolvePurpose, ResolvedResource, Resolver, ResourceIdentity, Result,
};

pub(crate) const XSLT_NS: &str = "http://www.w3.org/1999/XSL/Transform";
pub(crate) const EXSLT_FUNCTIONS_NS: &str = "http://exslt.org/functions";
const SAXON_NS: &str = "http://icl.com/saxon";
const XT_NS: &str = "http://www.jclark.com/xt";
const XALAN_REDIRECT_NS: &str = "org.apache.xalan.xslt.extensions.Redirect";
const LIBXSLT_TEST_NS: &str = "http://xmlsoft.org/XSLT/";
const LIBXSLT_TEST_PLUGIN_NS: &str = "http://xmlsoft.org/xslt/testplugin";

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
        let mut state = CompileState::new(self.budget, xml.len());
        self.compile_module(xml, base_uri, None, &mut state, 1)?;
        let principal_document = parse_semantic_document_metered(xml, base_uri, &mut state)?;
        let mut stylesheet = state.finish()?;
        stylesheet.principal_document = principal_document;
        stylesheet.principal_base_uri = base_uri.map(str::to_owned);
        Ok(stylesheet)
    }

    /// Decode and compile a complete stylesheet graph from external XML bytes.
    pub fn compile_bytes(&self, bytes: &[u8], base_uri: Option<&str>) -> Result<Stylesheet> {
        ensure(
            BudgetKind::StylesheetBytes,
            self.budget.stylesheet_bytes,
            bytes.len(),
        )?;
        let xml = xml_sec_xml_input::decode_xml_bounded(bytes, None, self.budget.stylesheet_bytes)
            .map_err(|error| Error::Xml(error.to_string()))?;
        self.compile(&xml, base_uri)
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
        state.charge_owned(estimate_compiled_owned_bytes(&document))?;
        let root = document.root_element();
        let StylesheetModuleKind::Standard { forward } = stylesheet_module_kind(root)? else {
            let precedence = inherited_precedence.unwrap_or_else(|| state.next_precedence());
            return self
                .compile_literal_result_stylesheet(root, base_uri, precedence, state, depth);
        };
        validate_standard_stylesheet_content(root)?;
        validate_top_level_declaration_attributes(root, forward)?;
        validate_namespace_prefix_attributes(root, forward)?;
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
                ensure(
                    BudgetKind::RecursionDepth,
                    state.budget.recursion_depth,
                    depth + 1,
                )?;
                let resource =
                    self.resolve_module(child, base_uri, ResolvePurpose::Import, state)?;
                self.enter_resource(&resource, state, |state| {
                    let source = resource_source(&resource, state)?;
                    self.compile_module(
                        &source,
                        Some(&resource.canonical_uri),
                        None,
                        state,
                        depth + 1,
                    )
                })?;
            } else if child.has_tag_name((XSLT_NS, "include")) {
                ensure(
                    BudgetKind::RecursionDepth,
                    state.budget.recursion_depth,
                    depth + 1,
                )?;
                let resource =
                    self.resolve_module(child, base_uri, ResolvePurpose::Include, state)?;
                self.enter_resource(&resource, state, |state| {
                    let source = resource_source(&resource, state)?;
                    let document = roxmltree::Document::parse(&source)
                        .map_err(|error| Error::Xml(error.to_string()))?;
                    let included_root = document.root_element();
                    match stylesheet_module_kind(included_root)? {
                        StylesheetModuleKind::Standard { forward } => {
                            validate_standard_stylesheet_content(included_root)?;
                            validate_top_level_declaration_attributes(included_root, forward)?;
                            self.compile_effective_imports(
                                included_root,
                                Some(&resource.canonical_uri),
                                state,
                                depth + 1,
                                saw_non_import,
                            )
                        }
                        StylesheetModuleKind::Simplified => Ok(()),
                    }
                })?;
                // XSLT 1.0 section 2.6.2 requires imports to precede every other top-level
                // element, explicitly including xsl:include after its imports are expanded.
                // https://www.w3.org/TR/1999/REC-xslt-19991116#import
                *saw_non_import = true;
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
                ensure(
                    BudgetKind::RecursionDepth,
                    state.budget.recursion_depth,
                    depth + 1,
                )?;
                let resource =
                    self.resolve_module(child, base_uri, ResolvePurpose::Include, state)?;
                self.enter_resource(&resource, state, |state| {
                    let source = resource_source(&resource, state)?;
                    let document = roxmltree::Document::parse(&source)
                        .map_err(|error| Error::Xml(error.to_string()))?;
                    let included_root = document.root_element();
                    match stylesheet_module_kind(included_root)? {
                        StylesheetModuleKind::Standard {
                            forward: included_forward,
                        } => self.compile_effective_declarations(
                            included_root,
                            Some(&resource.canonical_uri),
                            precedence,
                            included_forward,
                            state,
                            depth + 1,
                        ),
                        StylesheetModuleKind::Simplified => self.compile_literal_result_stylesheet(
                            included_root,
                            Some(&resource.canonical_uri),
                            precedence,
                            state,
                            depth + 1,
                        ),
                    }
                })?;
                continue;
            }
            self.compile_top_level(child, base_uri, precedence, forward, state, depth)?;
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
            && previous.as_ref() != resource.as_ref()
        {
            return Err(Error::StaleResource {
                identity: resource.identity.clone(),
            });
        }
        if !state.resolved_identities.contains_key(&resource.identity) {
            state.charge_stylesheet(resource.bytes.len())?;
        }
        state.charge_owned(resource.bytes.len())?;
        if !state.module_documents.contains_key(&resource.canonical_uri) {
            let source = resource_source(&resource, state)?;
            let document =
                parse_semantic_document_metered(&source, Some(&resource.canonical_uri), state)?;
            state
                .module_documents
                .insert(resource.canonical_uri.clone(), document);
        }
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
        base_uri: Option<&str>,
        precedence: usize,
        state: &mut CompileState,
        depth: usize,
    ) -> Result<()> {
        let version = root.attribute((XSLT_NS, "version")).ok_or_else(|| {
            Error::Static("literal result stylesheet requires xsl:version".into())
        })?;
        let forward = parse_stylesheet_version(version)? > 1.0;
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
                CompileContext::new(forward, depth, state.budget.recursion_depth, base_uri)?,
            )?]
            .into(),
        });
        Ok(())
    }

    fn compile_top_level(
        &self,
        node: roxmltree::Node<'_, '_>,
        base_uri: Option<&str>,
        precedence: usize,
        forward: bool,
        state: &mut CompileState,
        depth: usize,
    ) -> Result<()> {
        if node.has_tag_name((EXSLT_FUNCTIONS_NS, "function")) {
            validate_exslt_function_result_structure(node)?;
            let context =
                CompileContext::new(forward, depth, state.budget.recursion_depth, base_uri)?
                    .inside_function();
            let mut children = node.children().peekable();
            let mut params = Vec::new();
            while let Some(child) = children.peek().copied() {
                if child.has_tag_name((XSLT_NS, "param")) {
                    params.push(compile_variable(child, context.clone())?);
                    children.next();
                } else if is_ignorable_stylesheet_child(child) {
                    children.next();
                } else {
                    break;
                }
            }
            let body = compile_sequence(children, context)?;
            let order = state.next_order();
            state.functions.push(ExsltFunction {
                name: required_qname_attr(node, "name")?,
                params,
                body,
                precedence,
                order,
            });
            return Ok(());
        }
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
                    .map(|value| {
                        let priority = crate::xpath::xpath_number(value);
                        priority.is_finite().then_some(priority).ok_or_else(|| {
                            Error::Static("template priority must be a finite XPath number".into())
                        })
                    })
                    .transpose()?;
                let mode = optional_qname_attr(node, "mode")?;
                let mut children = node.children().peekable();
                let mut params = Vec::new();
                while let Some(child) = children.peek().copied() {
                    if child.has_tag_name((XSLT_NS, "param")) {
                        params.push(compile_variable(
                            child,
                            CompileContext::new(
                                forward,
                                depth,
                                state.budget.recursion_depth,
                                base_uri,
                            )?,
                        )?);
                        children.next();
                    } else if is_ignorable_stylesheet_child(child) {
                        children.next();
                    } else {
                        break;
                    }
                }
                let body: Arc<[Instruction]> = compile_sequence(
                    children,
                    CompileContext::new(forward, depth, state.budget.recursion_depth, base_uri)?,
                )?
                .into();
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
                            body: Arc::clone(&body),
                        });
                    }
                }
            }
            "variable" | "param" => {
                let variable = compile_variable(
                    node,
                    CompileContext::new(forward, depth, state.budget.recursion_depth, base_uri)?,
                )?;
                let order = state.next_order();
                state.globals.push(GlobalVariable {
                    variable,
                    precedence,
                    order,
                    is_parameter: node.tag_name().name() == "param",
                });
            }
            "output" => merge_output(
                &mut state.output,
                &mut state.output_precedence,
                node,
                precedence,
            )?,
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
            "key" => {
                let match_pattern = required_attr(node, "match")?;
                let use_expression = required_attr(node, "use")?;
                validate_key_dependency_expression("match", match_pattern)?;
                validate_key_dependency_expression("use", use_expression)?;
                state.keys.push(KeyDeclaration {
                    name: required_qname_attr(node, "name")?,
                    match_pattern: Pattern::new(match_pattern, node)?,
                    use_expression: Expression::new(use_expression, node, base_uri)?,
                });
            }
            "decimal-format" => {
                let format = DecimalFormat::parse(node, precedence)?;
                if let Some(existing) = state.decimal_formats.iter().find(|existing| {
                    existing.name == format.name && existing.precedence == format.precedence
                }) {
                    if existing != &format {
                        return Err(Error::Static(format!(
                            "conflicting xsl:decimal-format declaration for {}",
                            format
                                .name
                                .as_ref()
                                .map_or("the default format", |name| name.local.as_str())
                        )));
                    }
                } else {
                    state.decimal_formats.push(format);
                }
            }
            "namespace-alias" => merge_namespace_alias(
                &mut state.namespace_aliases,
                &mut state.namespace_alias_index,
                parse_namespace_alias(node, precedence)?,
            )?,
            "attribute-set" => {
                let order = state.next_order();
                state.attribute_sets.push(AttributeSet::parse(
                    node,
                    CompileContext::new(forward, depth, state.budget.recursion_depth, base_uri)?,
                    precedence,
                    order,
                )?)
            }
            _unknown if forward => {}
            unknown => return Err(Error::Static(format!("unknown top-level xsl:{unknown}"))),
        }
        Ok(())
    }
}

fn validate_standard_stylesheet_content(root: roxmltree::Node<'_, '_>) -> Result<()> {
    // XSLT 1.0 section 2.2 permits only template top-level declarations after stylesheet
    // whitespace stripping; other character data is a static error.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#stylesheet-element
    if root
        .children()
        .any(|child| child.is_text() && !is_ignorable_stylesheet_text(child))
    {
        return Err(Error::Static(
            "non-whitespace character data is not allowed at stylesheet top level".into(),
        ));
    }
    Ok(())
}

/// Immutable compiled XSLT stylesheet.
#[derive(Debug, Clone)]
pub struct Stylesheet {
    pub(crate) principal_document: Document,
    pub(crate) principal_base_uri: Option<String>,
    pub(crate) module_documents: Arc<[(String, Document)]>,
    pub(crate) templates: Arc<[Template]>,
    pub(crate) globals: Arc<[GlobalVariable]>,
    pub(crate) output: OutputDefinition,
    pub(crate) whitespace: Arc<[(NameTest, bool, usize, usize)]>,
    pub(crate) keys: Arc<[KeyDeclaration]>,
    pub(crate) decimal_formats: Arc<[DecimalFormat]>,
    pub(crate) namespace_aliases: Arc<[NamespaceAlias]>,
    pub(crate) attribute_sets: Arc<[AttributeSet]>,
    pub(crate) functions: Arc<[ExsltFunction]>,
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
    pub body: Arc<[Instruction]>,
}
#[derive(Debug, Clone)]
pub(crate) struct GlobalVariable {
    pub variable: Variable,
    pub precedence: usize,
    pub order: usize,
    pub is_parameter: bool,
}
#[derive(Debug, Clone)]
pub(crate) struct ExsltFunction {
    pub name: ExpandedName,
    pub params: Vec<Variable>,
    pub body: Vec<Instruction>,
    pub precedence: usize,
    pub order: usize,
}
#[derive(Debug, Clone)]
pub(crate) struct Variable {
    pub name: ExpandedName,
    pub select: Option<Expression>,
    pub content: Vec<Instruction>,
    pub base_uri: Option<String>,
}
#[derive(Debug, Clone)]
pub(crate) struct Expression {
    pub source: String,
    pub namespaces: Vec<(String, String)>,
    /// Expanded references let execution initialize only globals on the reached XPath path.
    pub variable_references: Arc<[ExpandedName]>,
    /// Static base of the stylesheet module that owns this expression.
    pub static_base_uri: Option<String>,
}
#[derive(Debug, Clone)]
pub(crate) struct Pattern {
    pub source: String,
    pub namespaces: Vec<(String, String)>,
    pub matches_attributes: bool,
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
    SecondaryOutput {
        uri: AttributeValueTemplate,
        properties: Vec<(String, AttributeValueTemplate)>,
        body: Vec<Instruction>,
    },
    ExtensionFallback {
        name: String,
        present: bool,
        body: Vec<Instruction>,
    },
    CompatibilityComment(String),
    FunctionResult {
        select: Option<Expression>,
        content: Vec<Instruction>,
        base_uri: Option<String>,
    },
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
    pub format: AttributeValueTemplate,
    pub lang: Option<AttributeValueTemplate>,
    pub letter_value: Option<AttributeValueTemplate>,
    pub grouping_separator: Option<AttributeValueTemplate>,
    pub grouping_size: Option<AttributeValueTemplate>,
    pub forward_compatible: bool,
}
#[derive(Debug, Clone)]
pub(crate) struct KeyDeclaration {
    pub name: ExpandedName,
    pub match_pattern: Pattern,
    pub use_expression: Expression,
}
#[derive(Debug, Clone)]
pub(crate) struct NamespaceAlias {
    pub stylesheet_namespace: Option<Arc<str>>,
    pub output_prefix: Option<String>,
    pub result_namespace: Option<String>,
    precedence: usize,
}
#[derive(Debug, Clone)]
pub(crate) struct AttributeSet {
    pub name: ExpandedName,
    pub uses: Vec<ExpandedName>,
    pub attributes: Vec<Instruction>,
    pub precedence: usize,
    pub order: usize,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecimalFormat {
    pub name: Option<ExpandedName>,
    pub precedence: usize,
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
    fn new(
        source: &str,
        node: roxmltree::Node<'_, '_>,
        static_base_uri: Option<&str>,
    ) -> Result<Self> {
        let namespaces = namespaces(node);
        validate_xpath_prefixes(source, &namespaces)?;
        let normalized = normalize_xpath_for_sxd(source);
        let normalized = crate::xpath::rewrite_absolute_paths_for_validation(&normalized);
        sxd_xpath_no_unsafe::Factory::new()
            .build(&normalized)
            .map_err(|error| {
                Error::Static(format!("invalid XPath expression `{source}`: {error}"))
            })?;
        Ok(Self::from_parts(
            source.to_owned(),
            namespaces,
            effective_base_uri(node, static_base_uri)?,
        ))
    }

    pub(crate) fn derived(&self, source: impl Into<String>) -> Self {
        Self::from_parts(
            source.into(),
            self.namespaces.clone(),
            self.static_base_uri.clone(),
        )
    }

    pub(crate) fn generated(source: impl Into<String>, namespaces: Vec<(String, String)>) -> Self {
        Self::from_parts(source.into(), namespaces, None)
    }

    fn from_parts(
        source: String,
        namespaces: Vec<(String, String)>,
        static_base_uri: Option<String>,
    ) -> Self {
        let variable_references = referenced_variables(&source, &namespaces).into();
        Self {
            source,
            namespaces,
            variable_references,
            static_base_uri,
        }
    }
}

fn referenced_variables(source: &str, namespaces: &[(String, String)]) -> Vec<ExpandedName> {
    let mut output = Vec::new();
    let mut quote = None;
    let mut characters = source.char_indices().peekable();
    while let Some((_, character)) = characters.next() {
        if let Some(active) = quote {
            if character == active {
                quote = None;
            }
            continue;
        }
        if matches!(character, '\'' | '"') {
            quote = Some(character);
            continue;
        }
        if character != '$' {
            continue;
        }
        let Some(&(byte_start, _)) = characters.peek() else {
            break;
        };
        let mut byte_end = byte_start;
        while let Some(&(offset, character)) = characters.peek() {
            if !crate::lexical::is_ncname_char(character) && character != ':' {
                break;
            }
            byte_end = offset + character.len_utf8();
            characters.next();
        }
        let lexical = &source[byte_start..byte_end];
        if is_lexical_qname(lexical) {
            let (prefix, local) = lexical
                .split_once(':')
                .map_or((None, lexical), |(prefix, local)| (Some(prefix), local));
            let namespace = prefix.and_then(|prefix| {
                namespaces
                    .iter()
                    .find(|(candidate, _)| candidate == prefix)
                    .map(|(_, namespace)| namespace.clone())
            });
            output.push(ExpandedName::new(namespace, local));
        }
    }
    output.sort_by(|left, right| {
        left.namespace
            .cmp(&right.namespace)
            .then_with(|| left.local.cmp(&right.local))
    });
    output.dedup();
    output
}

fn is_lexical_qname(value: &str) -> bool {
    let mut parts = value.split(':');
    let Some(first) = parts.next() else {
        return false;
    };
    is_ncname(first) && parts.next().is_none_or(is_ncname) && parts.next().is_none()
}
impl Pattern {
    fn new(source: &str, node: roxmltree::Node<'_, '_>) -> Result<Self> {
        if trim_xml_whitespace(source).is_empty() {
            return Err(Error::Static("empty template pattern".into()));
        }
        if contains_variable_reference(source) {
            return Err(Error::Static(format!(
                "XSLT 1.0 match pattern `{source}` must not contain a variable reference"
            )));
        }
        for branch in split_pattern_branches(source) {
            let branch = trim_xml_whitespace(branch);
            validate_xslt_pattern_branch(branch)?;
            validate_xpath_prefixes(branch, &namespaces(node))?;
            let normalized = normalize_xpath_for_sxd(branch);
            let expression = if normalized.starts_with('/')
                || normalized.starts_with("id(")
                || normalized.starts_with("key(")
            {
                normalized
            } else {
                Cow::Owned(format!("//{normalized}"))
            };
            let expression = crate::xpath::rewrite_absolute_paths_for_validation(&expression);
            sxd_xpath_no_unsafe::Factory::new()
                .build(&expression)
                .map_err(|error| {
                    Error::Static(format!("invalid match pattern `{branch}`: {error}"))
                })?;
        }
        Ok(Self {
            source: source.to_owned(),
            namespaces: namespaces(node),
            matches_attributes: sxd_xpath_no_unsafe::expression_uses_attribute_axis(
                &normalize_xpath_for_sxd(source),
            ),
        })
    }

    fn template_branches(source: &str, node: roxmltree::Node<'_, '_>) -> Result<Vec<Self>> {
        split_pattern_branches(source)
            .into_iter()
            .map(|branch| Self::new(trim_xml_whitespace(branch), node))
            .collect()
    }
    fn default_priority(&self) -> f64 {
        let normalized = normalize_xpath_for_sxd(trim_xml_whitespace(&self.source));
        let value = normalized
            .strip_prefix("child::")
            .or_else(|| normalized.strip_prefix("attribute::"))
            .unwrap_or(&normalized);
        if matches!(value, "*" | "@*")
            || matches!(
                value,
                "node()" | "text()" | "comment()" | "processing-instruction()"
            )
        {
            -0.5
        } else if value.ends_with(":*") {
            -0.25
        } else if !value.contains(['/', '[', '|', '(', ')'])
            || value
                .strip_prefix("processing-instruction(")
                .and_then(|value| value.strip_suffix(')'))
                .is_some_and(|value| {
                    let value = trim_xml_whitespace(value);
                    (value.starts_with('\'') && value.ends_with('\''))
                        || (value.starts_with('"') && value.ends_with('"'))
                })
        {
            0.0
        } else {
            0.5
        }
    }
}

fn contains_variable_reference(source: &str) -> bool {
    let mut quote = None;
    for character in source.chars() {
        if let Some(active) = quote {
            if character == active {
                quote = None;
            }
        } else if matches!(character, '\'' | '"') {
            quote = Some(character);
        } else if character == '$' {
            return true;
        }
    }
    false
}

fn validate_xpath_prefixes(source: &str, namespaces: &[(String, String)]) -> Result<()> {
    let characters = source.chars().collect::<Vec<_>>();
    let mut quote = None;
    let mut cursor = 0;
    while cursor < characters.len() {
        let character = characters[cursor];
        if let Some(active) = quote {
            if character == active {
                quote = None;
            }
            cursor += 1;
            continue;
        }
        if matches!(character, '\'' | '"') {
            quote = Some(character);
            cursor += 1;
            continue;
        }
        if !is_xpath_name_start(character) {
            cursor += 1;
            continue;
        }
        let start = cursor;
        cursor += 1;
        while cursor < characters.len() && is_xpath_ncname_character(characters[cursor]) {
            cursor += 1;
        }
        if cursor >= characters.len()
            || characters[cursor] != ':'
            || characters.get(cursor + 1) == Some(&':')
            || !characters
                .get(cursor + 1)
                .copied()
                .is_some_and(|character| character == '*' || is_xpath_name_start(character))
        {
            continue;
        }
        let prefix = characters[start..cursor].iter().collect::<String>();
        if prefix != "xml" && !namespaces.iter().any(|(declared, _)| declared == &prefix) {
            return Err(Error::Static(format!(
                "XPath expression `{source}` uses unbound namespace prefix `{prefix}`"
            )));
        }
        cursor += 1;
    }
    Ok(())
}

fn is_xpath_name_start(character: char) -> bool {
    character.is_alphabetic() || character == '_'
}

fn is_xpath_ncname_character(character: char) -> bool {
    is_xpath_name_start(character) || character.is_ascii_digit() || matches!(character, '-' | '.')
}

pub(crate) fn normalize_xpath_for_sxd(source: &str) -> Cow<'_, str> {
    // XPath 1.0 §3.7 defines whitespace as only XML S characters:
    // https://www.w3.org/TR/1999/REC-xpath-19991116/#exprlex
    if !source.chars().any(crate::lexical::is_xml_whitespace) && !source.contains('*') {
        return Cow::Borrowed(source);
    }
    let characters = source.chars().collect::<Vec<_>>();
    let mut output = String::with_capacity(source.len());
    let mut quote = None;
    let mut index = 0;
    while index < characters.len() {
        let character = characters[index];
        if let Some(active) = quote {
            output.push(character);
            if character == active {
                quote = None;
            }
            index += 1;
            continue;
        }
        if matches!(character, '\'' | '"') {
            quote = Some(character);
            output.push(character);
            index += 1;
            continue;
        }
        if crate::lexical::is_xml_whitespace(character)
            && output
                .chars()
                .next_back()
                .is_some_and(is_xpath_name_character)
        {
            let mut next = index + 1;
            while next < characters.len() && crate::lexical::is_xml_whitespace(characters[next]) {
                next += 1;
            }
            if next < characters.len() && characters[next] == '(' {
                index = next;
                continue;
            }
            if characters.get(next..next + 2) == Some(&[':', ':']) {
                index = next;
                continue;
            }
        }
        if character == ':' && characters.get(index + 1) == Some(&':') {
            output.push_str("::");
            index += 2;
            while index < characters.len() && crate::lexical::is_xml_whitespace(characters[index]) {
                index += 1;
            }
            continue;
        }
        if character == '*'
            && output
                .chars()
                .rev()
                .find(|candidate| !crate::lexical::is_xml_whitespace(*candidate))
                .is_some_and(|previous| matches!(previous, '(' | ','))
        {
            let next = characters[index + 1..]
                .iter()
                .copied()
                .find(|candidate| !crate::lexical::is_xml_whitespace(*candidate));
            if next.is_some_and(|next| matches!(next, ')' | ',')) {
                output.push_str("child::*");
                index += 1;
                continue;
            }
        }
        output.push(character);
        index += 1;
    }
    if output == source {
        Cow::Borrowed(source)
    } else {
        Cow::Owned(output)
    }
}

fn is_xpath_name_character(character: char) -> bool {
    character.is_alphanumeric() || matches!(character, '_' | '-' | '.' | ':')
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

fn validate_xslt_pattern_branch(branch: &str) -> Result<()> {
    let normalized = normalize_xpath_for_sxd(branch);
    let branch = normalized.as_ref();
    if branch == "/" {
        return Ok(());
    }
    let relative = if let Some(relative) = strip_id_key_pattern(branch)? {
        if relative.is_empty() {
            return Ok(());
        }
        relative
            .strip_prefix("//")
            .or_else(|| relative.strip_prefix('/'))
            .ok_or_else(|| invalid_match_pattern(branch))?
    } else {
        branch
            .strip_prefix("//")
            .or_else(|| branch.strip_prefix('/'))
            .unwrap_or(branch)
    };
    let steps = split_pattern_steps(relative).ok_or_else(|| invalid_match_pattern(branch))?;
    if steps.is_empty() || steps.iter().any(|step| !valid_pattern_step(step)) {
        return Err(invalid_match_pattern(branch));
    }
    Ok(())
}

fn strip_id_key_pattern(branch: &str) -> Result<Option<&str>> {
    let (name, expected_arguments) = if branch.starts_with("id(") {
        ("id", 1)
    } else if branch.starts_with("key(") {
        ("key", 2)
    } else {
        return Ok(None);
    };
    let open = name.len();
    let Some(close) = matching_delimiter(branch, open, '(', ')') else {
        return Err(invalid_match_pattern(branch));
    };
    let arguments = split_top_level(&branch[open + 1..close], ',');
    if arguments.len() != expected_arguments
        || arguments.iter().any(|value| !is_xpath_literal(value))
    {
        return Err(invalid_match_pattern(branch));
    }
    Ok(Some(branch[close + 1..].trim()))
}

fn split_pattern_steps(source: &str) -> Option<Vec<&str>> {
    if source.trim().is_empty() {
        return None;
    }
    let mut steps = Vec::new();
    let mut start = 0usize;
    let mut brackets = 0usize;
    let mut parentheses = 0usize;
    let mut quote = None;
    let mut characters = source.char_indices().peekable();
    while let Some((index, character)) = characters.next() {
        if let Some(active) = quote {
            if character == active {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            '[' => brackets = brackets.checked_add(1)?,
            ']' => brackets = brackets.checked_sub(1)?,
            '(' => parentheses = parentheses.checked_add(1)?,
            ')' => parentheses = parentheses.checked_sub(1)?,
            '/' if brackets == 0 && parentheses == 0 => {
                let step = source[start..index].trim();
                if step.is_empty() {
                    return None;
                }
                steps.push(step);
                if characters.peek().is_some_and(|(_, next)| *next == '/') {
                    let (second, _) = characters.next().expect("peeked path separator exists");
                    start = second + 1;
                } else {
                    start = index + 1;
                }
            }
            _ => {}
        }
    }
    if quote.is_some() || brackets != 0 || parentheses != 0 {
        return None;
    }
    let final_step = source[start..].trim();
    if final_step.is_empty() {
        return None;
    }
    steps.push(final_step);
    Some(steps)
}

fn valid_pattern_step(step: &str) -> bool {
    let predicate_start = first_top_level_character(step, '[').unwrap_or(step.len());
    let node_test = step[..predicate_start].trim();
    if !valid_pattern_node_test(node_test) {
        return false;
    }
    let mut remainder = step[predicate_start..].trim();
    while !remainder.is_empty() {
        if !remainder.starts_with('[') {
            return false;
        }
        let Some(close) = matching_delimiter(remainder, 0, '[', ']') else {
            return false;
        };
        if remainder[1..close].trim().is_empty() {
            return false;
        }
        remainder = remainder[close + 1..].trim();
    }
    true
}

fn valid_pattern_node_test(node_test: &str) -> bool {
    let normalized = normalize_xpath_for_sxd(node_test);
    let node_test = normalized.as_ref();
    let (node_test, explicit_axis) = match node_test.split_once("::") {
        Some((axis, test)) if matches!(axis.trim(), "child" | "attribute") => (test.trim(), true),
        Some(_) => return false,
        None => (node_test, false),
    };
    if explicit_axis && node_test.starts_with('@') {
        return false;
    }
    let node_test = node_test.strip_prefix('@').unwrap_or(node_test);
    if node_test == "*" || is_lexical_qname(node_test) {
        return true;
    }
    if node_test.strip_suffix(":*").is_some_and(is_ncname) {
        return true;
    }
    ["node()", "text()", "comment()"].contains(&node_test)
        || node_test == "processing-instruction()"
        || node_test
            .strip_prefix("processing-instruction(")
            .and_then(|value| value.strip_suffix(')'))
            .is_some_and(is_xpath_literal)
}

fn first_top_level_character(source: &str, needle: char) -> Option<usize> {
    let mut parentheses = 0usize;
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
            '(' => parentheses += 1,
            ')' => parentheses = parentheses.saturating_sub(1),
            _ if character == needle && parentheses == 0 => return Some(index),
            _ => {}
        }
    }
    None
}

fn matching_delimiter(source: &str, open: usize, left: char, right: char) -> Option<usize> {
    let mut depth = 0usize;
    let mut quote = None;
    for (index, character) in source.char_indices().filter(|(index, _)| *index >= open) {
        if let Some(active) = quote {
            if character == active {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            value if value == left => depth += 1,
            value if value == right => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn split_top_level(source: &str, separator: char) -> Vec<&str> {
    let mut output = Vec::new();
    let mut start = 0usize;
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
            value if value == separator && depth == 0 => {
                output.push(source[start..index].trim());
                start = index + character.len_utf8();
            }
            _ => {}
        }
    }
    output.push(source[start..].trim());
    output
}

fn is_xpath_literal(value: &str) -> bool {
    let value = value.trim();
    value.len() >= 2
        && ((value.starts_with('\'') && value.ends_with('\''))
            || (value.starts_with('"') && value.ends_with('"')))
}

fn invalid_match_pattern(pattern: &str) -> Error {
    Error::Static(format!(
        "invalid XSLT 1.0 match pattern `{pattern}`: expected a Pattern location path"
    ))
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
    if prefix == "#default" {
        return Ok(node.lookup_namespace_uri(None).map(str::to_owned));
    }
    node.lookup_namespace_uri(Some(prefix))
        .map(|uri| Some(uri.to_owned()))
        .ok_or_else(|| Error::Static(format!("namespace-alias prefix {prefix} is not bound")))
}

fn parse_namespace_alias(
    node: roxmltree::Node<'_, '_>,
    precedence: usize,
) -> Result<NamespaceAlias> {
    let stylesheet_prefix = required_attr(node, "stylesheet-prefix")?;
    let result_prefix = required_attr(node, "result-prefix")?;
    let stylesheet_namespace = alias_namespace(node, stylesheet_prefix)?;
    let result_namespace = alias_namespace(node, result_prefix)?;
    Ok(NamespaceAlias {
        stylesheet_namespace: stylesheet_namespace.map(Arc::from),
        output_prefix: (result_prefix != "#default").then(|| result_prefix.to_owned()),
        result_namespace,
        precedence,
    })
}

fn merge_namespace_alias(
    aliases: &mut Vec<NamespaceAlias>,
    index: &mut HashMap<Option<Arc<str>>, usize>,
    incoming: NamespaceAlias,
) -> Result<()> {
    let Some(existing_index) = index.get(&incoming.stylesheet_namespace).copied() else {
        index.insert(incoming.stylesheet_namespace.clone(), aliases.len());
        aliases.push(incoming);
        return Ok(());
    };
    let existing = &aliases[existing_index];
    if existing.precedence > incoming.precedence {
        return Ok(());
    }
    if existing.precedence == incoming.precedence {
        // XSLT 1.0 section 7.1.1 permits recovery from a highest-precedence conflict by choosing
        // the declaration occurring last, which is the libxslt-compatible behavior.
        // https://www.w3.org/TR/1999/REC-xslt-19991116#literal-result-element
        aliases[existing_index] = incoming;
        return Ok(());
    }
    aliases[existing_index] = incoming;
    Ok(())
}

#[derive(Default)]
struct OutputPropertyPrecedence {
    method: Option<usize>,
    version: Option<usize>,
    encoding: Option<usize>,
    omit_xml_declaration: Option<usize>,
    standalone: Option<usize>,
    doctype_public: Option<usize>,
    doctype_system: Option<usize>,
    indent: Option<usize>,
    media_type: Option<usize>,
}

struct CompileState {
    budget: CompileBudget,
    templates: Vec<Template>,
    globals: Vec<GlobalVariable>,
    output: OutputDefinition,
    output_precedence: OutputPropertyPrecedence,
    whitespace: Vec<(NameTest, bool, usize, usize)>,
    keys: Vec<KeyDeclaration>,
    decimal_formats: Vec<DecimalFormat>,
    namespace_aliases: Vec<NamespaceAlias>,
    namespace_alias_index: HashMap<Option<Arc<str>>, usize>,
    attribute_sets: Vec<AttributeSet>,
    functions: Vec<ExsltFunction>,
    resources: Vec<ResourceIdentity>,
    resource_set: HashSet<ResourceIdentity>,
    active_resources: HashSet<ResourceIdentity>,
    resolved_requests: HashMap<ResolveRequest, Arc<ResolvedResource>>,
    resolved_identities: HashMap<ResourceIdentity, Arc<ResolvedResource>>,
    module_documents: HashMap<String, Document>,
    imported_modules: usize,
    stylesheet_bytes: usize,
    owned_bytes: usize,
    precedence: usize,
    order: usize,
}
impl CompileState {
    fn new(budget: CompileBudget, stylesheet_bytes: usize) -> Self {
        Self {
            budget,
            templates: vec![],
            globals: vec![],
            output: OutputDefinition::default(),
            output_precedence: OutputPropertyPrecedence::default(),
            whitespace: vec![],
            keys: vec![],
            decimal_formats: vec![],
            namespace_aliases: vec![],
            namespace_alias_index: HashMap::new(),
            attribute_sets: vec![],
            functions: vec![],
            resources: vec![],
            resource_set: HashSet::new(),
            active_resources: HashSet::new(),
            resolved_requests: HashMap::new(),
            resolved_identities: HashMap::new(),
            module_documents: HashMap::new(),
            imported_modules: 0,
            stylesheet_bytes,
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
    fn charge_owned(&mut self, amount: usize) -> Result<()> {
        self.owned_bytes = self.owned_bytes.checked_add(amount).ok_or(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            limit: self.budget.owned_bytes,
            actual: usize::MAX,
        })?;
        ensure(
            BudgetKind::OwnedBytes,
            self.budget.owned_bytes,
            self.owned_bytes,
        )
    }
    fn charge_stylesheet(&mut self, amount: usize) -> Result<()> {
        self.stylesheet_bytes = self
            .stylesheet_bytes
            .checked_add(amount)
            .ok_or(Error::Budget {
                kind: BudgetKind::StylesheetBytes,
                limit: self.budget.stylesheet_bytes,
                actual: usize::MAX,
            })?;
        ensure(
            BudgetKind::StylesheetBytes,
            self.budget.stylesheet_bytes,
            self.stylesheet_bytes,
        )
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
        let mut functions = HashSet::new();
        for function in &self.functions {
            if !functions.insert((&function.name, function.precedence)) {
                return Err(Error::Static(format!(
                    "duplicate EXSLT function {} at equal import precedence",
                    function.name.local
                )));
            }
        }
        validate_attribute_set_references(
            &self.attribute_sets,
            &self.templates,
            &self.globals,
            &self.functions,
        )?;
        Ok(Stylesheet {
            principal_document: Document::empty(None),
            principal_base_uri: None,
            module_documents: self.module_documents.into_iter().collect::<Vec<_>>().into(),
            templates: self.templates.into(),
            globals: self.globals.into(),
            output: self.output,
            whitespace: self.whitespace.into(),
            keys: self.keys.into(),
            decimal_formats: self.decimal_formats.into(),
            namespace_aliases: self.namespace_aliases.into(),
            attribute_sets: self.attribute_sets.into(),
            functions: self.functions.into(),
            resource_identities: self.resources.into(),
        })
    }
}

fn validate_attribute_set_references(
    sets: &[AttributeSet],
    templates: &[Template],
    globals: &[GlobalVariable],
    functions: &[ExsltFunction],
) -> Result<()> {
    let declarations = sets.iter().map(|set| &set.name).collect::<HashSet<_>>();
    let validate_name = |name: &ExpandedName| {
        if declarations.contains(name) {
            Ok(())
        } else {
            Err(Error::Static(format!(
                "undefined attribute-set {}",
                name.local
            )))
        }
    };

    for set in sets {
        for name in &set.uses {
            validate_name(name)?;
        }
        validate_attribute_sets_in_sequence(&set.attributes, &validate_name)?;
    }
    for template in templates {
        for parameter in &template.params {
            validate_attribute_sets_in_sequence(&parameter.content, &validate_name)?;
        }
        validate_attribute_sets_in_sequence(&template.body, &validate_name)?;
    }
    for global in globals {
        validate_attribute_sets_in_sequence(&global.variable.content, &validate_name)?;
    }
    for function in functions {
        for parameter in &function.params {
            validate_attribute_sets_in_sequence(&parameter.content, &validate_name)?;
        }
        validate_attribute_sets_in_sequence(&function.body, &validate_name)?;
    }
    Ok(())
}

fn validate_attribute_sets_in_sequence(
    instructions: &[Instruction],
    validate_name: &impl Fn(&ExpandedName) -> Result<()>,
) -> Result<()> {
    for instruction in instructions {
        match instruction {
            Instruction::LiteralElement {
                children,
                attribute_sets,
                ..
            }
            | Instruction::Copy {
                body: children,
                attribute_sets,
            }
            | Instruction::Element {
                body: children,
                attribute_sets,
                ..
            } => {
                for name in attribute_sets {
                    validate_name(name)?;
                }
                validate_attribute_sets_in_sequence(children, validate_name)?;
            }
            Instruction::ApplyTemplates { parameters, .. }
            | Instruction::CallTemplate { parameters, .. } => {
                for parameter in parameters {
                    validate_attribute_sets_in_sequence(
                        &parameter.variable.content,
                        validate_name,
                    )?;
                }
            }
            Instruction::ForEach { body, .. }
            | Instruction::If { body, .. }
            | Instruction::Attribute { body, .. }
            | Instruction::Processing { body, .. }
            | Instruction::Message { body, .. }
            | Instruction::SecondaryOutput { body, .. }
            | Instruction::ExtensionFallback { body, .. } => {
                validate_attribute_sets_in_sequence(body, validate_name)?;
            }
            Instruction::Choose {
                branches,
                otherwise,
            } => {
                for (_, branch) in branches {
                    validate_attribute_sets_in_sequence(branch, validate_name)?;
                }
                validate_attribute_sets_in_sequence(otherwise, validate_name)?;
            }
            Instruction::Comment(body) => {
                validate_attribute_sets_in_sequence(body, validate_name)?;
            }
            Instruction::Variable(variable) => {
                validate_attribute_sets_in_sequence(&variable.content, validate_name)?;
            }
            Instruction::FunctionResult { content, .. } => {
                validate_attribute_sets_in_sequence(content, validate_name)?;
            }
            Instruction::Text(..)
            | Instruction::ApplyImports
            | Instruction::ValueOf { .. }
            | Instruction::CopyOf(_)
            | Instruction::Number(_)
            | Instruction::CompatibilityComment(_) => {}
        }
    }
    Ok(())
}

fn estimate_compiled_owned_bytes(document: &roxmltree::Document<'_>) -> usize {
    document.descendants().fold(0usize, |total, node| {
        // Compilation retains both a normalized semantic node and, conservatively, one IR
        // instruction for each frontend node. Child IDs, attributes, and namespaces live in
        // separately allocated containers and therefore need explicit structural accounting.
        let structural_bytes = std::mem::size_of::<crate::Node>()
            .saturating_add(std::mem::size_of::<Instruction>())
            .saturating_add(std::mem::size_of::<crate::NodeId>());
        let node_bytes = if node.is_element() {
            let tag = node.tag_name();
            let name_bytes = tag
                .namespace()
                .map_or(0, str::len)
                .saturating_add(tag.name().len());
            let attribute_bytes = node.attributes().fold(0usize, |sum, attribute| {
                sum.saturating_add(std::mem::size_of::<crate::Attribute>())
                    .saturating_add(attribute.namespace().map_or(0, str::len))
                    .saturating_add(attribute.name().len())
                    .saturating_add(attribute.value().len())
            });
            let namespace_bytes = node.namespaces().fold(0usize, |sum, namespace| {
                sum.saturating_add(std::mem::size_of::<crate::Namespace>())
                    .saturating_add(namespace.name().map_or(0, str::len))
                    .saturating_add(namespace.uri().len())
            });
            structural_bytes
                .saturating_add(name_bytes)
                .saturating_add(attribute_bytes)
                .saturating_add(namespace_bytes)
        } else {
            structural_bytes.saturating_add(node.text().map_or(0, str::len))
        };
        total.saturating_add(node_bytes)
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ResolveRequest {
    href: String,
    base_uri: Option<String>,
    purpose: ResolvePurpose,
}

#[derive(Debug, Clone)]
struct CompileContext {
    forward: bool,
    depth: usize,
    max_depth: usize,
    inside_function: bool,
    static_base_uri: Option<String>,
}

impl CompileContext {
    fn new(
        forward: bool,
        depth: usize,
        max_depth: usize,
        static_base_uri: Option<&str>,
    ) -> Result<Self> {
        ensure(BudgetKind::RecursionDepth, max_depth, depth)?;
        Ok(Self {
            forward,
            depth,
            max_depth,
            inside_function: false,
            static_base_uri: static_base_uri.map(str::to_owned),
        })
    }

    fn descend(&self) -> Result<Self> {
        let mut descended = Self::new(
            self.forward,
            self.depth.saturating_add(1),
            self.max_depth,
            self.static_base_uri.as_deref(),
        )?;
        descended.inside_function = self.inside_function;
        Ok(descended)
    }

    fn inside_function(mut self) -> Self {
        self.inside_function = true;
        self
    }

    fn expression(&self, source: &str, node: roxmltree::Node<'_, '_>) -> Result<Expression> {
        Expression::new(source, node, self.static_base_uri.as_deref())
    }

    fn with_literal_version(mut self, node: roxmltree::Node<'_, '_>) -> Result<Self> {
        if let Some(version) = node.attribute((XSLT_NS, "version")) {
            self.forward = parse_stylesheet_version(version)? > 1.0;
        }
        Ok(self)
    }
}

fn resource_source(resource: &ResolvedResource, state: &mut CompileState) -> Result<String> {
    let maximum = state.budget.owned_bytes.saturating_sub(state.owned_bytes);
    let decoded = decode_resource(&resource.bytes, resource.encoding.as_deref(), true, maximum)
        .map_err(|error| match error {
            xml_sec_xml_input::Error::DecodedLimit { actual, .. } => Error::Budget {
                kind: BudgetKind::OwnedBytes,
                limit: state.budget.owned_bytes,
                actual: state.owned_bytes.saturating_add(actual),
            },
            error => Error::Xml(error.to_string()),
        })?;
    state.charge_owned(decoded.len())?;
    Ok(decoded)
}

fn parse_semantic_document_metered(
    xml: &str,
    base_uri: Option<&str>,
    state: &mut CompileState,
) -> Result<Document> {
    let parsed = roxmltree::Document::parse(xml).map_err(|error| Error::Xml(error.to_string()))?;
    let projected_bytes = xml
        .len()
        .saturating_add(estimate_compiled_owned_bytes(&parsed))
        .saturating_add(
            base_uri
                .map_or(0, str::len)
                .saturating_mul(parsed.descendants().count()),
        );
    state.charge_owned(projected_bytes)?;
    Document::parse(xml, base_uri)
}

enum StylesheetModuleKind {
    Standard { forward: bool },
    Simplified,
}

fn stylesheet_module_kind(root: roxmltree::Node<'_, '_>) -> Result<StylesheetModuleKind> {
    if root.tag_name().namespace() == Some(XSLT_NS)
        && matches!(root.tag_name().name(), "stylesheet" | "transform")
    {
        return Ok(StylesheetModuleKind::Standard {
            forward: module_forward_compatible(root)?,
        });
    }
    root.attribute((XSLT_NS, "version"))
        .ok_or_else(|| Error::Static("literal result stylesheet requires xsl:version".into()))
        .and_then(parse_stylesheet_version)?;
    Ok(StylesheetModuleKind::Simplified)
}

fn module_forward_compatible(root: roxmltree::Node<'_, '_>) -> Result<bool> {
    match root.attribute("version") {
        Some(version) => Ok(parse_stylesheet_version(version)? > 1.0),
        None => Err(Error::Static("xsl:stylesheet requires version".into())),
    }
}

fn parse_stylesheet_version(version: &str) -> Result<f64> {
    // XSLT 1.0 sections 2.2 and 2.3 define version as XPath's Number production;
    // host float syntax is wider: https://www.w3.org/TR/1999/REC-xpath-19991116/#exprlex
    crate::xpath::parse_xpath_number_token(version)
        .filter(|value| value.is_finite() && *value >= 1.0)
        .ok_or_else(|| Error::Static(format!("unsupported XSLT version {version}")))
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
            base = Some(crate::resolver::resolve_uri_reference(
                base.as_deref(),
                reference,
            )?);
        }
    }
    Ok(base)
}

fn compile_sequence<'a>(
    nodes: impl Iterator<Item = roxmltree::Node<'a, 'a>>,
    context: CompileContext,
) -> Result<Vec<Instruction>> {
    let mut out = Vec::new();
    let mut follows_function_result = false;
    for node in nodes {
        if node.is_text() {
            if let Some(text) = node.text() {
                // XSLT strips whitespace-only stylesheet nodes unless explicitly
                // preserved by xsl:text; retaining indentation changes result trees.
                if !is_xml_whitespace_only(text) || stylesheet_space_is_preserved(node) {
                    out.push(Instruction::Text(text.to_owned(), false));
                }
            }
        } else if node.is_element() {
            if context.inside_function
                && follows_function_result
                && node.has_tag_name((XSLT_NS, "fallback"))
            {
                continue;
            }
            follows_function_result = node.has_tag_name((EXSLT_FUNCTIONS_NS, "result"));
            out.push(compile_instruction(node, context.descend()?)?);
        }
    }
    Ok(out)
}

fn stylesheet_space_is_preserved(node: roxmltree::Node<'_, '_>) -> bool {
    const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
    node.ancestors()
        .filter(roxmltree::Node::is_element)
        .find_map(|ancestor| ancestor.attribute((XML_NS, "space")))
        == Some("preserve")
}
fn compile_instruction(
    node: roxmltree::Node<'_, '_>,
    context: CompileContext,
) -> Result<Instruction> {
    if node.has_tag_name((EXSLT_FUNCTIONS_NS, "result")) {
        if !context.inside_function {
            return Err(Error::Static(
                "func:result is only permitted inside func:function".into(),
            ));
        }
        let select = node
            .attribute("select")
            .map(|value| context.expression(value, node))
            .transpose()?;
        let base_uri = effective_base_uri(node, context.static_base_uri.as_deref())?;
        let content = compile_sequence(node.children(), context)?;
        if select.is_some() && !content.is_empty() {
            return Err(Error::Static(
                "func:result with select cannot have content".into(),
            ));
        }
        return Ok(Instruction::FunctionResult {
            select,
            content,
            base_uri,
        });
    }
    if node.tag_name().namespace() != Some(XSLT_NS) {
        if is_extension_element(node)? {
            let locator = match (node.tag_name().namespace(), node.tag_name().name()) {
                (Some(XT_NS), "document") => Some("href"),
                (Some(SAXON_NS), "output") | (Some(XALAN_REDIRECT_NS), "write") => Some("file"),
                _ => None,
            };
            if let Some(locator) = locator {
                let uri = parse_avt(required_attr(node, locator)?, node, &context)?;
                let properties = node
                    .attributes()
                    .filter(|attribute| attribute.name() != locator)
                    .map(|attribute| {
                        if attribute.namespace().is_some() {
                            return Err(Error::Static(format!(
                                "unsupported namespaced secondary-output attribute {}",
                                attribute.name()
                            )));
                        }
                        Ok((
                            attribute.name().to_owned(),
                            parse_avt(attribute.value(), node, &context)?,
                        ))
                    })
                    .collect::<Result<Vec<_>>>()?;
                return Ok(Instruction::SecondaryOutput {
                    uri,
                    properties,
                    body: compile_sequence(
                        node.children()
                            .filter(|child| !child.has_tag_name((XSLT_NS, "fallback"))),
                        context.descend()?,
                    )?,
                });
            }
            let compatibility_comment = match (node.tag_name().namespace(), node.tag_name().name())
            {
                (Some(LIBXSLT_TEST_NS), "test") => Some("libxslt:test element test worked"),
                (Some(LIBXSLT_TEST_PLUGIN_NS), "testplugin") => {
                    Some("libxslt:testplugin element test worked")
                }
                _ => None,
            };
            if let Some(comment) = compatibility_comment {
                return Ok(Instruction::CompatibilityComment(comment.into()));
            }
            let mut fallback = Vec::new();
            let fallback_nodes = node
                .children()
                .filter(|child| child.has_tag_name((XSLT_NS, "fallback")))
                .collect::<Vec<_>>();
            for child in &fallback_nodes {
                validate_instruction_attributes(*child, context.forward)?;
                fallback.extend(compile_sequence(child.children(), context.descend()?)?);
            }
            return Ok(Instruction::ExtensionFallback {
                name: node.tag_name().name().into(),
                present: !fallback_nodes.is_empty(),
                body: fallback,
            });
        }
        return compile_literal_element(node, context);
    }
    validate_instruction_attributes(node, context.forward)?;
    let sequence = || compile_sequence(node.children(), context.clone());
    Ok(match node.tag_name().name() {
        "apply-templates" => {
            let mut sorts = vec![];
            let mut parameters = vec![];
            let mut parameter_names = HashSet::new();
            let mut saw_parameter = false;
            for child in node.children() {
                if is_ignorable_stylesheet_child(child) {
                    continue;
                }
                if child.has_tag_name((XSLT_NS, "sort")) && !saw_parameter {
                    sorts.push(compile_sort(child, &context)?)
                } else if child.has_tag_name((XSLT_NS, "with-param")) {
                    saw_parameter = true;
                    push_with_param(
                        &mut parameters,
                        &mut parameter_names,
                        child,
                        context.descend()?,
                    )?;
                } else {
                    return Err(Error::Static(
                        "xsl:apply-templates accepts only xsl:sort and xsl:with-param".into(),
                    ));
                }
            }
            Instruction::ApplyTemplates {
                select: context.expression(node.attribute("select").unwrap_or("node()"), node)?,
                mode: optional_qname_attr(node, "mode")?,
                sorts,
                parameters,
            }
        }
        "apply-imports" => {
            require_empty_instruction(node)?;
            Instruction::ApplyImports
        }
        "call-template" => {
            let mut parameters = Vec::new();
            let mut parameter_names = HashSet::new();
            for child in node.children() {
                if is_ignorable_stylesheet_child(child) {
                    continue;
                }
                if !child.has_tag_name((XSLT_NS, "with-param")) {
                    return Err(Error::Static(
                        "xsl:call-template accepts only xsl:with-param".into(),
                    ));
                }
                push_with_param(
                    &mut parameters,
                    &mut parameter_names,
                    child,
                    context.descend()?,
                )?;
            }
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
                    sorts.push(compile_sort(child, &context)?)
                } else if is_ignorable_stylesheet_child(child) {
                    continue;
                } else {
                    sorting = false;
                    if child.is_text() {
                        if let Some(text) = child.text()
                            && (!is_xml_whitespace_only(text)
                                || stylesheet_space_is_preserved(child))
                        {
                            body.push(Instruction::Text(text.into(), false));
                        }
                    } else if child.is_element() {
                        body.push(compile_instruction(child, context.descend()?)?);
                    }
                }
            }
            Instruction::ForEach {
                select: context.expression(required_attr(node, "select")?, node)?,
                sorts,
                body,
            }
        }
        "if" => Instruction::If {
            test: context.expression(required_attr(node, "test")?, node)?,
            body: sequence()?,
        },
        "choose" => {
            let mut branches = vec![];
            let mut otherwise = vec![];
            let mut saw_otherwise = false;
            for child in node.children() {
                if child.is_text() {
                    if is_ignorable_stylesheet_text(child) {
                        continue;
                    }
                    return Err(Error::Static(
                        "xsl:choose does not permit character data".into(),
                    ));
                }
                if !child.is_element() {
                    continue;
                }
                if child.has_tag_name((XSLT_NS, "when")) && !saw_otherwise {
                    validate_instruction_attributes(child, context.forward)?;
                    branches.push((
                        context.expression(required_attr(child, "test")?, child)?,
                        compile_sequence(child.children(), context.descend()?)?,
                    ));
                } else if child.has_tag_name((XSLT_NS, "otherwise")) {
                    validate_instruction_attributes(child, context.forward)?;
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
        "value-of" => {
            require_empty_instruction(node)?;
            Instruction::ValueOf {
                select: context.expression(required_attr(node, "select")?, node)?,
                disable_output_escaping: yes_no(node.attribute("disable-output-escaping"))?,
            }
        }
        "copy-of" => {
            require_empty_instruction(node)?;
            Instruction::CopyOf(context.expression(required_attr(node, "select")?, node)?)
        }
        "copy" => Instruction::Copy {
            body: sequence()?,
            attribute_sets: qname_list_attr(node, "use-attribute-sets")?,
        },
        "element" => Instruction::Element {
            name: parse_avt(required_attr(node, "name")?, node, &context)?,
            namespace: node
                .attribute("namespace")
                .map(|v| parse_avt(v, node, &context))
                .transpose()?,
            body: sequence()?,
            attribute_sets: qname_list_attr(node, "use-attribute-sets")?,
            namespaces: computed_element_namespaces(node),
        },
        "attribute" => Instruction::Attribute {
            name: parse_avt(required_attr(node, "name")?, node, &context)?,
            namespace: node
                .attribute("namespace")
                .map(|v| parse_avt(v, node, &context))
                .transpose()?,
            body: sequence()?,
            namespaces: namespaces(node),
        },
        "text" => {
            if node
                .children()
                .any(|child| !child.is_text() && !child.is_comment() && !child.is_pi())
            {
                return Err(Error::Static("xsl:text may contain only text".into()));
            }
            Instruction::Text(
                node.children()
                    .filter(roxmltree::Node::is_text)
                    .filter_map(|child| child.text())
                    .collect(),
                yes_no(node.attribute("disable-output-escaping"))?,
            )
        }
        "comment" => Instruction::Comment(sequence()?),
        "processing-instruction" => Instruction::Processing {
            name: parse_avt(required_attr(node, "name")?, node, &context)?,
            body: sequence()?,
        },
        "number" => Instruction::Number(compile_number(node, &context)?),
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
        "fallback" => {
            return Err(Error::Static(
                "xsl:fallback is permitted only as a child of an extension instruction".into(),
            ));
        }
        _unknown if context.forward => {
            let mut fallback = Vec::new();
            let fallback_nodes = node
                .children()
                .filter(|child| child.has_tag_name((XSLT_NS, "fallback")))
                .collect::<Vec<_>>();
            for child in &fallback_nodes {
                fallback.extend(compile_sequence(child.children(), context.descend()?)?);
            }
            Instruction::ExtensionFallback {
                name: node.tag_name().name().into(),
                present: !fallback_nodes.is_empty(),
                body: fallback,
            }
        }
        unknown => {
            return Err(Error::Static(format!(
                "unknown XSLT instruction xsl:{unknown}"
            )));
        }
    })
}

fn push_with_param(
    parameters: &mut Vec<WithParam>,
    names: &mut HashSet<ExpandedName>,
    node: roxmltree::Node<'_, '_>,
    context: CompileContext,
) -> Result<()> {
    let variable = compile_variable(node, context)?;
    if !names.insert(variable.name.clone()) {
        return Err(Error::Static(format!(
            "duplicate xsl:with-param binding `{}`",
            variable.name.local
        )));
    }
    parameters.push(WithParam { variable });
    Ok(())
}

fn is_xml_whitespace_only(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
}

fn trim_xml_whitespace(value: &str) -> &str {
    value.trim_matches(|character| matches!(character, ' ' | '\t' | '\r' | '\n'))
}

fn is_ignorable_stylesheet_text(node: roxmltree::Node<'_, '_>) -> bool {
    node.is_text()
        && node.text().is_some_and(is_xml_whitespace_only)
        && !stylesheet_space_is_preserved(node)
}

fn is_ignorable_stylesheet_child(node: roxmltree::Node<'_, '_>) -> bool {
    !node.is_element() && (!node.is_text() || is_ignorable_stylesheet_text(node))
}

fn require_empty_instruction(node: roxmltree::Node<'_, '_>) -> Result<()> {
    if node.children().any(|child| {
        child.is_element() || (child.is_text() && !is_ignorable_stylesheet_text(child))
    }) {
        return Err(Error::Static(format!(
            "xsl:{} must be empty",
            node.tag_name().name()
        )));
    }
    Ok(())
}

fn validate_instruction_attributes(node: roxmltree::Node<'_, '_>, forward: bool) -> Result<()> {
    let allowed: &[&str] = match node.tag_name().name() {
        "apply-templates" => &["select", "mode"],
        "apply-imports" | "choose" | "otherwise" | "comment" | "fallback" => &[],
        "call-template" | "processing-instruction" => &["name"],
        "for-each" | "copy-of" => &["select"],
        "if" | "when" => &["test"],
        "value-of" => &["select", "disable-output-escaping"],
        "copy" => &["use-attribute-sets"],
        "element" => &["name", "namespace", "use-attribute-sets"],
        "attribute" => &["name", "namespace"],
        "text" => &["disable-output-escaping"],
        "number" => &[
            "value",
            "count",
            "from",
            "level",
            "format",
            "lang",
            "letter-value",
            "grouping-separator",
            "grouping-size",
        ],
        "variable" | "param" | "with-param" => &["name", "select"],
        "message" => &["terminate"],
        "sort" => &["select", "lang", "data-type", "order", "case-order"],
        _ => return Ok(()),
    };
    reject_unknown_attributes(node, allowed, forward)
}

fn reject_unknown_attributes(
    node: roxmltree::Node<'_, '_>,
    allowed: &[&str],
    forward: bool,
) -> Result<()> {
    for attribute in node.attributes() {
        if attribute.namespace().is_none() && !allowed.contains(&attribute.name()) && !forward {
            return Err(Error::Static(format!(
                "xsl:{} does not permit unqualified attribute {}",
                node.tag_name().name(),
                attribute.name()
            )));
        }
    }
    Ok(())
}

fn validate_top_level_declaration_attributes(
    root: roxmltree::Node<'_, '_>,
    forward: bool,
) -> Result<()> {
    // XSLT 1.0 §2.2 and each declaration's Element Syntax define closed unqualified
    // attribute sets; forward-compatible behavior is specified by §2.5:
    // https://www.w3.org/TR/1999/REC-xslt-19991116
    reject_unknown_attributes(
        root,
        &[
            "version",
            "id",
            "extension-element-prefixes",
            "exclude-result-prefixes",
        ],
        forward,
    )?;
    for node in root.children().filter(roxmltree::Node::is_element) {
        let allowed: Option<&[&str]> = if node.has_tag_name((EXSLT_FUNCTIONS_NS, "function")) {
            Some(&["name"])
        } else if node.tag_name().namespace() == Some(XSLT_NS) {
            match node.tag_name().name() {
                "import" | "include" => Some(&["href"]),
                "template" => Some(&["match", "name", "priority", "mode"]),
                "variable" | "param" => Some(&["name", "select"]),
                "output" => Some(&[
                    "method",
                    "version",
                    "encoding",
                    "omit-xml-declaration",
                    "standalone",
                    "doctype-public",
                    "doctype-system",
                    "cdata-section-elements",
                    "indent",
                    "media-type",
                ]),
                "strip-space" | "preserve-space" => Some(&["elements"]),
                "key" => Some(&["name", "match", "use"]),
                "decimal-format" => Some(&[
                    "name",
                    "decimal-separator",
                    "grouping-separator",
                    "infinity",
                    "minus-sign",
                    "NaN",
                    "percent",
                    "per-mille",
                    "zero-digit",
                    "digit",
                    "pattern-separator",
                ]),
                "namespace-alias" => Some(&["stylesheet-prefix", "result-prefix"]),
                "attribute-set" => Some(&["name", "use-attribute-sets"]),
                _ => None,
            }
        } else {
            None
        };
        if let Some(allowed) = allowed {
            reject_unknown_attributes(node, allowed, forward)?;
        }
    }
    Ok(())
}

fn validate_exslt_function_result_structure(function: roxmltree::Node<'_, '_>) -> Result<()> {
    // EXSLT func:result v3, paragraphs after "Element Syntax", require no following element
    // except xsl:fallback and forbid nesting in func:result or variable bindings:
    // https://exslt.github.io/func/result/
    for result in function
        .descendants()
        .filter(|node| node.has_tag_name((EXSLT_FUNCTIONS_NS, "result")))
    {
        if result
            .next_siblings()
            .skip(1)
            .filter(roxmltree::Node::is_element)
            .any(|sibling| !sibling.has_tag_name((XSLT_NS, "fallback")))
        {
            return Err(Error::Static(
                "func:result may only be followed by xsl:fallback elements".into(),
            ));
        }
        for ancestor in result
            .ancestors()
            .skip(1)
            .take_while(|ancestor| ancestor.id() != function.id())
        {
            if ancestor.has_tag_name((EXSLT_FUNCTIONS_NS, "result")) {
                return Err(Error::Static(
                    "func:result cannot occur inside another func:result".into(),
                ));
            }
            if ancestor.has_tag_name((XSLT_NS, "variable"))
                || ancestor.has_tag_name((XSLT_NS, "param"))
            {
                return Err(Error::Static(
                    "func:result cannot occur inside an xsl:variable or xsl:param binding".into(),
                ));
            }
        }
    }
    Ok(())
}

fn is_extension_element(node: roxmltree::Node<'_, '_>) -> Result<bool> {
    let Some(namespace) = node.tag_name().namespace() else {
        return Ok(false);
    };
    for ancestor in node.ancestors().filter(roxmltree::Node::is_element) {
        let Some(prefixes) = ancestor
            .attribute((XSLT_NS, "extension-element-prefixes"))
            .or_else(|| {
                (ancestor.tag_name().namespace() == Some(XSLT_NS))
                    .then(|| ancestor.attribute("extension-element-prefixes"))
                    .flatten()
            })
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
    let context = context.with_literal_version(node)?;
    validate_literal_result_attributes(node, context.forward)?;
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
                value: parse_avt(a.value(), node, &context)?,
            })
        })
        .collect::<Result<_>>()?;
    let excluded = excluded_result_namespaces(node, context.forward)?;
    let used_namespaces = std::iter::once(node.tag_name().namespace())
        .chain(node.attributes().map(|attribute| attribute.namespace()))
        .flatten()
        .collect::<HashSet<_>>();
    let namespaces = node
        .namespaces()
        .filter(|n| n.uri() != XSLT_NS)
        .filter(|namespace| {
            used_namespaces.contains(namespace.uri()) || !excluded.contains(namespace.uri())
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

fn validate_literal_result_attributes(
    node: roxmltree::Node<'_, '_>,
    forward_compatible: bool,
) -> Result<()> {
    // XSLT 1.0 section 7.1.1 defines the complete set of XSLT-namespace control attributes on a
    // literal result element; section 2.5 permits unknown attributes only in FCP.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#literal-result-element
    // https://www.w3.org/TR/1999/REC-xslt-19991116#forwards
    const ALLOWED: &[&str] = &[
        "version",
        "extension-element-prefixes",
        "exclude-result-prefixes",
        "use-attribute-sets",
    ];
    if forward_compatible {
        return Ok(());
    }
    if let Some(attribute) = node.attributes().find(|attribute| {
        attribute.namespace() == Some(XSLT_NS) && !ALLOWED.contains(&attribute.name())
    }) {
        return Err(Error::Static(format!(
            "literal result element {} does not permit xsl:{}",
            node.tag_name().name(),
            attribute.name()
        )));
    }
    Ok(())
}

fn excluded_result_namespaces(
    node: roxmltree::Node<'_, '_>,
    forward_compatible: bool,
) -> Result<HashSet<String>> {
    let mut excluded = HashSet::new();
    if node.ancestors().any(|ancestor| {
        ancestor.has_tag_name((XSLT_NS, "variable")) || ancestor.has_tag_name((XSLT_NS, "param"))
    }) && let Some(stylesheet) = node.ancestors().find(|ancestor| {
        ancestor.has_tag_name((XSLT_NS, "stylesheet"))
            || ancestor.has_tag_name((XSLT_NS, "transform"))
    }) {
        for function in stylesheet
            .children()
            .filter(|child| child.has_tag_name((EXSLT_FUNCTIONS_NS, "function")))
        {
            if let Some((prefix, _)) = function
                .attribute("name")
                .and_then(|name| name.split_once(':'))
                && let Some(namespace) = function.lookup_namespace_uri(Some(prefix))
            {
                excluded.insert(namespace.to_owned());
            }
        }
    }
    let mut ancestors = node
        .ancestors()
        .filter(roxmltree::Node::is_element)
        .collect::<Vec<_>>();
    ancestors.reverse();
    for ancestor in ancestors {
        if ancestor.has_tag_name((EXSLT_FUNCTIONS_NS, "function"))
            && let Some((prefix, _)) = ancestor
                .attribute("name")
                .and_then(|name| name.split_once(':'))
            && let Some(namespace) = ancestor.lookup_namespace_uri(Some(prefix))
        {
            // libexslt treats the namespace naming a stylesheet-defined function
            // as implementation vocabulary, not as a namespace to copy into its
            // result-tree fragment.
            excluded.insert(namespace.to_owned());
        }
        for attribute in ["exclude-result-prefixes", "extension-element-prefixes"] {
            visit_namespace_prefix_attribute(
                ancestor,
                attribute,
                forward_compatible,
                |namespace| {
                    excluded.insert(namespace.to_owned());
                },
            )?;
        }
    }
    Ok(excluded)
}

fn validate_namespace_prefix_attributes(
    node: roxmltree::Node<'_, '_>,
    forward_compatible: bool,
) -> Result<()> {
    for attribute in ["exclude-result-prefixes", "extension-element-prefixes"] {
        visit_namespace_prefix_attribute(node, attribute, forward_compatible, |_| {})?;
    }
    Ok(())
}

fn visit_namespace_prefix_attribute(
    node: roxmltree::Node<'_, '_>,
    attribute: &str,
    forward_compatible: bool,
    mut visit: impl FnMut(&str),
) -> Result<()> {
    let value = if node.tag_name().namespace() == Some(XSLT_NS) {
        node.attribute(attribute)
    } else {
        node.attribute((XSLT_NS, attribute))
    };
    let Some(value) = value else {
        return Ok(());
    };
    if value.split_ascii_whitespace().any(|token| token == "#all") {
        // XSLT 1.0 section 7.1.1 permits QName tokens and #default only. Section 2.5
        // makes an unsupported optional attribute value ignorable as a whole in FCP.
        // https://www.w3.org/TR/1999/REC-xslt-19991116#literal-result-element
        // https://www.w3.org/TR/1999/REC-xslt-19991116#forwards
        if forward_compatible {
            return Ok(());
        }
        return Err(Error::Static(format!(
            "{attribute} does not permit #all in XSLT 1.0"
        )));
    }
    for token in value.split_ascii_whitespace() {
        let prefix = (token != "#default").then_some(token);
        let namespace = node
            .lookup_namespace_uri(prefix)
            .ok_or_else(|| Error::Static(format!("{attribute} prefix {token} is not bound")))?;
        visit(namespace);
    }
    Ok(())
}
fn validate_local_binding_scope(node: roxmltree::Node<'_, '_>, name: &ExpandedName) -> Result<()> {
    if !node.has_tag_name((XSLT_NS, "variable")) && !node.has_tag_name((XSLT_NS, "param")) {
        return Ok(());
    }
    let Some(parent) = node.parent_element() else {
        return Ok(());
    };
    if parent.has_tag_name((XSLT_NS, "stylesheet")) || parent.has_tag_name((XSLT_NS, "transform")) {
        return Ok(());
    }

    let mut cursor = node;
    loop {
        for sibling in cursor
            .prev_siblings()
            .skip(1)
            .filter(roxmltree::Node::is_element)
        {
            if (sibling.has_tag_name((XSLT_NS, "variable"))
                || sibling.has_tag_name((XSLT_NS, "param")))
                && required_qname_attr(sibling, "name")? == *name
            {
                return Err(Error::Static(format!(
                    "local binding {} shadows a still-visible template variable",
                    name.local
                )));
            }
        }
        let Some(parent) = cursor.parent_element() else {
            break;
        };
        let parent_is_top_level = parent.parent_element().is_some_and(|grandparent| {
            grandparent.has_tag_name((XSLT_NS, "stylesheet"))
                || grandparent.has_tag_name((XSLT_NS, "transform"))
        });
        if parent.has_tag_name((XSLT_NS, "template"))
            || parent.has_tag_name((EXSLT_FUNCTIONS_NS, "function"))
            || parent_is_top_level
        {
            break;
        }
        cursor = parent;
    }
    Ok(())
}

fn compile_variable(node: roxmltree::Node<'_, '_>, context: CompileContext) -> Result<Variable> {
    validate_instruction_attributes(node, context.forward)?;
    let name = required_qname_attr(node, "name")?;
    validate_local_binding_scope(node, &name)?;
    let select = node
        .attribute("select")
        .map(|value| context.expression(value, node))
        .transpose()?;
    let base_uri = effective_base_uri(node, context.static_base_uri.as_deref())?;
    let content = compile_sequence(node.children(), context)?;
    if select.is_some() && !content.is_empty() {
        return Err(Error::Static(
            "variable with select cannot have content".into(),
        ));
    }
    Ok(Variable {
        name,
        select,
        content,
        base_uri,
    })
}
fn compile_sort(node: roxmltree::Node<'_, '_>, context: &CompileContext) -> Result<Sort> {
    validate_instruction_attributes(node, context.forward)?;
    require_empty_instruction(node)?;
    Ok(Sort {
        select: context.expression(node.attribute("select").unwrap_or("."), node)?,
        data_type: parse_avt(node.attribute("data-type").unwrap_or("text"), node, context)?,
        order: parse_avt(
            node.attribute("order").unwrap_or("ascending"),
            node,
            context,
        )?,
        case_order: node
            .attribute("case-order")
            .map(|value| parse_avt(value, node, context))
            .transpose()?,
        lang: node
            .attribute("lang")
            .map(|value| parse_avt(value, node, context))
            .transpose()?,
    })
}
fn compile_number(
    node: roxmltree::Node<'_, '_>,
    context: &CompileContext,
) -> Result<NumberInstruction> {
    validate_instruction_attributes(node, context.forward)?;
    require_empty_instruction(node)?;
    let level = node.attribute("level").unwrap_or("single");
    if !matches!(level, "single" | "multiple" | "any") {
        return Err(Error::Static(format!(
            "xsl:number level must be single, multiple, or any, got `{level}`"
        )));
    }
    Ok(NumberInstruction {
        value: node
            .attribute("value")
            .map(|value| context.expression(value, node))
            .transpose()?,
        count: node
            .attribute("count")
            .map(|v| Pattern::new(v, node))
            .transpose()?,
        from: node
            .attribute("from")
            .map(|v| Pattern::new(v, node))
            .transpose()?,
        level: level.into(),
        format: parse_avt(node.attribute("format").unwrap_or("1"), node, context)?,
        lang: node
            .attribute("lang")
            .map(|value| parse_avt(value, node, context))
            .transpose()?,
        letter_value: node
            .attribute("letter-value")
            .map(|value| parse_avt(value, node, context))
            .transpose()?,
        grouping_separator: node
            .attribute("grouping-separator")
            .map(|value| parse_avt(value, node, context))
            .transpose()?,
        grouping_size: node
            .attribute("grouping-size")
            .map(|value| parse_avt(value, node, context))
            .transpose()?,
        forward_compatible: context.forward,
    })
}
fn parse_avt(
    value: &str,
    node: roxmltree::Node<'_, '_>,
    context: &CompileContext,
) -> Result<AttributeValueTemplate> {
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
                // XPath 1.0 section 3.7 recognizes only XML S around tokens; Unicode trim
                // would silently reinterpret NBSP and other expression characters as layout.
                // https://www.w3.org/TR/1999/REC-xpath-19991116#exprlex
                parts.push(AvtPart::Expression(
                    context.expression(trim_xml_whitespace(&expression), node)?,
                ));
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
fn merge_output_property<T>(
    slot: &mut T,
    slot_precedence: &mut Option<usize>,
    incoming: T,
    precedence: usize,
) -> bool {
    match *slot_precedence {
        Some(existing) if existing > precedence => false,
        Some(existing) if existing == precedence => {
            // XSLT 1.0 section 16 permits recovery from a surviving conflict by selecting the
            // value occurring last, matching libxslt's compatibility contract.
            // https://www.w3.org/TR/1999/REC-xslt-19991116#output
            *slot = incoming;
            true
        }
        _ => {
            *slot = incoming;
            *slot_precedence = Some(precedence);
            true
        }
    }
}

fn merge_output(
    out: &mut OutputDefinition,
    properties: &mut OutputPropertyPrecedence,
    node: roxmltree::Node<'_, '_>,
    precedence: usize,
) -> Result<()> {
    // XSLT 1.0 section 16 selects each scalar output property at highest import precedence;
    // equal-precedence recovery selects the last value, while CDATA element names form a union.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#output
    if let Some(method) = node.attribute("method") {
        let method = match method {
            "xml" => OutputMethod::Xml,
            "html" => OutputMethod::Html,
            "text" => OutputMethod::Text,
            _ => return Err(Error::Static(format!("unsupported output method {method}"))),
        };
        if merge_output_property(&mut out.method, &mut properties.method, method, precedence) {
            out.method_explicit = true;
        }
    }
    if let Some(v) = node.attribute("version") {
        merge_output_property(
            &mut out.version,
            &mut properties.version,
            Some(v.into()),
            precedence,
        );
    }
    if let Some(v) = node.attribute("encoding")
        && merge_output_property(
            &mut out.encoding,
            &mut properties.encoding,
            v.into(),
            precedence,
        )
    {
        out.encoding_explicit = true;
    }
    if let Some(v) = node.attribute("omit-xml-declaration") {
        merge_output_property(
            &mut out.omit_xml_declaration,
            &mut properties.omit_xml_declaration,
            yes_no(Some(v))?,
            precedence,
        );
    }
    if let Some(v) = node.attribute("standalone") {
        merge_output_property(
            &mut out.standalone,
            &mut properties.standalone,
            Some(yes_no(Some(v))?),
            precedence,
        );
    }
    if let Some(v) = node.attribute("doctype-public") {
        merge_output_property(
            &mut out.doctype_public,
            &mut properties.doctype_public,
            Some(v.into()),
            precedence,
        );
    }
    if let Some(v) = node.attribute("doctype-system") {
        merge_output_property(
            &mut out.doctype_system,
            &mut properties.doctype_system,
            Some(v.into()),
            precedence,
        );
    }
    if let Some(v) = node.attribute("indent")
        && merge_output_property(
            &mut out.indent,
            &mut properties.indent,
            yes_no(Some(v))?,
            precedence,
        )
    {
        out.indent_explicit = true;
    }
    if let Some(v) = node.attribute("media-type") {
        merge_output_property(
            &mut out.media_type,
            &mut properties.media_type,
            Some(v.into()),
            precedence,
        );
    }
    if let Some(v) = node.attribute("cdata-section-elements") {
        for name in v.split_ascii_whitespace() {
            out.cdata_section_elements
                .insert(required_cdata_output_qname(node, name)?);
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
            if !is_ncname(prefix) || (local != "*" && !is_ncname(local)) {
                return Err(Error::Static(format!(
                    "invalid whitespace-rule name test `{value}`"
                )));
            }
            let namespace = node
                .lookup_namespace_uri(Some(prefix))
                .ok_or_else(|| Error::Static(format!("unbound prefix {prefix}")))?;
            Ok(Self {
                namespace: NamespaceTest::Exact(namespace.into()),
                local: (local != "*").then(|| local.into()),
            })
        } else {
            if !is_ncname(value) {
                return Err(Error::Static(format!(
                    "invalid whitespace-rule name test `{value}`"
                )));
            }
            Ok(Self {
                namespace: NamespaceTest::None,
                local: Some(value.into()),
            })
        }
    }
}
impl DecimalFormat {
    fn parse(node: roxmltree::Node<'_, '_>, precedence: usize) -> Result<Self> {
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
        let format = Self {
            name: optional_qname_attr(node, "name")?,
            precedence,
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
        };
        if unicode_decimal_value(format.zero_digit) != Some(0) {
            return Err(Error::Static(
                "xsl:decimal-format zero-digit must have Unicode decimal value zero".into(),
            ));
        }
        let syntax = [
            ("decimal-separator", format.decimal_separator),
            ("grouping-separator", format.grouping_separator),
            ("percent", format.percent),
            ("per-mille", format.per_mille),
            ("zero-digit", format.zero_digit),
            ("digit", format.digit),
            ("pattern-separator", format.pattern_separator),
        ];
        for (index, (name, value)) in syntax.iter().enumerate() {
            if let Some((other, _)) = syntax[index + 1..]
                .iter()
                .find(|(_, candidate)| candidate == value)
            {
                return Err(Error::Static(format!(
                    "xsl:decimal-format {name} and {other} must be distinct"
                )));
            }
        }
        Ok(format)
    }
}

fn validate_key_dependency_expression(attribute: &str, source: &str) -> Result<()> {
    if contains_variable_reference(source) {
        return Err(Error::Static(format!(
            "xsl:key {attribute} must not contain a variable reference"
        )));
    }
    if !crate::expression::unprefixed_function_calls(source, "key").is_empty() {
        return Err(Error::Static(format!(
            "xsl:key {attribute} must not call key()"
        )));
    }
    Ok(())
}
impl AttributeSet {
    fn parse(
        node: roxmltree::Node<'_, '_>,
        context: CompileContext,
        precedence: usize,
        order: usize,
    ) -> Result<Self> {
        if node
            .children()
            .any(|child| child.is_text() && !is_ignorable_stylesheet_text(child))
        {
            return Err(Error::Static(
                "xsl:attribute-set may contain only xsl:attribute".into(),
            ));
        }
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
            precedence,
            order,
        })
    }
}
fn namespaces(node: roxmltree::Node<'_, '_>) -> Vec<(String, String)> {
    node.namespaces()
        .filter_map(|n| n.name().map(|p| (p.into(), n.uri().into())))
        .collect()
}

fn computed_element_namespaces(node: roxmltree::Node<'_, '_>) -> Vec<(String, String)> {
    node.namespaces()
        .map(|namespace| {
            (
                namespace.name().unwrap_or_default().into(),
                namespace.uri().into(),
            )
        })
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
        if !is_ncname(prefix) || !is_ncname(local) || local.contains(':') {
            return Err(Error::Static(format!("invalid QName {value}")));
        }
        let uri = node
            .lookup_namespace_uri(Some(prefix))
            .ok_or_else(|| Error::Static(format!("unbound prefix {prefix}")))?;
        if uri.starts_with('#') {
            return Err(Error::Static(format!(
                "QName {value} uses fragment-only namespace name `{uri}`"
            )));
        }
        Ok(ExpandedName::new(Some(uri), local))
    } else {
        if !is_ncname(value) {
            return Err(Error::Static(format!("invalid QName {value}")));
        }
        Ok(ExpandedName::new(None::<String>, value))
    }
}

fn required_cdata_output_qname(node: roxmltree::Node<'_, '_>, value: &str) -> Result<ExpandedName> {
    let mut name = required_qname(node, value)?;
    // XSLT 1.0 section 16.1 makes cdata-section-elements the explicit exception to the
    // stylesheet QName rule: its unprefixed names use the xsl:output default namespace.
    if !value.contains(':') {
        name.namespace = node.lookup_namespace_uri(None).map(str::to_owned);
    }
    Ok(name)
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
