use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet, VecDeque};
use std::rc::Rc;
use std::sync::{Arc, Weak};

use crate::budget::{COMPILE_RECURSION_DEPTH_CEILING, ensure};
use crate::lexical::{
    ValidatedXPointerFragment, is_ncname, is_ncname_char, is_ncname_start, is_xml_whitespace,
    strip_xpath_attribute_axis, trim_xml_whitespace, unicode_decimal_value, xpath_string_literal,
};
use crate::model::{normalized_xml_id, parser_workspace_bytes, prepare_xml_frontend_bounded};
use crate::resolver::decode_resource;
use crate::{
    BudgetKind, CompileBudget, Document, Error, ExpandedName, Namespace, OutputDefinition,
    OutputMethod, ResolvePurpose, ResolvedResource, Resolver, ResourceIdentity, Result,
};

pub(crate) const XSLT_NS: &str = "http://www.w3.org/1999/XSL/Transform";
pub(crate) const EXSLT_FUNCTIONS_NS: &str = "http://exslt.org/functions";
const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
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
        self.compile_with_workspace(xml, base_uri, 0)
    }

    fn compile_with_workspace(
        &self,
        xml: &str,
        base_uri: Option<&str>,
        decoded_workspace: usize,
    ) -> Result<Stylesheet> {
        ensure(
            BudgetKind::StylesheetBytes,
            self.budget.stylesheet_bytes,
            xml.len(),
        )?;
        let mut state = CompileState::new(self.budget, xml.len());
        state.charge_owned(decoded_workspace)?;
        self.compile_module(xml, base_uri, None, None, &mut state, 1)?;
        let principal_document = parse_semantic_document_metered(xml, base_uri, &mut state)?;
        let principal_base_uri = clone_compile_string(base_uri, &mut state)?;
        let mut stylesheet = state.finish()?;
        stylesheet.principal_document = principal_document;
        stylesheet.principal_base_uri = principal_base_uri;
        Ok(stylesheet)
    }

    /// Decode and compile a complete stylesheet graph from external XML bytes.
    pub fn compile_bytes(&self, bytes: &[u8], base_uri: Option<&str>) -> Result<Stylesheet> {
        ensure(
            BudgetKind::StylesheetBytes,
            self.budget.stylesheet_bytes,
            bytes.len(),
        )?;
        let decoded_limit = self.budget.stylesheet_bytes.min(self.budget.owned_bytes);
        let xml =
            xml_sec_xml_input::decode_xml_bounded(bytes, None, decoded_limit).map_err(|error| {
                match error {
                    xml_sec_xml_input::Error::DecodedLimit { actual, .. }
                        if self.budget.owned_bytes <= self.budget.stylesheet_bytes =>
                    {
                        Error::Budget {
                            kind: BudgetKind::OwnedBytes,
                            limit: self.budget.owned_bytes,
                            actual,
                        }
                    }
                    xml_sec_xml_input::Error::DecodedLimit { actual, .. } => Error::Budget {
                        kind: BudgetKind::StylesheetBytes,
                        limit: self.budget.stylesheet_bytes,
                        actual,
                    },
                    error => Error::Xml(error.to_string()),
                }
            })?;
        let (xml, decoded_workspace) = classify_decoded_workspace(xml);
        self.compile_with_workspace(&xml, base_uri, decoded_workspace)
    }

    fn compile_module(
        &self,
        xml: &str,
        base_uri: Option<&str>,
        fragment: Option<&str>,
        inherited_precedence: Option<usize>,
        state: &mut CompileState,
        depth: usize,
    ) -> Result<()> {
        ensure(
            BudgetKind::RecursionDepth,
            state.budget.recursion_depth,
            depth,
        )?;
        with_compiler_document(xml, base_uri, state, |document, state| {
            let root = stylesheet_module_root(document, fragment)?;
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
            self.compile_effective_declarations(
                root,
                base_uri,
                local_precedence,
                forward,
                state,
                depth,
            )
        })
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
                let module = self.resolve_module(child, base_uri, ResolvePurpose::Import, state)?;
                self.enter_resource(&module.resource, state, |state| {
                    let source = resource_source(&module.resource, state)?;
                    self.compile_module(
                        source.as_str(),
                        Some(&module.resource.canonical_uri),
                        module.fragment,
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
                let module =
                    self.resolve_module(child, base_uri, ResolvePurpose::Include, state)?;
                self.enter_resource(&module.resource, state, |state| {
                    let source = resource_source(&module.resource, state)?;
                    with_frontend_document(source.as_str(), state, |document, state| {
                        let included_root = stylesheet_module_root(document, module.fragment)?;
                        match stylesheet_module_kind(included_root)? {
                            StylesheetModuleKind::Standard { forward } => {
                                validate_standard_stylesheet_content(included_root)?;
                                validate_top_level_declaration_attributes(included_root, forward)?;
                                validate_namespace_prefix_attributes(included_root, forward)?;
                                self.compile_effective_imports(
                                    included_root,
                                    Some(&module.resource.canonical_uri),
                                    state,
                                    depth + 1,
                                    saw_non_import,
                                )
                            }
                            StylesheetModuleKind::Simplified => Ok(()),
                        }
                    })
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
                let module =
                    self.resolve_module(child, base_uri, ResolvePurpose::Include, state)?;
                self.enter_resource(&module.resource, state, |state| {
                    let source = resource_source(&module.resource, state)?;
                    with_compiler_document(
                        source.as_str(),
                        Some(&module.resource.canonical_uri),
                        state,
                        |document, state| {
                            let included_root = stylesheet_module_root(document, module.fragment)?;
                            match stylesheet_module_kind(included_root)? {
                                StylesheetModuleKind::Standard {
                                    forward: included_forward,
                                } => self.compile_effective_declarations(
                                    included_root,
                                    Some(&module.resource.canonical_uri),
                                    precedence,
                                    included_forward,
                                    state,
                                    depth + 1,
                                ),
                                StylesheetModuleKind::Simplified => self
                                    .compile_literal_result_stylesheet(
                                        included_root,
                                        Some(&module.resource.canonical_uri),
                                        precedence,
                                        state,
                                        depth + 1,
                                    ),
                            }
                        },
                    )
                })?;
                continue;
            }
            self.compile_top_level(child, base_uri, precedence, forward, state, depth)?;
        }
        Ok(())
    }

    fn resolve_module<'input>(
        &self,
        node: roxmltree::Node<'input, 'input>,
        base_uri: Option<&str>,
        purpose: ResolvePurpose,
        state: &mut CompileState,
    ) -> Result<ResolvedModule<'input>> {
        // XSLT 1.0 sections 2.6.1 and 2.6.2 define include/import as EMPTY. Validate the
        // declaration before URI resolution so malformed syntax cannot cause external access.
        // https://www.w3.org/TR/1999/REC-xslt-19991116#include
        require_empty_instruction(node)?;
        let href = required_attr(node, "href")?;
        let (resource_href, fragment) = href
            .split_once('#')
            .map_or((href, None), |(resource, fragment)| {
                (resource, Some(fragment))
            });
        if fragment == Some("") {
            return Err(Error::Static(
                "stylesheet module fragment identifier must not be empty".into(),
            ));
        }
        let effective_base = effective_base_uri(node, base_uri)?;
        let request_owned_bytes =
            resolve_request_retained_bytes(resource_href, effective_base.as_deref());
        state.charge_owned(request_owned_bytes)?;
        let request = ResolveRequest {
            href: resource_href.to_owned(),
            base_uri: effective_base.clone(),
            purpose,
        };
        if let Some(resource) = state.resolved_requests.get(&request) {
            let resource = Arc::clone(resource);
            state.release_owned(request_owned_bytes);
            return Ok(ResolvedModule { resource, fragment });
        }
        state.imported_modules = state.imported_modules.saturating_add(1);
        ensure(
            BudgetKind::ImportedModules,
            state.budget.imported_modules,
            state.imported_modules,
        )?;
        let resolved = match self.resolver.resolve(crate::ResolveRequest::new(
            resource_href,
            effective_base.as_deref(),
            purpose,
        )) {
            Ok(resource) => resource,
            Err(error) => {
                state.release_owned(request_owned_bytes);
                return Err(error);
            }
        };
        let (resource, new_identity) =
            if let Some(previous) = state.resolved_identities.get(&resolved.identity) {
                if previous.as_ref() != &resolved {
                    state.release_owned(request_owned_bytes);
                    return Err(Error::StaleResource {
                        identity: resolved.identity,
                    });
                }
                (Arc::clone(previous), false)
            } else {
                state.check_stylesheet(resolved.bytes.len())?;
                state.charge_owned(new_resolved_identity_retained_bytes(&resolved))?;
                (Arc::new(resolved), true)
            };
        if !state.module_documents.contains_key(&resource.canonical_uri) {
            state.charge_owned(module_document_cache_entry_bytes(&resource.canonical_uri))?;
            let source = resource_source(&resource, state)?;
            let document = parse_semantic_document_metered(
                source.as_str(),
                Some(&resource.canonical_uri),
                state,
            )?;
            state
                .module_documents
                .insert(resource.canonical_uri.clone(), document);
        }
        if new_identity {
            state
                .resolved_identities
                .insert(resource.identity.clone(), Arc::clone(&resource));
            state.resources.push(resource.identity.clone());
        }
        state
            .resolved_requests
            .insert(request, Arc::clone(&resource));
        Ok(ResolvedModule { resource, fragment })
    }

    fn enter_resource<T>(
        &self,
        resource: &Arc<ResolvedResource>,
        state: &mut CompileState,
        compile: impl FnOnce(&mut CompileState) -> Result<T>,
    ) -> Result<T> {
        if state
            .active_resources
            .iter()
            .any(|active| active.identity == resource.identity)
        {
            return Err(Error::Static(format!(
                "stylesheet include/import cycle at {}",
                resource.canonical_uri
            )));
        }
        state.active_resources.push(Arc::clone(resource));
        let result = compile(state);
        state.active_resources.pop();
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
        let forward = stylesheet_version_is_forward_compatible(version)?;
        let order = state.next_order();
        state.templates.push(Template {
            name: None,
            pattern: Some(Pattern::new("/", root, state.workspace())?),
            mode: None,
            priority: 0.5,
            precedence,
            order,
            params: Arc::from([]),
            body: vec![compile_literal_element(
                root,
                CompileContext::new(
                    forward,
                    depth,
                    state.budget.recursion_depth,
                    base_uri,
                    state.workspace(),
                )?,
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
        if is_exslt_function_declaration(node)? {
            validate_exslt_function_result_structure(node)?;
            let context = CompileContext::new(
                forward,
                depth,
                state.budget.recursion_depth,
                base_uri,
                state.workspace(),
            )?
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
            let name = required_qname_attr(node, "name")?;
            // EXSLT func:function requires the expanded name to have a non-null namespace;
            // otherwise it could replace an XPath core function binding.
            // https://exslt.github.io/func/elements/function/index.html
            if name.namespace.is_none() {
                return Err(Error::Static(
                    "EXSLT func:function name requires a namespace prefix".into(),
                ));
            }
            state.functions.push(ExsltFunction {
                name,
                params,
                body,
                precedence,
                order,
            });
            return Ok(());
        }
        if node.tag_name().namespace() != Some(XSLT_NS) {
            if node.tag_name().namespace().is_some() || forward {
                return Ok(());
            }
            // XSLT 1.0 section 2.2 permits extension top-level elements only when their
            // expanded name has a non-null namespace URI. Section 2.5 separately requires
            // unknown top-level elements to be ignored during forwards-compatible processing.
            // https://www.w3.org/TR/1999/REC-xslt-19991116#stylesheet-element
            return Err(Error::Static(
                "non-XSLT top-level elements require a namespace".into(),
            ));
        }
        match node.tag_name().name() {
            "template" => {
                let name = optional_qname_attr(node, "name")?;
                let patterns = node
                    .attribute("match")
                    .map(|value| Pattern::template_branches(value, node, state.workspace()))
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
                    .transpose()?
                    .filter(|_| !patterns.is_empty());
                // XSLT 1.0 sections 5.5 and 6 define priority for template-rule conflict
                // resolution, but explicitly make it irrelevant to named-template invocation.
                // Validate the lexical value above, then discard it for a named-only template.
                // https://www.w3.org/TR/1999/REC-xslt-19991116#named-templates
                let mode = optional_qname_attr(node, "mode")?;
                // XSLT 1.0 section 5.7 forbids mode when the template has no match rule.
                // https://www.w3.org/TR/1999/REC-xslt-19991116#modes
                if patterns.is_empty() && mode.is_some() {
                    return Err(Error::Static(
                        "xsl:template mode requires a match attribute".into(),
                    ));
                }
                let context = CompileContext::new(
                    forward,
                    depth,
                    state.budget.recursion_depth,
                    base_uri,
                    state.workspace(),
                )?;
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
                let body: Arc<[Instruction]> = compile_sequence(children, context)?;
                let params: Arc<[Variable]> = params.into();
                let order = state.next_order();
                if patterns.is_empty() {
                    state.templates.push(Template {
                        name,
                        pattern: None,
                        mode,
                        priority: 0.0,
                        precedence,
                        order,
                        params,
                        body,
                    });
                } else {
                    let pattern_buffer_bytes = patterns.capacity() * std::mem::size_of::<Pattern>();
                    for (index, pattern) in patterns.into_iter().enumerate() {
                        state.templates.push(Template {
                            name: (index == 0).then(|| name.clone()).flatten(),
                            priority: match explicit_priority {
                                Some(priority) => priority,
                                None => pattern.default_priority(state.workspace())?,
                            },
                            pattern: Some(pattern),
                            mode: mode.clone(),
                            precedence,
                            order,
                            params: Arc::clone(&params),
                            body: Arc::clone(&body),
                        });
                    }
                    state.workspace().release(pattern_buffer_bytes);
                }
            }
            "variable" | "param" => {
                let variable = compile_variable(
                    node,
                    CompileContext::new(
                        forward,
                        depth,
                        state.budget.recursion_depth,
                        base_uri,
                        state.workspace(),
                    )?,
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
                forward,
            )?,
            "strip-space" | "preserve-space" => {
                // XSLT 1.0 section 3.4 gives both declarations an EMPTY content model.
                // https://www.w3.org/TR/1999/REC-xslt-19991116#strip
                require_empty_instruction(node)?;
                let preserve = node.tag_name().name() == "preserve-space";
                let elements = required_attr(node, "elements")?;
                let mut name_tests = elements.split_ascii_whitespace().peekable();
                if name_tests.peek().is_none() {
                    return Err(Error::Static(format!(
                        "xsl:{} elements must contain at least one name test",
                        node.tag_name().name()
                    )));
                }
                for token in name_tests {
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
                // XSLT 1.0 section 12.2 defines xsl:key with an EMPTY content model.
                // https://www.w3.org/TR/1999/REC-xslt-19991116#key
                require_empty_instruction(node)?;
                let match_pattern = required_attr(node, "match")?;
                let use_expression = required_attr(node, "use")?;
                validate_key_dependency_expression(
                    "match",
                    match_pattern,
                    state.workspace().pending_source(match_pattern, node),
                )?;
                validate_key_dependency_expression(
                    "use",
                    use_expression,
                    state.workspace().pending_source(use_expression, node),
                )?;
                state.keys.push(KeyDeclaration {
                    name: required_qname_attr(node, "name")?,
                    match_pattern: Pattern::new(match_pattern, node, state.workspace())?,
                    use_expression: Expression::new(
                        use_expression,
                        node,
                        base_uri,
                        state.budget.recursion_depth,
                        state.workspace(),
                    )?,
                });
            }
            "decimal-format" => {
                // XSLT 1.0 section 12.3 defines xsl:decimal-format as EMPTY.
                // https://www.w3.org/TR/1999/REC-xslt-19991116#format-number
                require_empty_instruction(node)?;
                let format = DecimalFormat::parse(node, precedence)?;
                if let Some(existing) = state.decimal_formats.iter_mut().find(|existing| {
                    existing.name == format.name && existing.precedence == format.precedence
                }) {
                    existing.merge(format)?;
                } else {
                    state.decimal_formats.push(format);
                }
            }
            "namespace-alias" => {
                // XSLT 1.0 section 7.1.1 and its element syntax define this declaration as
                // EMPTY. Validate before parsing and merging its namespace mapping.
                // https://www.w3.org/TR/1999/REC-xslt-19991116#namespace-alias
                require_empty_instruction(node)?;
                merge_namespace_alias(
                    &mut state.namespace_aliases,
                    &mut state.namespace_alias_index,
                    parse_namespace_alias(node, precedence)?,
                )?;
            }
            "attribute-set" => {
                let order = state.next_order();
                state.attribute_sets.push(AttributeSet::parse(
                    node,
                    CompileContext::new(
                        forward,
                        depth,
                        state.budget.recursion_depth,
                        base_uri,
                        state.workspace(),
                    )?,
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

fn clone_compile_string(value: Option<&str>, state: &mut CompileState) -> Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    state.charge_owned(value.len())?;
    let mut owned = String::new();
    if owned.try_reserve_exact(value.len()).is_err() {
        state.release_owned(value.len());
        return Err(Error::Budget {
            kind: BudgetKind::OwnedBytes,
            limit: state.budget.owned_bytes,
            actual: usize::MAX,
        });
    }
    let capacity = owned.capacity();
    if capacity > value.len() {
        if let Err(error) = state.charge_owned(capacity - value.len()) {
            state.release_owned(value.len());
            return Err(error);
        }
    } else {
        state.release_owned(value.len() - capacity);
    }
    owned.push_str(value);
    Ok(Some(owned))
}

fn classify_decoded_workspace(xml: Cow<'_, str>) -> (Cow<'_, str>, usize) {
    let workspace = match &xml {
        Cow::Owned(xml) => xml.capacity(),
        Cow::Borrowed(_) => 0,
    };
    (xml, workspace)
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
    pub(crate) named_template_index: Arc<HashMap<ExpandedName, usize>>,
    pub(crate) globals: Arc<[GlobalVariable]>,
    pub(crate) output: OutputDefinition,
    pub(crate) whitespace: Arc<[(NameTest, bool, usize, usize)]>,
    pub(crate) keys: Arc<[KeyDeclaration]>,
    pub(crate) key_name_indices: Arc<[usize]>,
    pub(crate) decimal_formats: Arc<[DecimalFormat]>,
    pub(crate) namespace_aliases: Arc<[NamespaceAlias]>,
    pub(crate) namespace_alias_index: Arc<HashMap<Arc<str>, usize>>,
    pub(crate) default_namespace_alias: Option<usize>,
    pub(crate) attribute_sets: Arc<[AttributeSet]>,
    pub(crate) functions: Arc<[ExsltFunction]>,
    pub(crate) function_names: Arc<HashSet<ExpandedName>>,
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
    pub params: Arc<[Variable]>,
    pub body: InstructionSequence,
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
    pub body: InstructionSequence,
    pub precedence: usize,
    pub order: usize,
}
#[derive(Debug, Clone)]
pub(crate) struct Variable {
    pub name: ExpandedName,
    pub select: Option<Expression>,
    pub content: InstructionSequence,
    pub base_uri: Option<String>,
}
#[derive(Debug, Clone)]
pub(crate) struct Expression {
    pub source: String,
    pub namespaces: Arc<Vec<(String, String)>>,
    /// Expanded references let execution initialize only globals on the reached XPath path.
    pub variable_references: Arc<[ExpandedName]>,
    /// Static base of the stylesheet module that owns this expression.
    pub static_base_uri: Option<Arc<str>>,
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
    pub forward_compatible: bool,
}
#[derive(Debug, Clone)]
pub(crate) struct WithParam {
    pub variable: Variable,
}
pub(crate) type InstructionSequence = Arc<[Instruction]>;

#[derive(Debug, Clone)]
pub(crate) enum Instruction {
    Text(String, bool),
    LiteralElement {
        // XSLT 1.0 section 3.2 assigns a constructed node the base URI of its creating
        // stylesheet instruction: https://www.w3.org/TR/1999/REC-xslt-19991116#base-uri
        base_uri: Option<String>,
        name: ExpandedName,
        prefix: Option<String>,
        attributes: Vec<LiteralAttribute>,
        namespaces: Vec<Namespace>,
        children: InstructionSequence,
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
        body: InstructionSequence,
    },
    If {
        test: Expression,
        body: InstructionSequence,
    },
    Choose {
        branches: Vec<(Expression, InstructionSequence)>,
        otherwise: InstructionSequence,
    },
    ValueOf {
        select: Expression,
        disable_output_escaping: bool,
    },
    CopyOf {
        select: Expression,
        base_uri: Option<String>,
    },
    Copy {
        base_uri: Option<String>,
        body: InstructionSequence,
        attribute_sets: Vec<ExpandedName>,
    },
    Element {
        // Computed and literal result elements share the same creating-instruction rule.
        base_uri: Option<String>,
        name: AttributeValueTemplate,
        namespace: Option<AttributeValueTemplate>,
        namespaces: Vec<(String, String)>,
        body: InstructionSequence,
        attribute_sets: Vec<ExpandedName>,
    },
    Attribute {
        name: AttributeValueTemplate,
        namespace: Option<AttributeValueTemplate>,
        namespaces: Vec<(String, String)>,
        body: InstructionSequence,
    },
    Comment(InstructionSequence),
    Processing {
        name: AttributeValueTemplate,
        body: InstructionSequence,
    },
    Number(NumberInstruction),
    Variable(Variable),
    Message {
        terminate: bool,
        body: InstructionSequence,
    },
    SecondaryOutput {
        uri: AttributeValueTemplate,
        properties: Vec<(String, AttributeValueTemplate)>,
        body: InstructionSequence,
    },
    ExtensionFallback {
        name: String,
        present: bool,
        body: InstructionSequence,
    },
    CompatibilityComment(String),
    FunctionResult {
        select: Option<Expression>,
        content: InstructionSequence,
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
    pub attributes: InstructionSequence,
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
    pub(crate) specified: u16,
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
        max_depth: usize,
        workspace: CompileWorkspace<'_>,
    ) -> Result<Self> {
        workspace.retain(namespace_copy_bytes(node, true, workspace)?)?;
        Self::new_with_namespaces(
            source,
            node,
            Arc::new(namespaces(node)),
            static_base_uri,
            max_depth,
            workspace,
        )
    }

    fn new_with_namespaces(
        source: &str,
        node: roxmltree::Node<'_, '_>,
        namespaces: Arc<Vec<(String, String)>>,
        static_base_uri: Option<&str>,
        max_depth: usize,
        workspace: CompileWorkspace<'_>,
    ) -> Result<Self> {
        let static_base_uri = effective_base_uri(node, static_base_uri)?.map(Arc::from);
        Self::new_with_namespaces_and_base(
            source,
            namespaces,
            static_base_uri,
            max_depth,
            workspace,
            workspace.pending_source(source, node),
        )
    }

    fn new_with_namespaces_and_base(
        source: &str,
        namespaces: Arc<Vec<(String, String)>>,
        static_base_uri: Option<Arc<str>>,
        max_depth: usize,
        workspace: CompileWorkspace<'_>,
        validation_workspace: CompileWorkspace<'_>,
    ) -> Result<Self> {
        validate_xpath_prefixes(source, &namespaces, validation_workspace)?;
        {
            let (normalized, workspace) = validation_workspace.normalize(source)?;
            // This AST is only syntax-checked, never evaluated. Logical-document root rewriting
            // belongs to execution; adding those synthetic steps here wastes memory and depth.
            let parsed = workspace.parse_xpath(&normalized, source, false)?;
            ensure(BudgetKind::RecursionDepth, max_depth, parsed.ast_depth())?;
        }
        if validation_workspace.occupied == workspace.occupied {
            workspace.retain(source.len())?;
        }
        let variable_references = referenced_variables_bounded(source, &namespaces, workspace)?;
        Ok(Self {
            source: source.to_owned(),
            namespaces,
            static_base_uri,
            variable_references,
        })
    }

    pub(crate) fn derived(&self, source: impl Into<String>) -> Self {
        Self::from_parts(
            source.into(),
            self.namespaces.clone(),
            self.static_base_uri.clone(),
        )
    }

    pub(crate) fn generated(source: impl Into<String>, namespaces: Vec<(String, String)>) -> Self {
        Self::from_parts(source.into(), Arc::new(namespaces), None)
    }

    fn from_parts(
        source: String,
        namespaces: Arc<Vec<(String, String)>>,
        static_base_uri: Option<Arc<str>>,
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
    let mut count = 0usize;
    visit_referenced_variables(source, namespaces, |_, _| count += 1);
    let mut output = Vec::with_capacity(count);
    visit_referenced_variables(source, namespaces, |namespace, local| {
        output.push(ExpandedName::new(namespace, local));
    });
    output.sort_unstable_by(|left, right| {
        left.namespace
            .cmp(&right.namespace)
            .then_with(|| left.local.cmp(&right.local))
    });
    output.dedup();
    output
}

fn visit_referenced_variables<'a>(
    source: &'a str,
    namespaces: &'a [(String, String)],
    mut visit: impl FnMut(Option<&'a str>, &'a str),
) {
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
                    .map(|(_, namespace)| namespace.as_str())
            });
            visit(namespace, local);
        }
    }
}

fn referenced_variables_bounded(
    source: &str,
    namespaces: &[(String, String)],
    workspace: CompileWorkspace<'_>,
) -> Result<Arc<[ExpandedName]>> {
    let mut count = 0usize;
    let mut payload = Some(0usize);
    visit_referenced_variables(source, namespaces, |namespace, local| {
        count += 1; // Each reference consumes at least one distinct source byte.
        payload = payload
            .and_then(|bytes| bytes.checked_add(local.len()))
            .and_then(|bytes| bytes.checked_add(namespace.map_or(0, str::len)));
    });
    let vector_bytes = count
        .checked_mul(std::mem::size_of::<ExpandedName>())
        .filter(|bytes| *bytes <= isize::MAX as usize)
        .ok_or_else(|| workspace.overflow())?;
    let payload = payload.ok_or_else(|| workspace.overflow())?;
    let bytes = vector_bytes
        .checked_add(payload)
        .ok_or_else(|| workspace.overflow())?;
    workspace.retain(bytes)?;
    let references = referenced_variables(source, namespaces);
    let retained_payload = references.iter().fold(0usize, |bytes, name| {
        bytes + name.local.capacity() + name.namespace.as_ref().map_or(0, String::capacity)
    });
    workspace.release(payload - retained_payload);
    let arc_bytes = references
        .len()
        .checked_mul(std::mem::size_of::<ExpandedName>())
        .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<usize>()))
        .filter(|bytes| *bytes <= isize::MAX as usize)
        .ok_or_else(|| workspace.overflow())?;
    // Vec's buffer and the new Arc allocation overlap during conversion; strings move intact.
    workspace.retain(arc_bytes)?;
    let references = references.into();
    workspace.release(vector_bytes);
    Ok(references)
}

fn is_lexical_qname(value: &str) -> bool {
    let mut parts = value.split(':');
    let Some(first) = parts.next() else {
        return false;
    };
    is_ncname(first) && parts.next().is_none_or(is_ncname) && parts.next().is_none()
}
impl Pattern {
    fn new(
        source: &str,
        node: roxmltree::Node<'_, '_>,
        workspace: CompileWorkspace<'_>,
    ) -> Result<Self> {
        let validation_workspace = workspace.pending_source(source, node);
        if trim_xml_whitespace(source).is_empty() {
            return Err(validation_workspace.static_error(format_args!("empty template pattern")));
        }
        if contains_variable_reference(source) {
            return Err(validation_workspace.static_error(format_args!(
                "XSLT 1.0 match pattern `{source}` must not contain a variable reference"
            )));
        }
        workspace.retain(namespace_copy_bytes(node, false, workspace)?)?;
        let namespaces = namespaces(node);
        for branch in split_pattern_branches(source) {
            let branch = trim_xml_whitespace(branch);
            let (normalized, branch_workspace) = validation_workspace.normalize(branch)?;
            validate_xslt_pattern_branch(&normalized, branch_workspace)?;
            validate_xpath_prefixes(branch, &namespaces, branch_workspace)?;
            branch_workspace.parse_xpath(&normalized, branch, true)?;
        }
        let matches_attributes = {
            let (normalized, workspace) = validation_workspace.normalize(source)?;
            sxd_xpath_no_unsafe::expression_uses_attribute_axis_bounded(
                &normalized,
                workspace.remaining(),
            )
            .map_err(|error| workspace.parser_error(error, source, true))?
        };
        if validation_workspace.occupied == workspace.occupied {
            workspace.retain(source.len())?;
        }
        Ok(Self {
            source: source.to_owned(),
            namespaces,
            matches_attributes,
        })
    }

    fn template_branches(
        source: &str,
        node: roxmltree::Node<'_, '_>,
        workspace: CompileWorkspace<'_>,
    ) -> Result<Vec<Self>> {
        let count = split_pattern_branches(source).count();
        let bytes = count
            .checked_mul(std::mem::size_of::<Self>())
            .filter(|bytes| *bytes <= isize::MAX as usize)
            .ok_or_else(|| workspace.overflow())?;
        workspace.retain(bytes)?;
        let mut patterns = Vec::with_capacity(count);
        for branch in split_pattern_branches(source) {
            patterns.push(Self::new(trim_xml_whitespace(branch), node, workspace)?);
        }
        Ok(patterns)
    }
    fn default_priority(&self, workspace: CompileWorkspace<'_>) -> Result<f64> {
        let (normalized, _) = workspace.normalize(trim_xml_whitespace(&self.source))?;
        let value = normalized
            .strip_prefix("child::")
            .or_else(|| normalized.strip_prefix("attribute::"))
            .unwrap_or(&normalized);
        let value = value.strip_prefix('@').unwrap_or(value);
        let single_step = !value.contains(['/', '[', '|', '(', ')']);
        let node_test = pattern_node_test(value);
        Ok(
            if value == "*" || node_test == Some(PatternNodeTest::Generic) {
                -0.5
            // XSLT 1.0 section 5.5 assigns -0.25 only to a single NCName:* StepPattern;
            // a LocationPath containing that step has the complex-pattern priority 0.5.
            // https://www.w3.org/TR/1999/REC-xslt-19991116#conflict
            } else if single_step && value.ends_with(":*") {
                -0.25
            } else if single_step
                || node_test == Some(PatternNodeTest::ProcessingInstructionWithTarget)
            {
                0.0
            } else {
                0.5
            },
        )
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

fn validate_xpath_prefixes(
    source: &str,
    namespaces: &[(String, String)],
    workspace: CompileWorkspace<'_>,
) -> Result<()> {
    let mut characters = source.char_indices().peekable();
    let mut quote = None;
    while let Some((start, character)) = characters.next() {
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
        if !is_ncname_start(character) {
            continue;
        }
        while characters
            .peek()
            .is_some_and(|(_, next)| is_ncname_char(*next))
        {
            characters.next();
        }
        let Some(&(end, ':')) = characters.peek() else {
            continue;
        };
        let mut following = characters.clone();
        following.next();
        if !following
            .next()
            .is_some_and(|(_, next)| next == '*' || is_ncname_start(next))
        {
            continue;
        }
        let prefix = &source[start..end];
        if prefix != "xml" && !namespaces.iter().any(|(declared, _)| declared == prefix) {
            return Err(workspace.static_error(format_args!(
                "XPath expression `{source}` uses unbound namespace prefix `{prefix}`"
            )));
        }
        characters.next();
    }
    Ok(())
}

pub(crate) fn normalize_xpath_for_sxd(source: &str) -> Cow<'_, str> {
    // XPath 1.0 §3.7 defines whitespace as only XML S characters:
    // https://www.w3.org/TR/1999/REC-xpath-19991116/#exprlex
    if !source.chars().any(crate::lexical::is_xml_whitespace) && !source.contains('*') {
        return Cow::Borrowed(source);
    }
    let mut length = 0usize;
    let changed = visit_normalized_xpath(source, |part| length += part.len());
    if !changed {
        return Cow::Borrowed(source);
    }
    let mut output = String::with_capacity(length);
    visit_normalized_xpath(source, |part| output.push_str(part));
    debug_assert_eq!(output.len(), length);
    Cow::Owned(output)
}

// The measuring and writing passes share token handling; neither materializes a character array.
fn visit_normalized_xpath(source: &str, mut emit: impl FnMut(&str)) -> bool {
    let mut characters = source.char_indices().peekable();
    let mut quote = None;
    let mut previous = None;
    let mut previous_non_whitespace = None;
    let mut changed = false;
    while let Some((index, character)) = characters.next() {
        let literal = &source[index..index + character.len_utf8()];
        if let Some(active) = quote {
            emit(literal);
            previous = Some(character);
            if !is_xml_whitespace(character) {
                previous_non_whitespace = Some(character);
            }
            if character == active {
                quote = None;
            }
            continue;
        }
        if matches!(character, '\'' | '"') {
            quote = Some(character);
            emit(literal);
            previous = Some(character);
            previous_non_whitespace = Some(character);
            continue;
        }
        if is_xml_whitespace(character)
            && previous.is_some_and(|character| character == ':' || is_ncname_char(character))
        {
            let mut following = characters.clone();
            while following
                .peek()
                .is_some_and(|(_, next)| is_xml_whitespace(*next))
            {
                following.next();
            }
            let suffix = following
                .peek()
                .map_or("", |(offset, _)| &source[*offset..]);
            if suffix.starts_with('(') || suffix.starts_with("::") {
                characters = following;
                changed = true;
                continue;
            }
        }
        if character == ':' && characters.peek().is_some_and(|(_, next)| *next == ':') {
            emit("::");
            previous = Some(':');
            previous_non_whitespace = Some(':');
            characters.next();
            while characters
                .peek()
                .is_some_and(|(_, next)| is_xml_whitespace(*next))
            {
                characters.next();
                changed = true;
            }
            continue;
        }
        if character == '*' && matches!(previous_non_whitespace, Some('(' | ',')) {
            let next = characters
                .clone()
                .find(|(_, next)| !is_xml_whitespace(*next));
            if matches!(next, Some((_, ')' | ','))) {
                emit("child::*");
                previous = Some('*');
                previous_non_whitespace = Some('*');
                changed = true;
                continue;
            }
        }
        emit(literal);
        previous = Some(character);
        if !is_xml_whitespace(character) {
            previous_non_whitespace = Some(character);
        }
    }
    changed
}

fn split_pattern_branches(source: &str) -> impl Iterator<Item = &str> {
    split_top_level(source, '|')
}

// The caller has normalized and reserved the input; the pattern grammar scans borrow it.
fn validate_xslt_pattern_branch(branch: &str, workspace: CompileWorkspace<'_>) -> Result<()> {
    if branch == "/" {
        return Ok(());
    }
    let relative = if let Some(relative) = strip_id_key_pattern(branch, workspace)? {
        if relative.is_empty() {
            return Ok(());
        }
        relative
            .strip_prefix("//")
            .or_else(|| relative.strip_prefix('/'))
            .ok_or_else(|| invalid_match_pattern(branch, workspace))?
    } else {
        branch
            .strip_prefix("//")
            .or_else(|| branch.strip_prefix('/'))
            .unwrap_or(branch)
    };
    validate_pattern_steps(relative).ok_or_else(|| invalid_match_pattern(branch, workspace))?;
    Ok(())
}

fn strip_id_key_pattern<'a>(
    branch: &'a str,
    workspace: CompileWorkspace<'_>,
) -> Result<Option<&'a str>> {
    let (name, expected_arguments) = if branch.starts_with("id(") {
        ("id", 1)
    } else if branch.starts_with("key(") {
        ("key", 2)
    } else {
        return Ok(None);
    };
    let open = name.len();
    let Some(close) = matching_delimiter(branch, open, '(', ')') else {
        return Err(invalid_match_pattern(branch, workspace));
    };
    let mut count = 0;
    for argument in split_top_level(&branch[open + 1..close], ',') {
        count += 1;
        if count > expected_arguments || !is_xpath_literal(argument) {
            return Err(invalid_match_pattern(branch, workspace));
        }
    }
    if count != expected_arguments {
        return Err(invalid_match_pattern(branch, workspace));
    }
    Ok(Some(branch[close + 1..].trim_matches(is_xml_whitespace)))
}

fn validate_pattern_steps(source: &str) -> Option<()> {
    if trim_xml_whitespace(source).is_empty() {
        return None;
    }
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
                let step = trim_xml_whitespace(&source[start..index]);
                if step.is_empty() || !valid_pattern_step(step) {
                    return None;
                }
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
    let final_step = trim_xml_whitespace(&source[start..]);
    if final_step.is_empty() || !valid_pattern_step(final_step) {
        return None;
    }
    Some(())
}

fn valid_pattern_step(step: &str) -> bool {
    let predicate_start = first_top_level_character(step, '[').unwrap_or(step.len());
    let node_test = trim_xml_whitespace(&step[..predicate_start]);
    if !valid_pattern_node_test(node_test) {
        return false;
    }
    let mut remainder = trim_xml_whitespace(&step[predicate_start..]);
    while !remainder.is_empty() {
        if !remainder.starts_with('[') {
            return false;
        }
        let Some(close) = matching_delimiter(remainder, 0, '[', ']') else {
            return false;
        };
        if trim_xml_whitespace(&remainder[1..close]).is_empty() {
            return false;
        }
        remainder = trim_xml_whitespace(&remainder[close + 1..]);
    }
    true
}

fn valid_pattern_node_test(node_test: &str) -> bool {
    let (node_test, explicit_axis) = match node_test.split_once("::") {
        Some((axis, test))
            if matches!(axis.trim_matches(is_xml_whitespace), "child" | "attribute") =>
        {
            (test.trim_matches(is_xml_whitespace), true)
        }
        Some(_) => return false,
        None => (node_test, false),
    };
    if explicit_axis && node_test.starts_with('@') {
        return false;
    }
    let node_test = strip_xpath_attribute_axis(node_test).unwrap_or(node_test);
    if node_test == "*" || is_lexical_qname(node_test) {
        return true;
    }
    if node_test.strip_suffix(":*").is_some_and(is_ncname) {
        return true;
    }
    pattern_node_test(node_test).is_some()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PatternNodeTest {
    Generic,
    ProcessingInstructionWithTarget,
}

fn pattern_node_test(value: &str) -> Option<PatternNodeTest> {
    // XPath 1.0 section 3.7 permits ExprWhitespace between grammar tokens, including before `)`.
    // https://www.w3.org/TR/1999/REC-xpath-19991116/#exprlex
    let open = value.find('(')?;
    let close = value.strip_suffix(')')?;
    let name = trim_xml_whitespace(&value[..open]);
    let argument = trim_xml_whitespace(&close[open + 1..]);
    match (name, argument) {
        ("node" | "text" | "comment" | "processing-instruction", "") => {
            Some(PatternNodeTest::Generic)
        }
        ("processing-instruction", argument) if is_xpath_literal(argument) => {
            Some(PatternNodeTest::ProcessingInstructionWithTarget)
        }
        _ => None,
    }
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

fn split_top_level(source: &str, separator: char) -> impl Iterator<Item = &str> {
    let mut start = 0usize;
    let mut depth = 0usize;
    let mut quote = None;
    let mut characters = source.char_indices();
    let mut finished = false;
    std::iter::from_fn(move || {
        if finished {
            return None;
        }
        for (index, character) in characters.by_ref() {
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
                    let part = source[start..index].trim_matches(is_xml_whitespace);
                    start = index + character.len_utf8();
                    return Some(part);
                }
                _ => {}
            }
        }
        finished = true;
        Some(source[start..].trim_matches(is_xml_whitespace))
    })
}

fn is_xpath_literal(value: &str) -> bool {
    xpath_string_literal(value).is_some()
}

fn invalid_match_pattern(pattern: &str, workspace: CompileWorkspace<'_>) -> Error {
    workspace.static_error(format_args!(
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
    active_resources: Vec<Arc<ResolvedResource>>,
    resolved_requests: HashMap<ResolveRequest, Arc<ResolvedResource>>,
    resolved_identities: HashMap<ResourceIdentity, Arc<ResolvedResource>>,
    module_sources: HashMap<ResourceIdentity, Arc<String>>,
    module_documents: HashMap<String, Document>,
    imported_modules: usize,
    stylesheet_bytes: usize,
    owned_bytes: usize,
    xpath_owned_bytes: Cell<usize>,
    precedence: usize,
    order: usize,
}
impl CompileState {
    fn workspace(&self) -> CompileWorkspace<'_> {
        CompileWorkspace {
            limit: self.budget.owned_bytes,
            occupied: self.owned_bytes,
            retained: &self.xpath_owned_bytes,
        }
    }
    fn new(mut budget: CompileBudget, stylesheet_bytes: usize) -> Self {
        budget.recursion_depth = budget.recursion_depth.min(COMPILE_RECURSION_DEPTH_CEILING);
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
            active_resources: vec![],
            resolved_requests: HashMap::new(),
            resolved_identities: HashMap::new(),
            module_sources: HashMap::new(),
            module_documents: HashMap::new(),
            imported_modules: 0,
            stylesheet_bytes,
            owned_bytes: 0,
            xpath_owned_bytes: Cell::new(0),
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
        let workspace = self.workspace().reserve(amount)?;
        self.owned_bytes = workspace.occupied;
        Ok(())
    }
    fn remaining_owned_bytes(&self) -> usize {
        self.workspace().remaining()
    }
    fn release_owned(&mut self, amount: usize) {
        self.owned_bytes = self
            .owned_bytes
            .checked_sub(amount)
            .expect("released compiler workspace was previously charged");
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
    fn check_stylesheet(&self, amount: usize) -> Result<()> {
        ensure(
            BudgetKind::StylesheetBytes,
            self.budget.stylesheet_bytes,
            self.stylesheet_bytes.saturating_add(amount),
        )
    }
    fn finish(mut self) -> Result<Stylesheet> {
        self.templates
            .sort_by_key(|template| (template.precedence, template.order));
        let named_count = self
            .templates
            .iter()
            .filter(|template| template.name.is_some())
            .count();
        let named_workspace =
            named_count.saturating_mul(hash_entry_storage::<(&ExpandedName, usize), ()>());
        self.charge_owned(named_workspace)?;
        let mut named = HashSet::new();
        let named_result = (|| {
            for template in self
                .templates
                .iter()
                .filter(|template| template.name.is_some())
            {
                if !named.insert((template.name.as_ref(), template.precedence)) {
                    return Err(Error::Static(
                        "duplicate named template at equal import precedence".into(),
                    ));
                }
            }
            Ok(())
        })();
        drop(named);
        self.release_owned(named_workspace);
        named_result?;
        let named_index_bytes = self.templates.iter().fold(0usize, |total, template| {
            total.saturating_add(template.name.as_ref().map_or(0, |name| {
                hash_entry_storage::<ExpandedName, usize>()
                    .saturating_add(name.local.len())
                    .saturating_add(name.namespace.as_ref().map_or(0, String::len))
            }))
        });
        self.charge_owned(named_index_bytes)?;
        let mut named_template_index: HashMap<ExpandedName, usize> =
            HashMap::with_capacity(named_count);
        for (index, template) in self.templates.iter().enumerate() {
            let Some(name) = &template.name else {
                continue;
            };
            match named_template_index.entry(name.clone()) {
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    let selected = &self.templates[*entry.get()];
                    if (template.precedence, template.order) > (selected.precedence, selected.order)
                    {
                        entry.insert(index);
                    }
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(index);
                }
            }
        }
        let actual_named_index_bytes = named_template_index.iter().fold(
            named_template_index
                .len()
                .saturating_mul(hash_entry_storage::<ExpandedName, usize>()),
            |total, (name, _)| {
                total
                    .saturating_add(name.local.len())
                    .saturating_add(name.namespace.as_ref().map_or(0, String::len))
            },
        );
        self.release_owned(named_index_bytes.saturating_sub(actual_named_index_bytes));
        let key_name_workspace = self
            .keys
            .len()
            .saturating_mul(hash_entry_storage::<&ExpandedName, ()>());
        let key_name_index_upper = self.keys.len().saturating_mul(std::mem::size_of::<usize>());
        self.charge_owned(key_name_workspace.saturating_add(key_name_index_upper))?;
        let mut key_names = HashSet::with_capacity(self.keys.len());
        let key_name_indices = self
            .keys
            .iter()
            .enumerate()
            .filter_map(|(index, declaration)| key_names.insert(&declaration.name).then_some(index))
            .collect::<Vec<_>>();
        drop(key_names);
        self.release_owned(key_name_workspace);
        let key_name_index_bytes = key_name_indices
            .capacity()
            .saturating_mul(std::mem::size_of::<usize>());
        self.release_owned(key_name_index_upper.saturating_sub(key_name_index_bytes));
        let global_validation_workspace = self
            .globals
            .len()
            .saturating_mul(hash_entry_storage::<(&ExpandedName, usize), ()>());
        self.charge_owned(global_validation_workspace)?;
        let mut globals = HashSet::with_capacity(self.globals.len());
        let global_validation = (|| {
            for global in &self.globals {
                if !globals.insert((&global.variable.name, global.precedence)) {
                    return Err(Error::Static(format!(
                        "duplicate global variable {} at equal import precedence",
                        global.variable.name.local
                    )));
                }
            }
            Ok(())
        })();
        drop(globals);
        self.release_owned(global_validation_workspace);
        global_validation?;
        let function_validation_workspace = self
            .functions
            .len()
            .saturating_mul(hash_entry_storage::<(&ExpandedName, usize), ()>());
        self.charge_owned(function_validation_workspace)?;
        let mut functions = HashSet::with_capacity(self.functions.len());
        let function_validation = (|| {
            for function in &self.functions {
                if !functions.insert((&function.name, function.precedence)) {
                    return Err(Error::Static(format!(
                        "duplicate EXSLT function {} at equal import precedence",
                        function.name.local
                    )));
                }
            }
            Ok(())
        })();
        drop(functions);
        self.release_owned(function_validation_workspace);
        function_validation?;
        let function_index_bytes = self.functions.iter().fold(
            self.functions
                .len()
                .saturating_mul(hash_entry_storage::<ExpandedName, ()>()),
            |total, function| {
                total
                    .saturating_add(function.name.local.len())
                    .saturating_add(function.name.namespace.as_ref().map_or(0, String::len))
            },
        );
        self.charge_owned(function_index_bytes)?;
        let function_names = self
            .functions
            .iter()
            .map(|function| function.name.clone())
            .collect::<HashSet<_>>();
        let named_alias_count = self
            .namespace_aliases
            .iter()
            .filter(|alias| alias.stylesheet_namespace.is_some())
            .count();
        self.charge_owned(
            named_alias_count.saturating_mul(hash_entry_storage::<Arc<str>, usize>()),
        )?;
        let mut namespace_alias_index = HashMap::with_capacity(named_alias_count);
        let mut default_namespace_alias = None;
        for (index, alias) in self.namespace_aliases.iter().enumerate() {
            if let Some(namespace) = &alias.stylesheet_namespace {
                namespace_alias_index.insert(Arc::clone(namespace), index);
            } else {
                default_namespace_alias = Some(index);
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
            named_template_index: Arc::new(named_template_index),
            globals: self.globals.into(),
            output: self.output,
            whitespace: self.whitespace.into(),
            keys: self.keys.into(),
            key_name_indices: key_name_indices.into(),
            decimal_formats: self.decimal_formats.into(),
            namespace_aliases: self.namespace_aliases.into(),
            namespace_alias_index: Arc::new(namespace_alias_index),
            default_namespace_alias,
            attribute_sets: self.attribute_sets.into(),
            functions: self.functions.into(),
            function_names: Arc::new(function_names),
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
    validate_attribute_set_cycles(sets)?;
    for template in templates {
        for parameter in template.params.iter() {
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

fn validate_attribute_set_cycles(sets: &[AttributeSet]) -> Result<()> {
    let mut indices = HashMap::<&ExpandedName, usize>::new();
    for set in sets {
        let next = indices.len();
        indices.entry(&set.name).or_insert(next);
    }
    let mut edges = vec![Vec::new(); indices.len()];
    let mut incoming = vec![0usize; indices.len()];
    for set in sets {
        let source = indices[&set.name];
        for used in &set.uses {
            let target = indices[used];
            edges[source].push(target);
            incoming[target] = incoming[target].saturating_add(1);
        }
    }
    let mut ready = incoming
        .iter()
        .enumerate()
        .filter_map(|(index, count)| (*count == 0).then_some(index))
        .collect::<VecDeque<_>>();
    let mut visited = 0usize;
    while let Some(source) = ready.pop_front() {
        visited += 1;
        for &target in &edges[source] {
            incoming[target] -= 1;
            if incoming[target] == 0 {
                ready.push_back(target);
            }
        }
    }
    if visited != indices.len() {
        // XSLT 1.0 section 7.1.4 makes direct and indirect self-use erroneous even when the
        // attribute set is never reached at runtime.
        // https://www.w3.org/TR/1999/REC-xslt-19991116#attribute-sets
        return Err(Error::Static("attribute-set cycle".into()));
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
                ..
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
            | Instruction::CopyOf { .. }
            | Instruction::Number(_)
            | Instruction::CompatibilityComment(_) => {}
        }
    }
    Ok(())
}

fn estimate_compiled_owned_bytes(
    document: &roxmltree::Document<'_>,
    module_base_uri: Option<&str>,
) -> usize {
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
            let expression_count = node.attributes().fold(0usize, |count, attribute| {
                count.saturating_add(
                    1usize.saturating_add(
                        attribute
                            .value()
                            .bytes()
                            .filter(|byte| *byte == b'{')
                            .count(),
                    ),
                )
            });
            // XPath namespace snapshots are charged at their actual construction sites, not
            // once per element: patterns copy them and expressions may share them through Arc.
            // One shared Arc<str> is retained by all expressions compiled from this node. URL
            // serialization may percent-encode every byte, so three times the lexical inputs is
            // a conservative pre-allocation bound that requires no unmetered URI construction.
            let expression_base_uri_bytes = if expression_count != 0 {
                node.ancestors()
                    .filter(roxmltree::Node::is_element)
                    .filter_map(|ancestor| {
                        ancestor.attribute(("http://www.w3.org/XML/1998/namespace", "base"))
                    })
                    .map(str::len)
                    .fold(module_base_uri.map_or(0, str::len), usize::saturating_add)
                    .saturating_mul(3)
            } else {
                0
            };
            structural_bytes
                .saturating_add(name_bytes)
                .saturating_add(attribute_bytes)
                .saturating_add(namespace_bytes)
                .saturating_add(expression_base_uri_bytes)
        } else {
            structural_bytes.saturating_add(node.text().map_or(0, str::len))
        };
        total.saturating_add(node_bytes)
    })
}

fn with_frontend_document<T>(
    xml: &str,
    state: &mut CompileState,
    consume: impl FnOnce(&roxmltree::Document<'_>, &mut CompileState) -> Result<T>,
) -> Result<T> {
    let lexical_reserved = parser_workspace_bytes(xml);
    state.charge_owned(lexical_reserved)?;
    let prepared = match prepare_xml_frontend_bounded(
        xml,
        state.remaining_owned_bytes(),
        state.budget.recursion_depth,
    ) {
        Ok(prepared) => prepared,
        Err(error) => {
            state.release_owned(lexical_reserved);
            return Err(error);
        }
    };
    let expanded_owned_bytes = match &prepared {
        Cow::Borrowed(_) => 0,
        Cow::Owned(expanded) => expanded.capacity(),
    };
    if let Err(error) = state.charge_owned(expanded_owned_bytes) {
        state.release_owned(lexical_reserved);
        return Err(error);
    }
    let expanded_workspace = parser_workspace_bytes(prepared.as_ref());
    let additional_workspace = expanded_workspace.saturating_sub(lexical_reserved);
    if let Err(error) = state.charge_owned(additional_workspace) {
        state.release_owned(expanded_owned_bytes);
        state.release_owned(lexical_reserved);
        return Err(error);
    }
    let result = roxmltree::Document::parse(prepared.as_ref())
        .map_err(|error| Error::Xml(error.to_string()))
        .and_then(|document| consume(&document, state));
    state.release_owned(additional_workspace);
    state.release_owned(expanded_owned_bytes);
    state.release_owned(lexical_reserved);
    result
}

fn with_compiler_document<T>(
    xml: &str,
    base_uri: Option<&str>,
    state: &mut CompileState,
    compile: impl FnOnce(&roxmltree::Document<'_>, &mut CompileState) -> Result<T>,
) -> Result<T> {
    with_frontend_document(xml, state, |document, state| {
        // Each include occurrence retains distinct IR even when its source is cached.
        state.charge_owned(estimate_compiled_owned_bytes(document, base_uri))?;
        compile(document, state)
    })
}

// Module IR is precharged; XPath-owned namespace/reference copies are charged when constructed.
// All snapshots share that retained counter, while lexical parser reservations are scoped and
// reusable. No XPath object retains a borrow of this compile-only accounting state.
#[derive(Debug, Clone, Copy)]
struct CompileWorkspace<'a> {
    limit: usize,
    occupied: usize,
    retained: &'a Cell<usize>,
}

impl CompileWorkspace<'_> {
    fn overflow(self) -> Error {
        Error::Budget {
            kind: BudgetKind::OwnedBytes,
            limit: self.limit,
            actual: usize::MAX,
        }
    }

    fn reserve(self, bytes: usize) -> Result<Self> {
        let occupied = self
            .occupied
            .checked_add(bytes)
            .ok_or_else(|| self.overflow())?;
        let actual = occupied
            .checked_add(self.retained.get())
            .ok_or_else(|| self.overflow())?;
        ensure(BudgetKind::OwnedBytes, self.limit, actual)?;
        Ok(Self { occupied, ..self })
    }

    fn retain(self, bytes: usize) -> Result<()> {
        self.reserve(bytes)?;
        self.retained.set(self.retained.get() + bytes);
        Ok(())
    }

    fn release(self, bytes: usize) {
        self.retained.set(
            self.retained
                .get()
                .checked_sub(bytes)
                .expect("released XPath storage was reserved"),
        );
    }

    fn remaining(self) -> usize {
        self.limit - self.occupied - self.retained.get()
    }

    fn pending_source(self, source: &str, node: roxmltree::Node<'_, '_>) -> Self {
        // Module IR precharges attribute values. Only a borrowed slice of this node's attribute
        // may reuse its own future source allocation; generated defaults receive no credit.
        let start = source.as_ptr() as usize;
        let belongs_to_attribute = node.attributes().any(|attribute| {
            let value = attribute.value();
            let base = value.as_ptr() as usize;
            start >= base
                && start - base <= value.len()
                && source.len() <= value.len() - (start - base)
        });
        if belongs_to_attribute {
            Self {
                occupied: self
                    .occupied
                    .checked_sub(source.len())
                    .expect("attribute source was precharged by module compilation"),
                ..self
            }
        } else {
            self
        }
    }

    fn static_error(self, arguments: std::fmt::Arguments<'_>) -> Error {
        use std::fmt::Write;
        struct Length(usize);
        impl std::fmt::Write for Length {
            fn write_str(&mut self, value: &str) -> std::fmt::Result {
                self.0 = self.0.checked_add(value.len()).ok_or(std::fmt::Error)?;
                Ok(())
            }
        }
        let mut length = Length(0);
        if length.write_fmt(arguments).is_err() || length.0 > isize::MAX as usize {
            return self.overflow();
        }
        if let Err(error) = self.reserve(length.0) {
            return error;
        }
        let mut message = String::with_capacity(length.0);
        message
            .write_fmt(arguments)
            .expect("formatting to String cannot fail");
        debug_assert_eq!(message.len(), length.0);
        Error::Static(message)
    }

    fn normalize(self, source: &str) -> Result<(Cow<'_, str>, Self)> {
        let mut length = Some(0usize);
        let changed = visit_normalized_xpath(source, |part| {
            length = length.and_then(|length| length.checked_add(part.len()));
        });
        if !changed {
            return Ok((Cow::Borrowed(source), self));
        }
        let length = length
            .filter(|length| *length <= isize::MAX as usize)
            .ok_or_else(|| self.overflow())?;
        let workspace = self.reserve(length)?;
        let mut normalized = String::with_capacity(length);
        visit_normalized_xpath(source, |part| normalized.push_str(part));
        Ok((Cow::Owned(normalized), workspace))
    }

    fn parse_xpath(
        self,
        normalized: &str,
        source: &str,
        pattern: bool,
    ) -> Result<sxd_xpath_no_unsafe::XPath> {
        sxd_xpath_no_unsafe::Factory::new()
            .build_bounded(normalized, self.remaining())
            .map_err(|error| self.parser_error(error, source, pattern))
    }

    fn parser_error(
        self,
        error: sxd_xpath_no_unsafe::ParserError,
        source: &str,
        pattern: bool,
    ) -> Error {
        if let Some((_, actual)) = error.allocation_limit() {
            return Error::Budget {
                kind: BudgetKind::OwnedBytes,
                limit: self.limit,
                actual: self
                    .occupied
                    .saturating_add(self.retained.get())
                    .saturating_add(actual),
            };
        }
        let kind = if pattern {
            "match pattern"
        } else {
            "XPath expression"
        };
        match self.reserve(error.owned_bytes()) {
            Ok(workspace) => {
                workspace.static_error(format_args!("invalid {kind} `{source}`: {error}"))
            }
            Err(error) => error,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ResolveRequest {
    href: String,
    base_uri: Option<String>,
    purpose: ResolvePurpose,
}

struct ResolvedModule<'input> {
    resource: Arc<ResolvedResource>,
    fragment: Option<&'input str>,
}

fn hash_entry_storage<K, V>() -> usize {
    // Hash tables retain control bytes and spare buckets. Two entry widths conservatively model
    // the standard maximum load without depending on the allocator implementation.
    std::mem::size_of::<(K, V)>().saturating_mul(2)
}

fn resolve_request_retained_bytes(href: &str, base_uri: Option<&str>) -> usize {
    hash_entry_storage::<ResolveRequest, Arc<ResolvedResource>>()
        .saturating_add(href.len())
        .saturating_add(base_uri.map_or(0, str::len))
}

fn resolved_resource_owned_bytes(resource: &ResolvedResource) -> usize {
    std::mem::size_of::<ResolvedResource>()
        .saturating_add(std::mem::size_of::<usize>().saturating_mul(2))
        .saturating_add(resource.canonical_uri.capacity())
        .saturating_add(resource.identity.0.capacity())
        .saturating_add(resource.bytes.capacity())
        .saturating_add(resource.media_type.as_ref().map_or(0, String::capacity))
        .saturating_add(resource.encoding.as_ref().map_or(0, String::capacity))
}

fn new_resolved_identity_retained_bytes(resource: &ResolvedResource) -> usize {
    resolved_resource_owned_bytes(resource)
        .saturating_add(
            hash_entry_storage::<ResourceIdentity, Arc<ResolvedResource>>()
                .saturating_add(resource.identity.0.len()),
        )
        .saturating_add(
            std::mem::size_of::<ResourceIdentity>()
                .saturating_mul(2)
                .saturating_add(resource.identity.0.len()),
        )
        .saturating_add(std::mem::size_of::<Arc<ResolvedResource>>().saturating_mul(2))
}

fn module_document_cache_entry_bytes(canonical_uri: &str) -> usize {
    hash_entry_storage::<String, Document>().saturating_add(canonical_uri.len())
}

fn module_source_cache_entry_bytes(identity: &ResourceIdentity) -> usize {
    hash_entry_storage::<ResourceIdentity, Arc<String>>()
        .saturating_add(identity.0.len())
        .saturating_add(std::mem::size_of::<String>())
        .saturating_add(std::mem::size_of::<usize>().saturating_mul(2))
}

#[derive(Debug, Clone)]
struct CompileContext<'a> {
    forward: bool,
    depth: usize,
    max_depth: usize,
    workspace: CompileWorkspace<'a>,
    inside_function: bool,
    static_base_uri: Option<Arc<str>>,
    namespace_snapshot: NamespaceSnapshot,
    base_uri_snapshot: BaseUriSnapshot,
    local_bindings: LocalBindingIndex,
}

type NamespaceSnapshot = Rc<RefCell<Option<(roxmltree::NodeId, Weak<Vec<(String, String)>>)>>>;
type BaseUriSnapshot = Rc<RefCell<Option<(roxmltree::NodeId, Option<Arc<str>>)>>>;
type LocalBindingIndex = Rc<RefCell<HashMap<roxmltree::NodeId, HashSet<ExpandedName>>>>;

impl<'a> CompileContext<'a> {
    fn new(
        forward: bool,
        depth: usize,
        max_depth: usize,
        static_base_uri: Option<&str>,
        workspace: CompileWorkspace<'a>,
    ) -> Result<Self> {
        ensure(BudgetKind::RecursionDepth, max_depth, depth)?;
        Ok(Self {
            forward,
            depth,
            max_depth,
            workspace,
            inside_function: false,
            static_base_uri: static_base_uri.map(Arc::from),
            namespace_snapshot: Rc::new(RefCell::new(None)),
            base_uri_snapshot: Rc::new(RefCell::new(None)),
            local_bindings: Rc::new(RefCell::new(HashMap::new())),
        })
    }

    fn descend(&self) -> Result<Self> {
        let depth = self.depth.saturating_add(1);
        ensure(BudgetKind::RecursionDepth, self.max_depth, depth)?;
        let mut descended = self.clone();
        descended.depth = depth;
        Ok(descended)
    }

    fn inside_function(mut self) -> Self {
        self.inside_function = true;
        self
    }

    fn expression(&self, source: &str, node: roxmltree::Node<'_, '_>) -> Result<Expression> {
        let mut snapshot = self.namespace_snapshot.borrow_mut();
        let cached = snapshot
            .as_ref()
            .filter(|(id, _)| *id == node.id())
            .and_then(|(_, namespaces)| namespaces.upgrade());
        let namespaces = if let Some(namespaces) = cached {
            namespaces
        } else {
            self.workspace
                .retain(namespace_copy_bytes(node, true, self.workspace)?)?;
            let namespaces = Arc::new(namespaces(node));
            *snapshot = Some((node.id(), Arc::downgrade(&namespaces)));
            namespaces
        };
        let mut base_snapshot = self.base_uri_snapshot.borrow_mut();
        let static_base_uri = if let Some((id, base_uri)) = base_snapshot.as_ref()
            && *id == node.id()
        {
            base_uri.clone()
        } else {
            let base_uri =
                effective_base_uri(node, self.static_base_uri.as_deref())?.map(Arc::from);
            *base_snapshot = Some((node.id(), base_uri.clone()));
            base_uri
        };
        Expression::new_with_namespaces_and_base(
            source,
            namespaces,
            static_base_uri,
            self.max_depth,
            self.workspace,
            self.workspace.pending_source(source, node),
        )
    }

    fn has_visible_local_binding(
        &self,
        node: roxmltree::Node<'_, '_>,
        name: &ExpandedName,
    ) -> bool {
        let bindings = self.local_bindings.borrow();
        let mut cursor = node;
        while let Some(parent) = cursor.parent_element() {
            if bindings
                .get(&parent.id())
                .is_some_and(|names| names.contains(name))
            {
                return true;
            }
            cursor = parent;
        }
        false
    }

    fn register_local_binding(&self, node: roxmltree::Node<'_, '_>, name: ExpandedName) {
        let Some(parent) = node.parent_element() else {
            return;
        };
        self.local_bindings
            .borrow_mut()
            .entry(parent.id())
            .or_default()
            .insert(name);
    }

    fn with_literal_version(mut self, node: roxmltree::Node<'_, '_>) -> Result<Self> {
        if let Some(version) = node.attribute((XSLT_NS, "version")) {
            self.forward = stylesheet_version_is_forward_compatible(version)?;
        }
        Ok(self)
    }
}

fn resource_source(resource: &ResolvedResource, state: &mut CompileState) -> Result<Arc<String>> {
    if let Some(source) = state.module_sources.get(&resource.identity) {
        return Ok(Arc::clone(source));
    }
    let cache_entry_bytes = module_source_cache_entry_bytes(&resource.identity);
    state.charge_owned(cache_entry_bytes)?;
    let remaining_stylesheet = state
        .budget
        .stylesheet_bytes
        .saturating_sub(state.stylesheet_bytes);
    let remaining_owned = state.remaining_owned_bytes();
    let maximum = remaining_stylesheet.min(remaining_owned);
    let decoded =
        match decode_resource(&resource.bytes, resource.encoding.as_deref(), true, maximum) {
            Ok(decoded) => decoded,
            Err(error) => {
                state.release_owned(cache_entry_bytes);
                return Err(match error {
                    xml_sec_xml_input::Error::DecodedLimit { actual, .. }
                        if remaining_stylesheet <= remaining_owned =>
                    {
                        Error::Budget {
                            kind: BudgetKind::StylesheetBytes,
                            limit: state.budget.stylesheet_bytes,
                            actual: state.stylesheet_bytes.saturating_add(actual),
                        }
                    }
                    xml_sec_xml_input::Error::DecodedLimit { actual, .. } => Error::Budget {
                        kind: BudgetKind::OwnedBytes,
                        limit: state.budget.owned_bytes,
                        actual: state
                            .owned_bytes
                            .saturating_add(state.xpath_owned_bytes.get())
                            .saturating_add(actual),
                    },
                    error => Error::Xml(error.to_string()),
                });
            }
        };
    state.charge_stylesheet(decoded.len())?;
    state.charge_owned(decoded.capacity())?;
    let source = Arc::new(decoded);
    state
        .module_sources
        .insert(resource.identity.clone(), Arc::clone(&source));
    Ok(source)
}

fn parse_semantic_document_metered(
    xml: &str,
    base_uri: Option<&str>,
    state: &mut CompileState,
) -> Result<Document> {
    let projected_bytes = with_frontend_document(xml, state, |parsed, _state| {
        Ok(xml
            .len()
            .saturating_add(estimate_compiled_owned_bytes(parsed, base_uri))
            .saturating_add(
                base_uri
                    .map_or(0, str::len)
                    .saturating_mul(parsed.descendants().count()),
            ))
    })?;
    state.charge_owned(projected_bytes)?;
    let parser_workspace = parser_workspace_bytes(xml);
    state.charge_owned(parser_workspace)?;
    let document = Document::parse(xml, base_uri);
    state.release_owned(parser_workspace);
    document
}

enum StylesheetModuleKind {
    Standard { forward: bool },
    Simplified,
}

fn stylesheet_module_kind(root: roxmltree::Node<'_, '_>) -> Result<StylesheetModuleKind> {
    if root.tag_name().namespace() == Some(XSLT_NS) {
        if matches!(root.tag_name().name(), "stylesheet" | "transform") {
            return Ok(StylesheetModuleKind::Standard {
                forward: module_forward_compatible(root)?,
            });
        }
        // XSLT 1.0 section 2.3 permits only a literal result element as a simplified
        // stylesheet; XSLT-namespace elements are instructions, not literal results.
        // https://www.w3.org/TR/1999/REC-xslt-19991116#result-element-stylesheet
        return Err(Error::Static(format!(
            "xsl:{} cannot be the document element of a stylesheet",
            root.tag_name().name()
        )));
    }
    root.attribute((XSLT_NS, "version"))
        .ok_or_else(|| Error::Static("literal result stylesheet requires xsl:version".into()))
        .and_then(parse_stylesheet_version)?;
    Ok(StylesheetModuleKind::Simplified)
}

fn stylesheet_module_root<'nodes, 'input>(
    document: &'nodes roxmltree::Document<'input>,
    fragment: Option<&str>,
) -> Result<roxmltree::Node<'nodes, 'input>> {
    let Some(raw_fragment) = fragment else {
        return Ok(document.root_element());
    };
    // XSLT 1.0 sections 2.6 and 2.7 allow a URI reference to identify an embedded
    // xsl:stylesheet by its ID. Module selection is per reference, not per fetched resource.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#embedded
    let fragment = ValidatedXPointerFragment::new(raw_fragment)?;
    let mut selected = None;
    for node in document.descendants().filter(roxmltree::Node::is_element) {
        let unqualified_match = node
            .attribute("id")
            .is_some_and(|candidate| fragment.equals(candidate));
        let xml_id_match = node
            .attribute((XML_NS, "id"))
            .map(normalized_xml_id)
            .transpose()?
            .is_some_and(|value| fragment.equals(&value));
        if !unqualified_match && !xml_id_match {
            continue;
        }
        if selected.replace(node).is_some() {
            return Err(Error::Static(format!(
                "stylesheet module fragment #{raw_fragment} is not unique"
            )));
        }
    }
    let selected = selected.ok_or_else(|| {
        Error::Static(format!(
            "stylesheet module fragment #{raw_fragment} does not identify an element"
        ))
    })?;
    if selected.tag_name().namespace() != Some(XSLT_NS)
        || !matches!(selected.tag_name().name(), "stylesheet" | "transform")
    {
        return Err(Error::Static(format!(
            "stylesheet module fragment #{raw_fragment} does not identify xsl:stylesheet"
        )));
    }
    Ok(selected)
}

fn module_forward_compatible(root: roxmltree::Node<'_, '_>) -> Result<bool> {
    match root.attribute("version") {
        Some(version) => stylesheet_version_is_forward_compatible(version),
        None => Err(Error::Static("xsl:stylesheet requires version".into())),
    }
}

fn stylesheet_version_is_forward_compatible(version: &str) -> Result<bool> {
    // XSLT 1.0 sections 2.2 and 2.5 enable forwards-compatible processing whenever
    // the version Number is not equal to 1.0, including values below 1.0.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#forwards
    Ok(parse_stylesheet_version(version)? != 1.0)
}

fn parse_stylesheet_version(version: &str) -> Result<f64> {
    // XSLT 1.0 sections 2.2 and 2.3 define version as XPath's Number production;
    // host float syntax is wider: https://www.w3.org/TR/1999/REC-xpath-19991116/#exprlex
    crate::xpath::parse_xpath_number_token(version)
        .filter(|value| value.is_finite())
        .ok_or_else(|| Error::Static(format!("unsupported XSLT version {version}")))
}

fn effective_base_uri(
    node: roxmltree::Node<'_, '_>,
    module_base: Option<&str>,
) -> Result<Option<String>> {
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
) -> Result<InstructionSequence> {
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
    Ok(out.into())
}

fn stylesheet_space_is_preserved(node: roxmltree::Node<'_, '_>) -> bool {
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
                fallback.extend(
                    compile_sequence(child.children(), context.descend()?)?
                        .iter()
                        .cloned(),
                );
            }
            return Ok(Instruction::ExtensionFallback {
                name: node.tag_name().name().into(),
                present: !fallback_nodes.is_empty(),
                body: fallback.into(),
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
                body: body.into(),
            }
        }
        "if" => Instruction::If {
            test: context.expression(required_attr(node, "test")?, node)?,
            body: sequence()?,
        },
        "choose" => {
            let mut branches = vec![];
            let mut otherwise = Arc::from([]);
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
                disable_output_escaping: instruction_yes_no(
                    node,
                    "disable-output-escaping",
                    context.forward,
                )?,
            }
        }
        "copy-of" => {
            require_empty_instruction(node)?;
            Instruction::CopyOf {
                select: context.expression(required_attr(node, "select")?, node)?,
                base_uri: effective_base_uri(node, context.static_base_uri.as_deref())?,
            }
        }
        "copy" => Instruction::Copy {
            base_uri: effective_base_uri(node, context.static_base_uri.as_deref())?,
            body: sequence()?,
            attribute_sets: qname_list_attr(node, "use-attribute-sets")?,
        },
        "element" => Instruction::Element {
            base_uri: effective_base_uri(node, context.static_base_uri.as_deref())?,
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
                instruction_yes_no(node, "disable-output-escaping", context.forward)?,
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
            terminate: instruction_yes_no(node, "terminate", context.forward)?,
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
                fallback.extend(
                    compile_sequence(child.children(), context.descend()?)?
                        .iter()
                        .cloned(),
                );
            }
            Instruction::ExtensionFallback {
                name: node.tag_name().name().into(),
                present: !fallback_nodes.is_empty(),
                body: fallback.into(),
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
        let Some(_) = ancestor
            .attribute((XSLT_NS, "extension-element-prefixes"))
            .or_else(|| {
                (ancestor.tag_name().namespace() == Some(XSLT_NS))
                    .then(|| ancestor.attribute("extension-element-prefixes"))
                    .flatten()
            })
        else {
            continue;
        };
        let mut extension = false;
        visit_namespace_prefix_attribute(
            ancestor,
            "extension-element-prefixes",
            forward_compatible_at(ancestor)?,
            |resolved| extension |= resolved == namespace,
        )?;
        if extension {
            return Ok(true);
        }
    }
    Ok(false)
}

fn is_exslt_function_declaration(node: roxmltree::Node<'_, '_>) -> Result<bool> {
    Ok(node.has_tag_name((EXSLT_FUNCTIONS_NS, "function")) && is_extension_element(node)?)
}

fn forward_compatible_at(node: roxmltree::Node<'_, '_>) -> Result<bool> {
    for ancestor in node.ancestors().filter(roxmltree::Node::is_element) {
        if let Some(forward) = local_forward_compatible(ancestor)? {
            return Ok(forward);
        }
    }
    Ok(false)
}

fn local_forward_compatible(node: roxmltree::Node<'_, '_>) -> Result<Option<bool>> {
    let version = if node.has_tag_name((XSLT_NS, "stylesheet"))
        || node.has_tag_name((XSLT_NS, "transform"))
    {
        node.attribute("version")
    } else {
        node.attribute((XSLT_NS, "version"))
    };
    version
        .map(stylesheet_version_is_forward_compatible)
        .transpose()
}
fn compile_literal_element(
    node: roxmltree::Node<'_, '_>,
    context: CompileContext,
) -> Result<Instruction> {
    let context = context.with_literal_version(node)?;
    validate_literal_result_attributes(node, context.forward)?;
    let prefix = element_prefix(node);
    let attributes: Vec<LiteralAttribute> = node
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
    let excluded = excluded_result_namespaces(node)?;
    let mut used_prefixes = HashSet::new();
    if node.tag_name().namespace().is_some() {
        used_prefixes.insert(prefix.as_deref());
    }
    used_prefixes.extend(
        attributes
            .iter()
            .filter(|attribute| attribute.name.namespace.is_some())
            .map(|attribute| attribute.prefix.as_deref()),
    );
    let namespaces = node
        .namespaces()
        .filter(|n| n.uri() != XSLT_NS)
        .filter(|namespace| {
            used_prefixes.contains(&namespace.name()) || !excluded.contains(namespace.uri())
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
        base_uri: effective_base_uri(node, context.static_base_uri.as_deref())?,
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

fn excluded_result_namespaces(node: roxmltree::Node<'_, '_>) -> Result<HashSet<String>> {
    let mut excluded = HashSet::new();
    if node.ancestors().any(|ancestor| {
        ancestor.has_tag_name((XSLT_NS, "variable")) || ancestor.has_tag_name((XSLT_NS, "param"))
    }) && let Some(stylesheet) = node.ancestors().find(|ancestor| {
        ancestor.has_tag_name((XSLT_NS, "stylesheet"))
            || ancestor.has_tag_name((XSLT_NS, "transform"))
    }) {
        for function in stylesheet.children() {
            if !is_exslt_function_declaration(function)? {
                continue;
            }
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
    let mut forward_compatible = false;
    for ancestor in ancestors {
        if let Some(local) = local_forward_compatible(ancestor)? {
            forward_compatible = local;
        }
        if is_exslt_function_declaration(ancestor)?
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
    let mut tokens = value.split_ascii_whitespace().peekable();
    if tokens.peek().is_none() {
        // XSLT 1.0 sections 7.1.1 and 14.1 define these attributes as token lists, so an
        // explicitly present value must contain a prefix token.
        // https://www.w3.org/TR/1999/REC-xslt-19991116#literal-result-element
        return Err(Error::Static(format!(
            "{attribute} requires at least one namespace prefix token"
        )));
    }
    if tokens.clone().any(|token| token == "#all") {
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
    for token in tokens {
        let prefix = (token != "#default").then_some(token);
        let namespace = node
            .lookup_namespace_uri(prefix)
            .ok_or_else(|| Error::Static(format!("{attribute} prefix {token} is not bound")))?;
        visit(namespace);
    }
    Ok(())
}
fn validate_local_binding_scope(
    node: roxmltree::Node<'_, '_>,
    name: &ExpandedName,
    context: &CompileContext,
) -> Result<()> {
    // This also rejects duplicate leading xsl:param declarations: the first parameter is visible
    // to the second under XSLT 1.0 section 11.5, even when different prefixes expand to one name.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#local-variables
    if !node.has_tag_name((XSLT_NS, "variable")) && !node.has_tag_name((XSLT_NS, "param")) {
        return Ok(());
    }
    let Some(parent) = node.parent_element() else {
        return Ok(());
    };
    if parent.has_tag_name((XSLT_NS, "stylesheet")) || parent.has_tag_name((XSLT_NS, "transform")) {
        return Ok(());
    }

    if context.has_visible_local_binding(node, name) {
        return Err(Error::Static(format!(
            "local binding {} shadows a still-visible template variable",
            name.local
        )));
    }
    Ok(())
}

fn compile_variable(node: roxmltree::Node<'_, '_>, context: CompileContext) -> Result<Variable> {
    validate_instruction_attributes(node, context.forward)?;
    let name = required_qname_attr(node, "name")?;
    validate_local_binding_scope(node, &name, &context)?;
    let select = node
        .attribute("select")
        .map(|value| context.expression(value, node))
        .transpose()?;
    let base_uri = effective_base_uri(node, context.static_base_uri.as_deref())?;
    let content = compile_sequence(node.children(), context.clone())?;
    if select.is_some() && !content.is_empty() {
        return Err(Error::Static(
            "variable with select cannot have content".into(),
        ));
    }
    let variable = Variable {
        name,
        select,
        content,
        base_uri,
    };
    context.register_local_binding(node, variable.name.clone());
    Ok(variable)
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
        forward_compatible: context.forward,
    })
}
fn compile_number(
    node: roxmltree::Node<'_, '_>,
    context: &CompileContext,
) -> Result<NumberInstruction> {
    validate_instruction_attributes(node, context.forward)?;
    require_empty_instruction(node)?;
    let level = match node.attribute("level") {
        None | Some("single") => "single",
        Some(level @ ("multiple" | "any")) => level,
        // XSLT 1.0 section 2.5 requires unsupported values of optional attributes to be ignored
        // during forward-compatible processing, restoring the omitted `level` default.
        // https://www.w3.org/TR/1999/REC-xslt-19991116#forwards
        Some(_) if context.forward => "single",
        Some(level) => {
            return Err(Error::Static(format!(
                "xsl:number level must be single, multiple, or any, got `{level}`"
            )));
        }
    };
    Ok(NumberInstruction {
        value: node
            .attribute("value")
            .map(|value| context.expression(value, node))
            .transpose()?,
        count: node
            .attribute("count")
            .map(|v| Pattern::new(v, node, context.workspace))
            .transpose()?,
        from: node
            .attribute("from")
            .map(|v| Pattern::new(v, node, context.workspace))
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
    while let Some((start, ch)) = chars.next() {
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
                let mut quote = None;
                let end = loop {
                    let Some((end, c)) = chars.next() else {
                        return Err(context
                            .workspace
                            .static_error(format_args!("unterminated attribute value template")));
                    };
                    if matches!(c, '\'' | '"') {
                        if quote == Some(c) {
                            quote = None
                        } else if quote.is_none() {
                            quote = Some(c)
                        }
                    }
                    if c == '}' && quote.is_none() {
                        break end;
                    }
                };
                // XPath 1.0 section 3.7 recognizes only XML S around tokens; Unicode trim
                // would silently reinterpret NBSP and other expression characters as layout.
                // https://www.w3.org/TR/1999/REC-xpath-19991116#exprlex
                parts.push(AvtPart::Expression(
                    context.expression(trim_xml_whitespace(&value[start + 1..end]), node)?,
                ));
            }
            '}' => {
                return Err(context
                    .workspace
                    .static_error(format_args!("unescaped }} in attribute value template")));
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
    forward: bool,
) -> Result<()> {
    // XSLT 1.0 section 16 defines xsl:output with EMPTY content.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#output
    require_empty_instruction(node)?;
    // XSLT 1.0 section 16 selects each scalar output property at highest import precedence;
    // equal-precedence recovery selects the last value. cdata-section-elements is the explicit
    // exception: names from every xsl:output form one union, regardless of import precedence.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#output
    if let Some(method) = node.attribute("method") {
        let method = match method {
            "xml" => Some(OutputMethod::Xml),
            "html" => Some(OutputMethod::Html),
            "text" => Some(OutputMethod::Text),
            // Section 2.5 requires an unsupported optional attribute value to be ignored during
            // forward-compatible processing, leaving the default output method unchanged.
            // https://www.w3.org/TR/1999/REC-xslt-19991116#forwards
            _ if forward => None,
            _ => return Err(Error::Static(format!("unsupported output method {method}"))),
        };
        if method.is_some_and(|method| {
            merge_output_property(&mut out.method, &mut properties.method, method, precedence)
        }) {
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
    if let Some(value) = node
        .attribute("omit-xml-declaration")
        .map(|value| optional_yes_no(value, forward))
        .transpose()?
        .flatten()
    {
        merge_output_property(
            &mut out.omit_xml_declaration,
            &mut properties.omit_xml_declaration,
            value,
            precedence,
        );
    }
    if let Some(value) = node
        .attribute("standalone")
        .map(|value| optional_yes_no(value, forward))
        .transpose()?
        .flatten()
    {
        merge_output_property(
            &mut out.standalone,
            &mut properties.standalone,
            Some(value),
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
    if let Some(value) = node
        .attribute("indent")
        .map(|value| optional_yes_no(value, forward))
        .transpose()?
        .flatten()
        && merge_output_property(&mut out.indent, &mut properties.indent, value, precedence)
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
        let names = v
            .split_ascii_whitespace()
            .map(|name| required_cdata_output_qname(node, name))
            .collect::<Result<Vec<_>>>();
        match names {
            Ok(names) => out.cdata_section_elements.extend(names),
            // Section 2.5 ignores the optional attribute as one property in FCP. Parsing before
            // mutation prevents a valid prefix of an invalid QName list from leaking through.
            // https://www.w3.org/TR/1999/REC-xslt-19991116#forwards
            Err(_) if forward => {}
            Err(error) => return Err(error),
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
    const DECIMAL_SEPARATOR: u16 = 1 << 0;
    const GROUPING_SEPARATOR: u16 = 1 << 1;
    const INFINITY: u16 = 1 << 2;
    const MINUS_SIGN: u16 = 1 << 3;
    const NAN: u16 = 1 << 4;
    const PERCENT: u16 = 1 << 5;
    const PER_MILLE: u16 = 1 << 6;
    const ZERO_DIGIT: u16 = 1 << 7;
    const DIGIT: u16 = 1 << 8;
    const PATTERN_SEPARATOR: u16 = 1 << 9;

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
            specified: [
                ("decimal-separator", Self::DECIMAL_SEPARATOR),
                ("grouping-separator", Self::GROUPING_SEPARATOR),
                ("infinity", Self::INFINITY),
                ("minus-sign", Self::MINUS_SIGN),
                ("NaN", Self::NAN),
                ("percent", Self::PERCENT),
                ("per-mille", Self::PER_MILLE),
                ("zero-digit", Self::ZERO_DIGIT),
                ("digit", Self::DIGIT),
                ("pattern-separator", Self::PATTERN_SEPARATOR),
            ]
            .into_iter()
            .filter_map(|(name, bit)| node.attribute(name).map(|_| bit))
            .fold(0, |mask, bit| mask | bit),
        };
        format.validate()?;
        Ok(format)
    }

    fn merge(&mut self, incoming: Self) -> Result<()> {
        macro_rules! merge_property {
            ($field:ident, $bit:ident) => {
                if incoming.specified & Self::$bit != 0 {
                    if self.specified & Self::$bit != 0 && self.$field != incoming.$field {
                        return Err(self.conflict());
                    }
                    self.$field = incoming.$field;
                }
            };
        }
        merge_property!(decimal_separator, DECIMAL_SEPARATOR);
        merge_property!(grouping_separator, GROUPING_SEPARATOR);
        merge_property!(infinity, INFINITY);
        merge_property!(minus_sign, MINUS_SIGN);
        merge_property!(nan, NAN);
        merge_property!(percent, PERCENT);
        merge_property!(per_mille, PER_MILLE);
        merge_property!(zero_digit, ZERO_DIGIT);
        merge_property!(digit, DIGIT);
        merge_property!(pattern_separator, PATTERN_SEPARATOR);
        self.specified |= incoming.specified;
        self.validate()
    }

    fn validate(&self) -> Result<()> {
        if unicode_decimal_value(self.zero_digit) != Some(0) {
            return Err(Error::Static(
                "xsl:decimal-format zero-digit must have Unicode decimal value zero".into(),
            ));
        }
        let syntax = [
            ("decimal-separator", self.decimal_separator),
            ("grouping-separator", self.grouping_separator),
            ("percent", self.percent),
            ("per-mille", self.per_mille),
            ("zero-digit", self.zero_digit),
            ("digit", self.digit),
            ("pattern-separator", self.pattern_separator),
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
        Ok(())
    }

    fn conflict(&self) -> Error {
        Error::Static(format!(
            "conflicting xsl:decimal-format declaration for {}",
            self.name
                .as_ref()
                .map_or("the default format", |name| name.local.as_str())
        ))
    }
}

fn validate_key_dependency_expression(
    attribute: &str,
    source: &str,
    workspace: CompileWorkspace<'_>,
) -> Result<()> {
    if contains_variable_reference(source) {
        return Err(workspace.static_error(format_args!(
            "xsl:key {attribute} must not contain a variable reference"
        )));
    }
    if crate::expression::has_unprefixed_function_call(source, "key") {
        return Err(workspace.static_error(format_args!("xsl:key {attribute} must not call key()")));
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
            attributes: attributes.into(),
            precedence,
            order,
        })
    }
}
fn namespaces(node: roxmltree::Node<'_, '_>) -> Vec<(String, String)> {
    let count = node
        .namespaces()
        .filter(|namespace| namespace.name().is_some())
        .count();
    let mut result = Vec::with_capacity(count);
    for namespace in node.namespaces() {
        if let Some(prefix) = namespace.name() {
            result.push((prefix.into(), namespace.uri().into()));
        }
    }
    result
}

fn namespace_copy_bytes(
    node: roxmltree::Node<'_, '_>,
    shared: bool,
    workspace: CompileWorkspace<'_>,
) -> Result<usize> {
    let mut bytes = 0usize;
    for namespace in node.namespaces() {
        if let Some(prefix) = namespace.name() {
            bytes = bytes
                .checked_add(std::mem::size_of::<(String, String)>())
                .and_then(|bytes| bytes.checked_add(prefix.len()))
                .and_then(|bytes| bytes.checked_add(namespace.uri().len()))
                .ok_or_else(|| workspace.overflow())?;
        }
    }
    if shared {
        bytes = bytes
            .checked_add(std::mem::size_of::<Vec<(String, String)>>())
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<usize>()))
            .ok_or_else(|| workspace.overflow())?;
    }
    if bytes > isize::MAX as usize {
        return Err(workspace.overflow());
    }
    Ok(bytes)
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
        // Namespaces in XML 1.0 section 2 permits URI references, and RFC 2396 section 4
        // classifies a fragment-only reference as relative; XSLT 1.0 does not narrow it.
        // https://www.w3.org/TR/REC-xml-names/#ns-decl
        // https://www.rfc-editor.org/rfc/rfc2396#section-4
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
    lexical_prefix_at(
        node.document().input_text(),
        attribute.range().start,
        attribute.name(),
    )
}

fn element_prefix(node: roxmltree::Node<'_, '_>) -> Option<String> {
    lexical_prefix_at(
        node.document().input_text(),
        node.range().start.saturating_add(1),
        node.tag_name().name(),
    )
}

fn lexical_prefix_at(source: &str, offset: usize, local: &str) -> Option<String> {
    let lexical = source
        .get(offset..)?
        .split(|character: char| {
            character.is_ascii_whitespace() || matches!(character, '=' | '/' | '>')
        })
        .next()?;
    lexical
        .strip_suffix(local)?
        .strip_suffix(':')
        .map(str::to_owned)
}

fn instruction_yes_no(
    node: roxmltree::Node<'_, '_>,
    name: &str,
    forward_compatible: bool,
) -> Result<bool> {
    // XSLT 1.0 section 2.5 requires unsupported optional attribute values to be
    // ignored in forward-compatible mode, which restores the attribute default.
    // https://www.w3.org/TR/1999/REC-xslt-19991116#forwards
    node.attribute(name)
        .map(|value| optional_yes_no(value, forward_compatible))
        .transpose()
        .map(|value| value.flatten().unwrap_or(false))
}

fn optional_yes_no(value: &str, forward_compatible: bool) -> Result<Option<bool>> {
    match value {
        "yes" => Ok(Some(true)),
        "no" => Ok(Some(false)),
        _ if forward_compatible => Ok(None),
        _ => Err(Error::Static(format!("expected yes or no, got {value}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_base_uri_copy_is_charged_by_retained_capacity() {
        let budget = CompileBudget::new(4096, 0, 32, 4096);
        let mut state = CompileState::new(budget, 0);
        let uri = "memory:principal/".repeat(32);

        let retained = clone_compile_string(Some(&uri), &mut state)
            .expect("principal URI fits the compiler budget")
            .expect("principal URI is retained");

        assert_eq!(retained, uri);
        assert_eq!(state.owned_bytes, retained.capacity());
    }

    #[test]
    fn xpath_diagnostics_reserve_the_exact_formatted_length() {
        // Prefix diagnostics preserve their text when it fits and fail before formatting otherwise.
        let source = "missing:item";
        let expected = "XPath expression `missing:item` uses unbound namespace prefix `missing`";
        let retained = std::cell::Cell::new(0);
        for limit in [expected.len() - 1, expected.len()] {
            let workspace = CompileWorkspace {
                limit,
                occupied: 0,
                retained: &retained,
            };
            let error = validate_xpath_prefixes(source, &[], workspace)
                .expect_err("unbound prefix produces a static or budget error");
            if limit == expected.len() {
                assert!(matches!(error, Error::Static(message) if message == expected));
            } else {
                assert!(matches!(error, Error::Budget { actual, .. } if actual == expected.len()));
            }
        }
    }

    #[test]
    fn xpath_parser_diagnostic_accounts_for_owned_token_and_escaping() {
        // Debug escaping expands a token. Measure the rendered diagnostic, not source length,
        // and keep the unexpected token's string charged until formatting finishes.
        let source = "f(1 'a\nb')";
        let error = sxd_xpath_no_unsafe::Factory::new()
            .build(source)
            .expect_err("missing argument separator leaves an unexpected literal token");
        assert_eq!(error.owned_bytes(), 3);
        let message = format!("invalid XPath expression `{source}`: {error}");
        let required = message.len() + error.owned_bytes();
        let retained = Cell::new(0);
        let workspace = CompileWorkspace {
            limit: required - 1,
            occupied: 0,
            retained: &retained,
        };
        assert!(
            matches!(workspace.parser_error(error.clone(), source, false),
            Error::Budget { actual, .. } if actual == required)
        );
        let workspace = CompileWorkspace {
            limit: required,
            ..workspace
        };
        assert!(matches!(workspace.parser_error(error, source, false),
            Error::Static(actual) if actual == message));
    }

    #[test]
    fn xpath_namespace_copies_and_reference_conversion_are_charged() {
        // Each pattern owns a namespace copy. References duplicate namespace strings, but dedup
        // frees duplicates before the Vec-to-Arc overlap and retained charge are calculated.
        let document = roxmltree::Document::parse(r#"<root xmlns:p="urn:namespace"/>"#)
            .expect("namespace accounting fixture parses");
        let node = document.root_element();
        let retained = Cell::new(0);
        let workspace = CompileWorkspace {
            limit: 16_384,
            occupied: 0,
            retained: &retained,
        };
        let namespaces = namespaces(node);
        let copy_bytes = namespaces.capacity() * std::mem::size_of::<(String, String)>()
            + namespaces
                .iter()
                .map(|(prefix, uri)| prefix.capacity() + uri.capacity())
                .sum::<usize>();
        assert_eq!(
            namespace_copy_bytes(node, false, workspace)
                .expect("namespace copy size fits the workspace"),
            copy_bytes
        );
        let first =
            Pattern::new("p:a", node, workspace).expect("first pattern and namespace copy fit");
        let second = Pattern::new("p:b", node, workspace)
            .expect("second pattern and namespace copy fit alongside the first");
        assert_eq!(
            retained.get(),
            2 * copy_bytes + first.source.capacity() + second.source.capacity()
        );

        let names = [("p".to_owned(), "urn:namespace".to_owned())];
        let unit = std::mem::size_of::<ExpandedName>();
        let payload = "urn:namespace".len() + 1;
        let arc = 2 * unit + 2 * std::mem::size_of::<usize>();
        let peak = (3 * unit + 3 * payload).max(3 * unit + 2 * payload + arc);
        for limit in [peak - 1, peak] {
            let retained = Cell::new(0);
            let workspace = CompileWorkspace {
                limit,
                occupied: 0,
                retained: &retained,
            };
            let result = referenced_variables_bounded("$p:a + $p:a + $p:b", &names, workspace);
            if limit == peak {
                assert_eq!(
                    result.expect("exact reference-conversion peak fits").len(),
                    2
                );
                assert_eq!(retained.get(), arc + 2 * payload);
            } else {
                assert!(matches!(result, Err(Error::Budget { actual, .. }) if actual == peak));
            }
        }
    }

    #[test]
    fn included_literal_reuses_future_source_storage_during_validation() {
        // Import discovery and compilation share one decode. The validation literal and retained
        // expression source are not live together and must not require a seventh payload copy.
        let payload = "x".repeat(64 * 1024);
        let module = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:variable name="payload" select="'{payload}'"/></xsl:stylesheet>"#
        );
        let principal = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:include href="module.xsl"/></xsl:stylesheet>"#;
        Compiler::new(
            Arc::new(RepeatedIncludeResolver {
                module: module.into_bytes(),
                encoding: None,
            }),
            CompileBudget::new(1 << 20, 8, 256, 450 * 1024),
        )
        .compile(principal, Some("memory:main.xsl"))
        .expect("one decoded source and nonoverlapping XPath storage fit");
    }

    #[test]
    fn xpath_source_credit_is_limited_to_its_borrowed_attribute_slice() {
        // Equal text is not proof of precharged storage. Generated defaults and independent
        // strings cannot borrow another attribute's reservation, even if their values match.
        let document = roxmltree::Document::parse(r#"<root select="'payload'"/>"#)
            .expect("source-credit fixture parses");
        let node = document.root_element();
        let source = node
            .attribute("select")
            .expect("fixture has a select attribute");
        let retained = Cell::new(0);
        let workspace = CompileWorkspace {
            limit: 4096,
            occupied: source.len(),
            retained: &retained,
        };
        assert_eq!(workspace.pending_source(source, node).occupied, 0);
        assert_eq!(workspace.pending_source(&source[1..8], node).occupied, 2);
        let independent = source.to_owned();
        assert_eq!(
            workspace.pending_source(&independent, node).occupied,
            source.len()
        );
        assert_eq!(
            workspace.pending_source("node()", node).occupied,
            source.len()
        );
    }

    #[test]
    fn xpath_prefix_scan_preserves_unicode_axes_and_literals() {
        // Byte offsets must remain UTF-8 boundaries; axes and quoted colons are not prefixes.
        let retained = Cell::new(0);
        let workspace = CompileWorkspace {
            limit: 4096,
            occupied: 0,
            retained: &retained,
        };
        let namespaces = vec![("\u{3c0}".into(), "urn:test".into())];
        for source in [
            "child::\u{3c0}:item/@xml:lang",
            "\u{3c0}:*",
            "concat('missing:name', \"other:*\")",
        ] {
            validate_xpath_prefixes(source, &namespaces, workspace)
                .expect("bound prefixes are accepted");
        }
        let source = "child::\u{3bb}:item";
        assert!(matches!(
            validate_xpath_prefixes(source, &namespaces, workspace),
            Err(Error::Static(message)) if message == format!(
                "XPath expression `{source}` uses unbound namespace prefix `\u{3bb}`"
            )
        ));
    }

    #[test]
    fn xpath_normalization_preserves_tokens_and_bounds_capacity() {
        // Preserve literals and non-XML whitespace while adapting axes, calls and wildcards.
        for (source, expected) in [
            ("child \t:: \n\u{3c0}:item", "child::\u{3c0}:item"),
            ("count \r( * )", "count( child::* )"),
            ("f(*, *, ' * :: ( ')", "f(child::*, child::*, ' * :: ( ')"),
            ("2 * 3", "2 * 3"),
            ("f\u{a0}(*)", "f\u{a0}(child::*)"),
        ] {
            let normalized = normalize_xpath_for_sxd(source);
            assert_eq!(normalized.as_ref(), expected);
            if let Cow::Owned(output) = normalized {
                assert_eq!(output.capacity(), expected.len());
            }
        }
        for source in ["\u{3c0}:item", "' * :: ( '", "2 * 3"] {
            assert!(matches!(normalize_xpath_for_sxd(source), Cow::Borrowed(_)));
        }
    }

    #[test]
    fn large_literal_attributes_do_not_reserve_xpath_grammar_workspace() {
        // Neither a literal AVT nor one quoted XPath literal represents a million AST nodes.
        let payload = "x".repeat(1 << 20);
        for value in [payload.clone(), format!("{{'{payload}'}}")] {
            let xml = format!(
                r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><out value="{value}"/></xsl:template></xsl:stylesheet>"#
            );
            Compiler::new(
                Arc::new(crate::NoResolver),
                CompileBudget::new(2 << 20, 0, 32, 32 << 20),
            )
            .compile(&xml, None)
            .expect("literal storage fits without fictitious grammar work");
        }
    }

    #[test]
    fn small_compile_budgets_preserve_static_error_contracts() {
        // This previously failed at the speculative module reservation before syntax checking.
        let xml = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:apply-templates>invalid</xsl:apply-templates></xsl:template></xsl:stylesheet>"#;
        assert!(
            matches!(Compiler::new(Arc::new(crate::NoResolver), CompileBudget::new(4096, 0, 32, 16_384)).compile(xml, None), Err(Error::Static(message)) if message == "xsl:apply-templates accepts only xsl:sort and xsl:with-param")
        );
    }

    #[test]
    fn xpath_compile_workspace_precedes_validation_and_is_released() {
        // Actual token/AST allocations, not a module estimate, must cross the allocation gate.
        let retained = Cell::new(0);
        let workspace = CompileWorkspace {
            limit: 128,
            occupied: 128,
            retained: &retained,
        };
        assert!(matches!(
            workspace.parse_xpath("'payload'", "'payload'", false),
            Err(Error::Budget {
                kind: BudgetKind::OwnedBytes,
                limit: 128,
                actual: 135
            })
        ));
        let workspace = CompileWorkspace {
            limit: 4096,
            occupied: 128,
            retained: &retained,
        };
        for _ in 0..100 {
            workspace
                .parse_xpath("'payload'", "'payload'", false)
                .expect("dropped AST releases its allowance");
            assert!(matches!(
                workspace.parse_xpath("1 +", "1 +", false),
                Err(Error::Static(_))
            ));
        }
        assert_eq!(workspace.occupied, 128);
    }

    #[test]
    fn xpath_compile_workspace_covers_patterns_keys_and_avts() {
        // Direct Pattern/Expression constructors and context-based AVTs must share the gate.
        for body in [
            r#"<xsl:template match="child :: item[count( * )]"/>"#,
            r#"<xsl:key name="k" match="item" use="count( * )"/>"#,
            r#"<xsl:template match="/"><out value="{count( * )}"/></xsl:template>"#,
            r#"<xsl:template match="/"><xsl:number count="child :: item"/></xsl:template>"#,
        ] {
            let xml = format!(
                r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">{body}</xsl:stylesheet>"#
            );
            let document = roxmltree::Document::parse(&xml).expect("XML parses");
            let required =
                parser_workspace_bytes(&xml) + estimate_compiled_owned_bytes(&document, None);
            assert!(matches!(
                Compiler::new(
                    Arc::new(crate::NoResolver),
                    CompileBudget::new(xml.len(), 0, 32, required),
                ).compile(&xml, None),
                Err(Error::Budget { kind: BudgetKind::OwnedBytes, actual, .. })
                    if actual > required
            ));
            Compiler::new(
                Arc::new(crate::NoResolver),
                CompileBudget::new(xml.len(), 0, 32, 4 << 20),
            )
            .compile(&xml, None)
            .expect("the same source compiles with sufficient workspace");
        }
    }

    struct RepeatedIncludeResolver {
        module: Vec<u8>,
        encoding: Option<String>,
    }

    struct FragmentModuleResolver {
        module: Vec<u8>,
    }

    impl Resolver for RepeatedIncludeResolver {
        fn resolve(&self, request: crate::ResolveRequest<'_>) -> Result<ResolvedResource> {
            let crate::ResolveRequest { uri, purpose, .. } = request;
            assert_eq!(uri, "module.xsl");
            assert_eq!(purpose, ResolvePurpose::Include);
            Ok(ResolvedResource {
                canonical_uri: "memory:module.xsl".into(),
                identity: ResourceIdentity("repeated-module".into()),
                bytes: self.module.clone(),
                media_type: Some("application/xslt+xml".into()),
                encoding: self.encoding.clone(),
            })
        }
    }

    impl Resolver for FragmentModuleResolver {
        fn resolve(&self, request: crate::ResolveRequest<'_>) -> Result<ResolvedResource> {
            assert_eq!(request.uri, "module.xml");
            assert!(matches!(
                request.purpose,
                ResolvePurpose::Include | ResolvePurpose::Import
            ));
            Ok(ResolvedResource {
                canonical_uri: "memory:module.xml".into(),
                identity: ResourceIdentity("fragment-module".into()),
                bytes: self.module.clone(),
                media_type: Some("application/xml".into()),
                encoding: Some("UTF-8".into()),
            })
        }
    }

    fn embedded_stylesheet_module(ids: (&str, &str)) -> Vec<u8> {
        format!(
            r#"<bundle xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:stylesheet id="{}" version="1.0"><xsl:template name="ignored"/></xsl:stylesheet><xsl:stylesheet id="{}" version="1.0"><xsl:template name="selected"/></xsl:stylesheet></bundle>"#,
            ids.0, ids.1
        )
        .into_bytes()
    }

    #[test]
    fn many_distinct_local_bindings_compile_with_one_scope_index() {
        // A wide lexical scope must use the incremental binding index rather than rescanning all
        // preceding siblings for every declaration.
        let mut body = String::new();
        for index in 0..2_048 {
            use std::fmt::Write as _;
            write!(body, r#"<xsl:variable name="v{index}" select="{index}"/>"#)
                .expect("writing to a String succeeds");
        }
        let stylesheet = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/">{body}</xsl:template></xsl:stylesheet>"#
        );

        Compiler::new(
            Arc::new(crate::NoResolver),
            CompileBudget::new(8 << 20, 4, 32, 16 << 20),
        )
        .compile(&stylesheet, None)
        .expect("distinct bindings compile without repeated sibling scans");
    }

    #[test]
    fn include_and_import_select_the_referenced_embedded_stylesheet() {
        // XSLT 1.0 sections 2.6 and 2.7 make the fragment identify an embedded stylesheet;
        // fetching the containing XML resource must not compile its document element instead.
        // https://www.w3.org/TR/1999/REC-xslt-19991116#embedded
        for instruction in ["include", "import"] {
            let principal = format!(
                r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:{instruction} href="module.xml#target"/></xsl:stylesheet>"#
            );
            let stylesheet = Compiler::new(
                Arc::new(FragmentModuleResolver {
                    module: embedded_stylesheet_module(("other", "target")),
                }),
                CompileBudget::new(1 << 20, 4, 16, 1 << 20),
            )
            .compile(&principal, Some("memory:main.xsl"))
            .expect("fragment-targeted module compiles");

            assert!(
                stylesheet
                    .named_template_index
                    .contains_key(&ExpandedName::new(None::<String>, "selected"))
            );
            assert!(
                !stylesheet
                    .named_template_index
                    .contains_key(&ExpandedName::new(None::<String>, "ignored"))
            );
        }
    }

    #[test]
    fn include_and_import_resolve_normalized_xml_id_fragments() {
        // xml:id 1.0 section 4 assigns ID type after ID whitespace normalization, so embedded
        // stylesheet lookup must not depend on an unqualified compatibility `id` attribute.
        // https://www.w3.org/TR/2005/REC-xml-id-20050909/#processing
        for instruction in ["include", "import"] {
            let principal = format!(
                r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:{instruction} href="module.xml#target"/></xsl:stylesheet>"#
            );
            let module = br#"<bundle xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:stylesheet xml:id="  target  " version="1.0"><xsl:template name="selected"/></xsl:stylesheet></bundle>"#.to_vec();
            let stylesheet = Compiler::new(
                Arc::new(FragmentModuleResolver { module }),
                CompileBudget::new(1 << 20, 4, 16, 1 << 20),
            )
            .compile(&principal, Some("memory:main.xsl"))
            .expect("normalized xml:id identifies the embedded stylesheet");

            assert!(
                stylesheet
                    .named_template_index
                    .contains_key(&ExpandedName::new(None::<String>, "selected"))
            );
        }
    }

    #[test]
    fn include_and_import_decode_utf8_embedded_stylesheet_fragments() {
        // XPointer Framework appendix B encodes non-ASCII pointer characters as UTF-8 octets;
        // module selection must compare the decoded identifier.
        // https://www.w3.org/TR/2003/REC-xptr-framework-20030325/#escaping
        for instruction in ["include", "import"] {
            let principal = format!(
                r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:{instruction} href="module.xml#caf%C3%A9"/></xsl:stylesheet>"#
            );
            let stylesheet = Compiler::new(
                Arc::new(FragmentModuleResolver {
                    module: embedded_stylesheet_module(("other", "café")),
                }),
                CompileBudget::new(1 << 20, 4, 16, 1 << 20),
            )
            .compile(&principal, Some("memory:main.xsl"))
            .expect("percent-encoded UTF-8 fragment selects the embedded stylesheet");

            assert!(
                stylesheet
                    .named_template_index
                    .contains_key(&ExpandedName::new(None::<String>, "selected"))
            );
        }
    }

    #[test]
    fn stylesheet_module_fragments_reject_malformed_percent_encoding() {
        for (fragment, expected) in [
            ("truncated%", "truncated percent escape"),
            ("incomplete%C3%", "truncated percent escape"),
            ("invalid%GG", "invalid percent escape"),
            ("%FF", "not valid UTF-8"),
        ] {
            let principal = format!(
                r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:include href="module.xml#{fragment}"/></xsl:stylesheet>"#
            );
            let error = Compiler::new(
                Arc::new(FragmentModuleResolver {
                    module: embedded_stylesheet_module(("other", "target")),
                }),
                CompileBudget::new(1 << 20, 4, 16, 1 << 20),
            )
            .compile(&principal, Some("memory:main.xsl"))
            .expect_err("malformed fragment must be rejected");
            assert!(
                error.to_string().contains(expected),
                "fragment {fragment:?} returned unexpected error: {error}"
            );
        }
    }

    #[test]
    fn stylesheet_fragment_must_identify_one_unique_element() {
        let compile = |module, fragment| {
            Compiler::new(
                Arc::new(FragmentModuleResolver { module }),
                CompileBudget::new(1 << 20, 4, 16, 1 << 20),
            )
            .compile(
                &format!(
                    r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:include href="module.xml#{fragment}"/></xsl:stylesheet>"#
                ),
                Some("memory:main.xsl"),
            )
        };

        assert!(matches!(
            compile(embedded_stylesheet_module(("other", "target")), "missing"),
            Err(Error::Static(message)) if message.contains("does not identify")
        ));
        assert!(matches!(
            compile(embedded_stylesheet_module(("same", "same")), "same"),
            Err(Error::Static(message)) if message.contains("not unique")
        ));
        assert!(matches!(
            compile(
                br#"<bundle xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:stylesheet id="same" version="1.0"/><xsl:stylesheet xml:id="same" version="1.0"/></bundle>"#.to_vec(),
                "same"
            ),
            Err(Error::Static(message)) if message.contains("not unique")
        ));
        assert!(matches!(
            compile(
                br#"<bundle><not-a-stylesheet id="target"/></bundle>"#.to_vec(),
                "target"
            ),
            Err(Error::Static(message)) if message.contains("does not identify xsl:stylesheet")
        ));
    }

    #[test]
    fn frontend_workspace_accounts_for_every_parser_arena() {
        // roxmltree preallocates node and attribute vectors from lexical delimiters and retains
        // depth/namespace workspaces while parsing. The preflight must dominate all of them.
        let xml = r#"<root xmlns:p="urn:test" a="value"><p:child/></root>"#;
        let node_slots = xml.bytes().filter(|byte| *byte == b'<').count();
        let attribute_slots = xml.bytes().filter(|byte| *byte == b'=').count();
        let lexical_only = xml.len();
        let nodes_only = lexical_only.saturating_add(node_slots);
        let attributes_only = nodes_only.saturating_add(attribute_slots);

        assert!(parser_workspace_bytes(xml) > attributes_only);
    }

    #[test]
    fn compiled_stylesheets_share_the_function_lookup_index() {
        // Function declarations are immutable compiled state; executions must not rebuild or clone
        // their lookup keys under the operation budget.
        let stylesheet = Compiler::new(
            Arc::new(crate::NoResolver),
            CompileBudget::new(1 << 20, 0, 32, 1 << 20),
        )
        .compile(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:func="http://exslt.org/functions" xmlns:f="urn:functions" extension-element-prefixes="func"><func:function name="f:value"><func:result select="'ok'"/></func:function></xsl:stylesheet>"#,
            None,
        )
        .expect("function stylesheet compiles");
        let cloned = stylesheet.clone();

        assert!(
            stylesheet
                .function_names
                .contains(&ExpandedName::new(Some("urn:functions"), "value"))
        );
        assert!(Arc::ptr_eq(
            &stylesheet.function_names,
            &cloned.function_names
        ));
    }

    #[test]
    fn compiled_stylesheets_index_unique_keys_and_named_templates() {
        // Runtime dispatch must borrow declarations from immutable compiled state instead of
        // rebuilding owned name collections for every key() or xsl:call-template invocation.
        let stylesheet = Compiler::new(
            Arc::new(crate::NoResolver),
            CompileBudget::new(1 << 20, 0, 32, 1 << 20),
        )
        .compile(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:key name="a" match="a" use="."/><xsl:key name="a" match="b" use="."/><xsl:key name="b" match="b" use="."/><xsl:template name="target"/><xsl:template match="/"/></xsl:stylesheet>"#,
            None,
        )
        .expect("indexed stylesheet compiles");
        let cloned = stylesheet.clone();

        assert_eq!(stylesheet.key_name_indices.as_ref(), &[0, 2]);
        let target = ExpandedName::new(None::<String>, "target");
        assert_eq!(
            stylesheet.templates[*stylesheet
                .named_template_index
                .get(&target)
                .expect("named template is indexed")]
            .name
            .as_ref(),
            Some(&target)
        );
        assert!(Arc::ptr_eq(
            &stylesheet.named_template_index,
            &cloned.named_template_index
        ));
        assert!(Arc::ptr_eq(
            &stylesheet.key_name_indices,
            &cloned.key_name_indices
        ));
    }

    #[test]
    fn expressions_on_one_node_share_their_namespace_snapshot() {
        // A literal result element can contain many AVTs. Sharing one immutable static namespace
        // context prevents retained memory from growing as expressions times namespaces.
        let source = r#"<root xmlns:p="urn:namespace"/>"#;
        let document = roxmltree::Document::parse(source).expect("stylesheet fragment parses");
        let root = document.root_element();
        let retained = Cell::new(0);
        let context = CompileContext::new(
            false,
            0,
            8,
            Some("memory:shared-base/"),
            CompileWorkspace {
                limit: 16_384,
                occupied: 0,
                retained: &retained,
            },
        )
        .expect("context is valid");
        let first = context
            .expression("p:first", root)
            .expect("expression compiles");
        let second = context
            .expression("p:second", root)
            .expect("expression compiles");

        assert!(Arc::ptr_eq(&first.namespaces, &second.namespaces));
        assert!(Arc::ptr_eq(
            first
                .static_base_uri
                .as_ref()
                .expect("base URI is retained"),
            second
                .static_base_uri
                .as_ref()
                .expect("base URI is retained"),
        ));
    }

    #[test]
    fn decoded_workspace_uses_live_string_capacity() {
        let mut decoded = String::with_capacity(4_096);
        decoded.push_str("<xsl:stylesheet/>");
        let capacity = decoded.capacity();

        let (decoded, workspace) = classify_decoded_workspace(Cow::Owned(decoded));
        assert_eq!(workspace, capacity);
        assert_eq!(decoded.as_ref(), "<xsl:stylesheet/>");

        let (decoded, workspace) = classify_decoded_workspace(Cow::Borrowed("<x/>"));
        assert_eq!(workspace, 0);
        assert_eq!(decoded.as_ref(), "<x/>");
    }

    #[test]
    fn repeated_includes_charge_each_retained_declaration_expansion() {
        // XSLT 1.0 section 2.6.1 instantiates included declarations at every include point. A
        // cached source document therefore cannot make repeated compiled IR free.
        // https://www.w3.org/TR/1999/REC-xslt-19991116#include
        let body = "x".repeat(32 * 1_024);
        let module = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="item"><out>{body}</out></xsl:template></xsl:stylesheet>"#
        );
        let includes = r#"<xsl:include href="module.xsl"/>"#.repeat(32);
        let principal = format!(
            r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">{includes}</xsl:stylesheet>"#
        );
        let compiler = Compiler::new(
            Arc::new(RepeatedIncludeResolver {
                module: module.into_bytes(),
                encoding: Some("UTF-8".into()),
            }),
            CompileBudget::new(1 << 20, 64, 16, 768 * 1_024),
        );

        assert!(matches!(
            compiler.compile(&principal, Some("memory:main.xsl")),
            Err(Error::Budget {
                kind: BudgetKind::OwnedBytes,
                ..
            })
        ));
    }

    #[test]
    fn imported_modules_apply_stylesheet_budget_after_decoding() {
        // A single-byte source encoding can expand in UTF-8. The compiled stylesheet budget
        // measures the decoded XML consumed by the parser, not only resolver wire bytes.
        let prefix = br#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><out>"#;
        let suffix = b"</out></xsl:template></xsl:stylesheet>";
        let mut module = Vec::from(prefix.as_slice());
        module.extend(std::iter::repeat_n(0xe9, 64));
        module.extend_from_slice(suffix);
        let principal = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:include href="module.xsl"/></xsl:stylesheet>"#;
        let raw_total = principal.len() + module.len();
        let compiler = Compiler::new(
            Arc::new(RepeatedIncludeResolver {
                module,
                encoding: Some("windows-1252".into()),
            }),
            CompileBudget::new(raw_total, 1, 4, usize::MAX),
        );

        assert!(matches!(
            compiler.compile(principal, Some("memory:main.xsl")),
            Err(Error::Budget {
                kind: BudgetKind::StylesheetBytes,
                limit,
                actual,
            }) if limit == raw_total && actual > limit
        ));
    }

    #[test]
    fn frontend_workspace_is_rejected_before_parsing() {
        // A malformed input must still report the exhausted allocation gate first: the frontend
        // parser is not allowed to allocate merely to discover a later syntax error.
        let xml = "<stylesheet>";
        let required = parser_workspace_bytes(xml);
        let mut state =
            CompileState::new(CompileBudget::new(xml.len(), 0, 1, required - 1), xml.len());

        assert!(matches!(
            with_frontend_document(xml, &mut state, |_document, _state| Ok(())),
            Err(Error::Budget {
                kind: BudgetKind::OwnedBytes,
                actual,
                ..
            }) if actual == required
        ));
    }

    #[test]
    fn frontend_workspace_preflights_internal_entity_expansion() {
        // The compiler must account for the entity-expanded source before constructing the
        // frontend DOM; otherwise a short lexical input can allocate far beyond owned_bytes.
        let replacement = "x".repeat(1_024);
        let references = "&payload;".repeat(64);
        let xml = format!(
            r#"<!DOCTYPE xsl:stylesheet [<!ENTITY payload "{replacement}">]><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><out>{references}</out></xsl:template></xsl:stylesheet>"#
        );
        let lexical_workspace = parser_workspace_bytes(&xml);
        let mut state = CompileState::new(
            CompileBudget::new(xml.len(), 0, 8, lexical_workspace + replacement.len()),
            xml.len(),
        );

        assert!(matches!(
            with_frontend_document(&xml, &mut state, |_document, _state| Ok(())),
            Err(Error::Budget {
                kind: BudgetKind::OwnedBytes,
                ..
            })
        ));
    }

    #[test]
    fn semantic_projection_reserves_the_second_parser_workspace() {
        // The semantic parse overlaps retained compile state, so its transient arena must fit the
        // remaining peak budget rather than relying on the earlier frontend parse reservation.
        let xml = r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"/></xsl:stylesheet>"#;
        let parsed = roxmltree::Document::parse(xml).expect("test stylesheet parses");
        let retained = xml
            .len()
            .saturating_add(estimate_compiled_owned_bytes(&parsed, None));
        let parser_workspace = parser_workspace_bytes(xml);
        let mut state = CompileState::new(
            CompileBudget::new(
                xml.len(),
                0,
                8,
                retained.saturating_add(parser_workspace).saturating_sub(1),
            ),
            xml.len(),
        );

        assert!(matches!(
            parse_semantic_document_metered(xml, None, &mut state),
            Err(Error::Budget {
                kind: BudgetKind::OwnedBytes,
                ..
            })
        ));
    }
}
