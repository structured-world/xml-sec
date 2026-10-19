//! XSLT transform adapter (XMLDSig 1.1 section 6.6.5).
//!
//! <https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-XSLT>

use std::cell::Cell;
use std::sync::Arc;

use super::{ExecutionData, TransformError, TransformExecutionBudget, TransformScratch};
use crate::c14n::scratch::Bytes as _;
use crate::document::{DocumentParseSettings, XmlDocumentError, XmlParseWorkBudget};
use crate::policy::{PolicyViolation, ResourcePolicy, XsltStylesheetSemantics, resource_name};
use crate::xml::dom::storage::Storage as DomStorage;
use crate::xslt::{
    BudgetKind, CompileBudget, Compiler, Document, Error, ExecutionBudget, ExecutionEnvironment,
    ExecutionOptions, ExecutionUsage, NoResolver, Parameters, ParseBudget, ParseUsage, Reported,
    UnboundPrefixLists,
};

#[cfg(test)]
mod tests;

/// Work kinds that `ResourcePolicy::max_xslt_work` bounds independently.
const WORK_KINDS: [BudgetKind; 9] = [
    BudgetKind::XPathEvaluations,
    BudgetKind::XPathOperations,
    BudgetKind::ExtensionOperations,
    BudgetKind::PatternEvaluations,
    BudgetKind::TemplateApplications,
    BudgetKind::SortComparisons,
    BudgetKind::KeyEntries,
    BudgetKind::ResultNodes,
    BudgetKind::Messages,
];

fn admitted(usage: &ExecutionUsage, kind: BudgetKind) -> usize {
    match kind {
        BudgetKind::XPathEvaluations => usage.xpath_evaluations,
        BudgetKind::XPathOperations => usage.xpath_operations,
        BudgetKind::ExtensionOperations => usage.extension_operations,
        BudgetKind::PatternEvaluations => usage.pattern_evaluations,
        BudgetKind::TemplateApplications => usage.template_applications,
        BudgetKind::SortComparisons => usage.sort_comparisons,
        BudgetKind::KeyEntries => usage.key_entries,
        BudgetKind::ResultNodes => usage.result_nodes,
        BudgetKind::Messages => usage.messages,
        _ => 0,
    }
}

/// The `xsl:stylesheet` parameter of an XSLT transform, kept as the markup the
/// `<Transform>` element contains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XsltStylesheet {
    source: String,
    parsed: Option<ParsedStylesheet>,
}

/// The stylesheet element of a parsed `<Transform>`, serialized from the tree.
///
/// Entity references and character references are already replaced, so the
/// stylesheet compiles without the document's DTD (XML 1.0 section 4.4).
/// <https://www.w3.org/TR/2008/REC-xml-20081126/#entproc>
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ParsedStylesheet {
    /// The stylesheet with the namespace declarations written on its elements.
    document: String,
    /// Declarations in scope at the `<Transform>` that the stylesheet element does
    /// not make itself, serialized as attributes.
    inherited: String,
    /// Offset in `document` just after the stylesheet element's name.
    at: usize,
}

impl ParsedStylesheet {
    /// The stylesheet document `semantics` compiles.
    ///
    /// The stylesheet is an element of the signed document: every namespace in
    /// scope at it, including those declared on its ancestors (Namespaces in XML
    /// 1.0 section 6.1), is a namespace node of its elements that literal result
    /// elements copy (XSLT 1.0 section 7.1.1). libxmlsec1 compiles the element
    /// with only the declarations written inside it.
    /// <https://www.w3.org/TR/1999/REC-xslt-19991116#literal-result-element>
    fn text(&self, semantics: XsltStylesheetSemantics) -> std::borrow::Cow<'_, str> {
        match semantics {
            XsltStylesheetSemantics::Specification if !self.inherited.is_empty() => {
                let (head, tail) = self.document.split_at(self.at);
                std::borrow::Cow::Owned([head, &self.inherited, tail].concat())
            }
            _ => std::borrow::Cow::Borrowed(&self.document),
        }
    }
}

/// An XSLT transform parameter as the executor reads it.
#[derive(Clone, Copy)]
pub(crate) enum XsltParameter<'a> {
    /// A stylesheet held by an owned transform.
    Stylesheet(&'a XsltStylesheet),
    /// The `<Transform>` element of a parsed document.
    Transform(crate::xml::dom::Node<'a, 'a>),
}

impl<'a> XsltParameter<'a> {
    /// The stylesheet document `semantics` compiles.
    fn document(self, semantics: XsltStylesheetSemantics) -> Option<std::borrow::Cow<'a, str>> {
        match self {
            Self::Stylesheet(stylesheet) => Some(match &stylesheet.parsed {
                Some(parsed) => parsed.text(semantics),
                // Markup given to `XsltStylesheet::new` has no enclosing document.
                None => std::borrow::Cow::Borrowed(&stylesheet.source),
            }),
            Self::Transform(transform) => Some(std::borrow::Cow::Owned(
                ParsedStylesheet::from_transform(transform)?
                    .text(semantics)
                    .into_owned(),
            )),
        }
    }
}

impl XsltStylesheet {
    /// Accept stylesheet markup for a signature template.
    ///
    /// The markup is written into the `<Transform>` element unchanged and is
    /// compiled as its own document, so it must be valid element content holding
    /// exactly one root element.
    ///
    /// # Errors
    ///
    /// [`TransformError::XmlParse`] for markup that is not well-formed element
    /// content, and [`TransformError::UnsupportedTransform`] when it does not
    /// hold exactly one element outside comments, processing instructions and
    /// whitespace.
    ///
    /// # Examples
    ///
    /// ```
    /// use xml_sec::xmldsig::{Transform, XsltStylesheet};
    ///
    /// let stylesheet = XsltStylesheet::new(
    ///     r#"<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"/>"#,
    /// )?;
    /// let transform = Transform::Xslt(stylesheet);
    /// # let _ = transform;
    /// # Ok::<(), xml_sec::xmldsig::TransformError>(())
    /// ```
    pub fn new(source: impl Into<String>) -> Result<Self, TransformError> {
        let source = source.into();
        let wrapped = format!("<transform>{source}</transform>");
        let document = crate::xml::dom::Document::parse(&wrapped)
            .map_err(|error| TransformError::XmlParse(XmlDocumentError::Parse(error)))?;
        let mut elements = 0usize;
        for child in document.root_element().children() {
            if child.is_element() {
                elements += 1;
            } else if child.is_text()
                && !child
                    .text()
                    .is_some_and(super::super::whitespace::is_xml_whitespace_only)
            {
                elements = usize::MAX;
                break;
            }
        }
        if elements != 1 {
            return Err(TransformError::UnsupportedTransform(
                "XSLT stylesheet must be one element".into(),
            ));
        }
        Ok(Self {
            source,
            parsed: None,
        })
    }

    /// The stylesheet of a parsed `<Transform>`, whose markup is already element content.
    pub(super) fn from_parsed(transform: crate::xml::dom::Node<'_, '_>, source: &str) -> Self {
        Self {
            source: source.to_owned(),
            parsed: ParsedStylesheet::from_transform(transform),
        }
    }

    /// The stylesheet markup.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }
}

/// Stylesheet markup of one `<Transform>` element: the source text between its
/// first and last child.
///
/// libxmlsec1 serializes each child with `xmlNodeDump` and parses the result as
/// a document (`xmlSecXsltReadNode` in its `xslt.c`), which is the same markup.
pub(super) fn stylesheet_source<'a>(transform: crate::xml::dom::Node<'a, 'a>) -> Option<&'a str> {
    let first = transform.first_child()?;
    let last = transform.children().next_back()?;
    transform
        .document()
        .input_text()
        .get(first.range().start..last.range().end)
}

/// Append `value` as the content of a double-quoted attribute.
fn push_attribute_value(out: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            // Attribute-value normalization would turn these into spaces.
            '\t' => out.push_str("&#9;"),
            '\n' => out.push_str("&#10;"),
            '\r' => out.push_str("&#13;"),
            character => out.push(character),
        }
    }
}

/// Append `value` as character data.
fn push_text(out: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            // Line-end normalization would turn a literal carriage return into a line feed.
            '\r' => out.push_str("&#13;"),
            character => out.push(character),
        }
    }
}

/// Append ` xmlns[:prefix]="uri"`.
fn push_declaration(out: &mut String, prefix: Option<&str>, uri: &str) {
    out.push_str(" xmlns");
    if let Some(prefix) = prefix {
        out.push(':');
        out.push_str(prefix);
    }
    out.push_str("=\"");
    push_attribute_value(out, uri);
    out.push('"');
}

/// Prefixes declared on `element` itself, `None` for the default namespace.
///
/// The tree keeps only in-scope bindings, so the declarations are read from the
/// element's start tag; an element produced by entity replacement has none in
/// the document text and falls back to the bindings that differ from its parent.
fn declared_prefixes<'a>(element: crate::xml::dom::Node<'a, 'a>) -> Vec<Option<&'a str>> {
    let text = element.document().input_text();
    let lexical = text.get(element.range()).and_then(|markup| {
        markup.starts_with('<').then_some(())?;
        match crate::xml_input_shared::lexical::Scanner::new(markup).next_event() {
            Ok(Some(
                crate::xml_input_shared::lexical::Event::Start(tag)
                | crate::xml_input_shared::lexical::Event::Empty(tag),
            )) => Some(
                tag.attributes
                    .iter()
                    .filter_map(|attribute| {
                        let name = attribute.name.qualified();
                        if name == "xmlns" {
                            Some(None)
                        } else {
                            name.strip_prefix("xmlns:")
                                .and_then(|prefix| {
                                    element
                                        .namespaces()
                                        .find(|namespace| namespace.name() == Some(prefix))
                                })
                                .map(|namespace| namespace.name())
                        }
                    })
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        }
    });
    lexical.unwrap_or_else(|| {
        let parent = element.parent();
        let inherited =
            |prefix: Option<&str>| parent.and_then(|parent| parent.lookup_namespace_uri(prefix));
        let mut declared: Vec<Option<&'a str>> = element
            .namespaces()
            .filter(|namespace| inherited(namespace.name()) != Some(namespace.uri()))
            .map(|namespace| namespace.name())
            .collect();
        if element.lookup_namespace_uri(None).is_none() && inherited(None).is_some() {
            declared.push(None);
        }
        declared
    })
}

impl ParsedStylesheet {
    /// Serialize the stylesheet element of `transform` from the parsed tree.
    fn from_transform(transform: crate::xml::dom::Node<'_, '_>) -> Option<Self> {
        enum Step<'a> {
            Open(crate::xml::dom::Node<'a, 'a>),
            Close(crate::xml::dom::Node<'a, 'a>),
        }
        let root = transform.children().find(|child| child.is_element())?;
        let mut document = String::new();
        let mut at = None;
        let mut root_declarations = Vec::new();
        let push_name = |out: &mut String, prefix: Option<&str>, local: &str| {
            if let Some(prefix) = prefix {
                out.push_str(prefix);
                out.push(':');
            }
            out.push_str(local);
        };
        // An explicit stack keeps native recursion independent of the stylesheet's depth.
        let mut steps = vec![Step::Open(root)];
        while let Some(step) = steps.pop() {
            match step {
                Step::Close(element) => {
                    document.push_str("</");
                    push_name(&mut document, element.prefix(), element.tag_name().name());
                    document.push('>');
                }
                Step::Open(node) if node.is_element() => {
                    document.push('<');
                    push_name(&mut document, node.prefix(), node.tag_name().name());
                    let declared = declared_prefixes(node);
                    if at.is_none() {
                        at = Some(document.len());
                        root_declarations.clone_from(&declared);
                    }
                    for prefix in declared {
                        push_declaration(
                            &mut document,
                            prefix,
                            node.lookup_namespace_uri(prefix).unwrap_or(""),
                        );
                    }
                    for attribute in node.attributes() {
                        document.push(' ');
                        push_name(&mut document, attribute.prefix(), attribute.name());
                        document.push_str("=\"");
                        push_attribute_value(&mut document, attribute.value());
                        document.push('"');
                    }
                    if node.first_child().is_none() {
                        document.push_str("/>");
                    } else {
                        document.push('>');
                        steps.push(Step::Close(node));
                        steps.extend(node.children().rev().map(Step::Open));
                    }
                }
                Step::Open(node) if node.is_comment() => {
                    document.push_str("<!--");
                    document.push_str(node.text().unwrap_or(""));
                    document.push_str("-->");
                }
                Step::Open(node) if node.is_pi() => {
                    if let Some(pi) = node.pi() {
                        document.push_str("<?");
                        document.push_str(pi.target);
                        if let Some(value) = pi.value {
                            document.push(' ');
                            document.push_str(value);
                        }
                        document.push_str("?>");
                    }
                }
                Step::Open(node) => push_text(&mut document, node.text().unwrap_or("")),
            }
        }
        let mut inherited = String::new();
        for namespace in transform.namespaces() {
            let prefix = namespace.name();
            if prefix != Some("xml") && !root_declarations.contains(&prefix) {
                push_declaration(&mut inherited, prefix, namespace.uri());
            }
        }
        Some(Self {
            document,
            inherited,
            at: at?,
        })
    }
}

/// One XSLT allowance shared by every execution in an operation.
pub(crate) struct Allowance {
    work_used: [Cell<usize>; WORK_KINDS.len()],
    output_used: Cell<usize>,
    max_work: usize,
    max_output: usize,
    max_workspace: usize,
    max_recursion: usize,
    max_document_bytes: usize,
    max_nodes: usize,
    max_depth: usize,
}

impl Default for Allowance {
    fn default() -> Self {
        Self::new(&ResourcePolicy::default())
    }
}

impl Allowance {
    pub(crate) fn new(resources: &ResourcePolicy) -> Self {
        Self {
            work_used: Default::default(),
            output_used: Cell::new(0),
            max_work: resources.max_xslt_work,
            max_output: resources.max_xslt_output_bytes,
            max_workspace: resources.max_xslt_workspace_bytes,
            max_recursion: resources.max_xslt_recursion_depth,
            max_document_bytes: resources.max_xml_document_bytes,
            max_nodes: resources.max_xml_nodes,
            max_depth: resources.max_xml_depth,
        }
    }

    fn work_used(&self, kind: BudgetKind) -> usize {
        WORK_KINDS
            .iter()
            .position(|candidate| *candidate == kind)
            .map_or(0, |index| self.work_used[index].get())
    }

    fn execution_budget(&self, workspace: usize) -> ExecutionBudget {
        // Each admitted amount was at most the remainder offered, so `used <= max` holds.
        let remaining = |kind| self.max_work - self.work_used(kind);
        ExecutionBudget {
            source_bytes: self.max_document_bytes,
            // Stylesheets cannot resolve resources: `document()` has no capability to use.
            external_documents: 0,
            recursion_depth: self.max_recursion,
            xpath_evaluations: remaining(BudgetKind::XPathEvaluations),
            xpath_operations: remaining(BudgetKind::XPathOperations),
            extension_operations: remaining(BudgetKind::ExtensionOperations),
            pattern_evaluations: remaining(BudgetKind::PatternEvaluations),
            template_applications: remaining(BudgetKind::TemplateApplications),
            sort_comparisons: remaining(BudgetKind::SortComparisons),
            key_entries: remaining(BudgetKind::KeyEntries),
            result_nodes: remaining(BudgetKind::ResultNodes),
            serialized_bytes: self.max_output - self.output_used.get(),
            messages: remaining(BudgetKind::Messages),
            owned_bytes: workspace,
        }
    }

    fn admit(&self, usage: &ExecutionUsage) {
        for (index, kind) in WORK_KINDS.into_iter().enumerate() {
            let used = &self.work_used[index];
            used.set(used.get() + admitted(usage, kind));
        }
        self.output_used
            .set(self.output_used.get() + usage.serialized_bytes);
    }
}

#[derive(Clone, Copy)]
enum Phase {
    Stylesheet,
    Input,
    Execution,
}

fn uri_refusal() -> TransformError {
    // XMLDSig gives the transform no base URI or resolver; libxmlsec1 forbids
    // file and network access through xsltSetSecurityPrefs as well.
    PolicyViolation::Uri {
        operation: "XSLT transform",
        reason: "stylesheets cannot resolve external resources",
    }
    .into()
}

fn map_error<S: TransformScratch>(
    error: Error,
    phase: Phase,
    held: usize,
    allowance: &Allowance,
    workspace: usize,
    scratch: &S,
) -> TransformError {
    let limit = |resource, maximum, actual| -> TransformError {
        PolicyViolation::ResourceLimit {
            resource,
            maximum,
            actual,
        }
        .into()
    };
    match error {
        Error::Budget { kind, actual, .. } => match kind {
            BudgetKind::OwnedBytes | BudgetKind::NamespaceScopeBytes
                if workspace < allowance.max_workspace =>
            {
                // The operation's memory account, not the policy, granted less.
                structured_asn1::memory::MemoryError::LimitExceeded.into()
            }
            BudgetKind::OwnedBytes | BudgetKind::NamespaceScopeBytes => limit(
                resource_name::XSLT_WORKSPACE_BYTES,
                allowance.max_workspace,
                // The engine reports `usize::MAX` for a total it cannot represent;
                // adding what earlier stages hold keeps that meaning.
                held.saturating_add(actual),
            ),
            BudgetKind::StylesheetBytes | BudgetKind::SourceBytes => limit(
                resource_name::XML_DOCUMENT,
                allowance.max_document_bytes,
                actual,
            ),
            BudgetKind::SourceNodes => limit(resource_name::XML_NODES, allowance.max_nodes, actual),
            BudgetKind::RecursionDepth => match phase {
                Phase::Input => limit(resource_name::XML_DEPTH, allowance.max_depth, actual),
                Phase::Stylesheet | Phase::Execution => limit(
                    resource_name::XSLT_RECURSION_DEPTH,
                    allowance.max_recursion,
                    actual,
                ),
            },
            BudgetKind::SerializedBytes => limit(
                resource_name::XSLT_OUTPUT_BYTES,
                allowance.max_output,
                allowance.output_used.get() + actual,
            ),
            BudgetKind::ImportedModules | BudgetKind::ExternalDocuments => uri_refusal(),
            kind if WORK_KINDS.contains(&kind) => limit(
                resource_name::XSLT_WORK,
                allowance.max_work,
                allowance.work_used(kind) + actual,
            ),
            _ => scratch.xslt_error(&Error::Budget {
                kind,
                limit: 0,
                actual,
            }),
        },
        Error::StaleResource { .. }
        | Error::ResourceNotFound { .. }
        | Error::Resolver { .. }
        | Error::ResourceAccessDenied { .. } => uri_refusal(),
        error => scratch.xslt_error(&error),
    }
}

/// Refuse a document type declaration before the engine applies it.
///
/// The engine expands internal entities and applies attribute defaults, which
/// changes the signed data, so this follows the operation's XML input policy.
fn reject_document_type(xml: &str, settings: DocumentParseSettings) -> Result<(), TransformError> {
    if settings.allow_dtd {
        return Ok(());
    }
    let mut scanner = crate::xml_input_shared::lexical::Scanner::new(xml);
    // A lexical error is reported by the engine's own parse of the same text.
    while let Ok(Some(event)) = scanner.next_event() {
        match event {
            crate::xml_input_shared::lexical::Event::DocType { .. } => {
                return Err(super::map_transform_xml_parse_error(
                    XmlDocumentError::Parse(crate::xml::dom::ParseError::DtdDetected),
                    settings,
                ));
            }
            crate::xml_input_shared::lexical::Event::Start(_)
            | crate::xml_input_shared::lexical::Event::Empty(_) => return Ok(()),
            _ => {}
        }
    }
    Ok(())
}

/// Debit the parser work an engine pass admitted; a pass the shared remainder
/// refused is the operation's parse-work limit, not an engine error.
fn charge_parse_work<T>(
    reported: Reported<T, ParseUsage>,
    xml_parse: &XmlParseWorkBudget,
) -> Result<Result<T, Error>, TransformError> {
    // The engine was offered exactly the remainder, so what it admitted fits.
    xml_parse.charge_policy(reported.usage.parse_work_bytes)?;
    match reported.outcome {
        Err(Error::Budget {
            kind: BudgetKind::ParseWorkBytes,
            actual,
            ..
        }) => Err(xml_parse
            .charge_policy(actual - reported.usage.parse_work_bytes)
            .err()
            .map_or_else(
                || TransformError::Xslt("XSLT parser work exceeded its allowance".into()),
                TransformError::from,
            )),
        outcome => Ok(outcome),
    }
}

/// Apply the stylesheet of `parameter` to the octets `input` and return the serialized result.
///
/// Compilation, the parsed input and execution share one workspace: each stage
/// receives what the earlier ones still hold subtracted from it.
#[allow(clippy::too_many_arguments)]
pub(super) fn execute<'d, S: TransformScratch, D: DomStorage>(
    parameter: XsltParameter<'_>,
    input: &[u8],
    semantics: XsltStylesheetSemantics,
    allow_dtd: bool,
    budget: &TransformExecutionBudget,
    xml_parse: &XmlParseWorkBudget,
    scratch: &S,
) -> Result<ExecutionData<'d, S, D>, TransformError> {
    let allowance = &budget.xslt;
    let stylesheet = parameter.document(semantics).ok_or_else(|| {
        TransformError::UnsupportedTransform("XSLT transform requires a stylesheet".into())
    })?;
    let (reservation, workspace) = scratch.reserve_workspace(allowance.max_workspace)?;
    // `held` is what earlier stages keep in the workspace while a stage runs; a
    // refusal reports the workspace total, not the stage's share of it.
    let fail = |error, phase, held| map_error(error, phase, held, allowance, workspace, scratch);
    let exhausted = |needed: usize| Error::Budget {
        kind: BudgetKind::OwnedBytes,
        limit: workspace,
        actual: needed,
    };

    // The stylesheet is element content, which cannot hold a document type declaration.
    let stylesheet_settings = DocumentParseSettings {
        allow_dtd: false,
        ..budget.xml_parse_settings
    };
    crate::document::preflight_xml_limits(&stylesheet, stylesheet_settings, xml_parse)
        .map_err(|error| super::map_transform_xml_parse_error(error, stylesheet_settings))?;
    // Text assembled with inherited declarations lives in the workspace until compiled.
    let assembled = match &stylesheet {
        std::borrow::Cow::Owned(text) => text.capacity(),
        std::borrow::Cow::Borrowed(_) => 0,
    };
    let compile_workspace = workspace
        .checked_sub(assembled)
        .ok_or_else(|| fail(exhausted(assembled), Phase::Stylesheet, 0))?;
    let compiled = charge_parse_work(
        Compiler::new(
            Arc::new(NoResolver),
            CompileBudget::new(
                allowance.max_document_bytes,
                0,
                allowance.max_recursion,
                compile_workspace,
            )
            .with_parse_work_bytes(xml_parse.remaining()),
        )
        .unbound_prefix_lists(match semantics {
            XsltStylesheetSemantics::Specification => UnboundPrefixLists::Reject,
            XsltStylesheetSemantics::Libxmlsec1 => UnboundPrefixLists::Ignore,
        })
        .compile_reported(&stylesheet, None),
        xml_parse,
    )?
    .map_err(|error| fail(error, Phase::Stylesheet, assembled))?;
    drop(stylesheet);
    let held = compiled.retained_bytes();

    let settings = DocumentParseSettings {
        allow_dtd,
        ..budget.xml_parse_settings
    };
    super::check_xml_octets(input, settings)?;
    xml_parse.charge_policy(input.len())?;
    let xml = crate::xml_input_shared::decode_xml_in(
        input,
        settings.max_bytes,
        |_, _| Ok(()),
        &scratch.decoder(),
    )
    .map_err(S::decode_error)?;
    reject_document_type(xml.as_ref(), settings)?;
    // The engine's parser does not count namespace bindings or apply the rest of
    // the operation's XML input policy itself.
    crate::document::preflight_xml_limits(xml.as_ref(), settings, xml_parse)
        .map_err(|error| super::map_transform_xml_parse_error(error, settings))?;
    let (entity_references, entity_expansion_bytes) = if allow_dtd {
        (
            crate::hard_limits::XML_ENTITY_EXPANSION_CEILING as usize,
            crate::hard_limits::XML_ENTITY_EXPANSION_WORK_BYTE_CEILING,
        )
    } else {
        (0, 0)
    };
    let source_workspace = workspace
        .checked_sub(held)
        .ok_or_else(|| fail(exhausted(held), Phase::Input, 0))?;
    let source = charge_parse_work(
        Document::parse_with_budget_reported(
            xml.as_ref(),
            None,
            ParseBudget::new(
                allowance.max_document_bytes,
                allowance.max_nodes,
                allowance.max_depth,
                entity_references,
                entity_expansion_bytes,
                source_workspace,
            )
            .with_owned_bytes(source_workspace)
            .with_parse_work_bytes(xml_parse.remaining()),
        ),
        xml_parse,
    )?
    .map_err(|error| fail(error, Phase::Input, held))?;
    drop(xml);
    let held = held
        .checked_add(source.retained_bytes())
        .ok_or_else(|| fail(exhausted(usize::MAX), Phase::Input, 0))?;

    let execution_workspace = workspace
        .checked_sub(held)
        .ok_or_else(|| fail(exhausted(held), Phase::Execution, 0))?;
    let reported = compiled.execute_reported(
        &source,
        &Parameters::new(),
        ExecutionEnvironment::new(Arc::new(NoResolver)),
        ExecutionOptions {
            budget: allowance.execution_budget(execution_workspace),
            initial_mode: None,
            initial_template: None,
        },
    );
    drop(source);
    drop(compiled);
    // A failed execution spends its work too, and later references and signatures
    // of the operation draw on the same allowance. The error reports the totals
    // before this execution's work is admitted.
    let usage = reported.usage;
    let outcome = reported
        .outcome
        .map_err(|error| fail(error, Phase::Execution, held));
    allowance.admit(&usage);
    let work = WORK_KINDS
        .into_iter()
        .try_fold(0usize, |total, kind| {
            total.checked_add(admitted(&usage, kind))
        })
        .expect("each kind is bounded by the policy work ceiling");
    scratch.charge(work)?;
    let output = outcome?.serialized.bytes;
    if S::ACCOUNTED {
        // The native output sits inside the workspace reservation. Move its charge to
        // a reservation of its own, so the account sees both copies while it is copied.
        drop(reservation);
        let (output_reservation, granted) = scratch.reserve_workspace(output.capacity())?;
        if granted < output.capacity() {
            return Err(structured_asn1::memory::MemoryError::LimitExceeded.into());
        }
        let mut accounted = scratch.bytes();
        accounted.append(&output)?;
        drop(output);
        drop(output_reservation);
        Ok(ExecutionData::Accounted(accounted))
    } else {
        drop(reservation);
        Ok(ExecutionData::NativeBinary(output))
    }
}
