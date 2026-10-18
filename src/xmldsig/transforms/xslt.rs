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
    inherited: Option<Inherited>,
}

/// Namespace declarations in scope at a `<Transform>` that its stylesheet
/// element does not make itself, serialized as attributes, and the offset in
/// the stylesheet markup just after that element's name where they belong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Inherited {
    at: usize,
    declarations: String,
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
    /// The stylesheet markup and the declarations it inherits.
    fn parts(self) -> Option<(&'a str, Option<std::borrow::Cow<'a, Inherited>>)> {
        match self {
            Self::Stylesheet(stylesheet) => Some((
                &stylesheet.source,
                stylesheet
                    .inherited
                    .as_ref()
                    .map(std::borrow::Cow::Borrowed),
            )),
            Self::Transform(transform) => Some((
                stylesheet_source(transform)?,
                inherited_namespaces(transform).map(std::borrow::Cow::Owned),
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
            inherited: None,
        })
    }

    /// The stylesheet of a parsed `<Transform>`, whose markup is already element content.
    pub(super) fn from_parsed(transform: crate::xml::dom::Node<'_, '_>, source: &str) -> Self {
        Self {
            source: source.to_owned(),
            inherited: inherited_namespaces(transform),
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

/// Prefixes in a stylesheet's markup that no element of the markup declares
/// where they are used, and the length of its root element's name. `None`
/// stands for the default namespace.
///
/// A reference is an element or attribute name prefix, an unprefixed element
/// name (the default namespace), a QName prefix in an attribute value (XPath
/// expressions, patterns, attribute value templates), or an entry of an
/// `exclude-result-prefixes` or `extension-element-prefixes` list.
fn unresolved_references(markup: &str) -> Option<(usize, Vec<Option<String>>)> {
    use crate::xml_input_shared::lexical::{Event, Scanner};
    let mut scanner = Scanner::new(markup);
    let mut scopes: Vec<Vec<Option<String>>> = Vec::new();
    let mut unresolved: Vec<Option<String>> = Vec::new();
    let mut root_name = None;
    while let Ok(Some(event)) = scanner.next_event() {
        let (tag, empty) = match event {
            Event::Start(tag) => (tag, false),
            Event::Empty(tag) => (tag, true),
            Event::End { .. } => {
                scopes.pop();
                continue;
            }
            _ => continue,
        };
        root_name.get_or_insert(tag.name.qualified().len());
        let mut declared = Vec::new();
        for attribute in &tag.attributes {
            let name = attribute.name.qualified();
            if name == "xmlns" {
                declared.push(None);
            } else if let Some(prefix) = name.strip_prefix("xmlns:") {
                declared.push(Some(prefix.to_owned()));
            }
        }
        scopes.push(declared);
        let mut refer = |prefix: Option<&str>| {
            if prefix == Some("xml") {
                return;
            }
            let prefix = prefix.map(str::to_owned);
            if !scopes.iter().any(|frame| frame.contains(&prefix)) && !unresolved.contains(&prefix)
            {
                unresolved.push(prefix);
            }
        };
        refer(tag.name.prefix());
        for attribute in &tag.attributes {
            let name = attribute.name.qualified();
            if name == "xmlns" || name.starts_with("xmlns:") {
                continue;
            }
            if let Some(prefix) = attribute.name.prefix() {
                refer(Some(prefix));
            }
            // XSLT 1.0 sections 7.1.1 and 14.1: whitespace-separated prefixes, `#default`
            // naming the default namespace.
            if matches!(
                attribute.name.local(),
                "exclude-result-prefixes" | "extension-element-prefixes"
            ) {
                for token in attribute.value.split_ascii_whitespace() {
                    refer((token != "#default").then_some(token));
                }
            } else {
                qname_prefixes(attribute.value, |prefix| refer(Some(prefix)));
            }
        }
        if empty {
            scopes.pop();
        }
    }
    Some((root_name?, unresolved))
}

/// Call `visit` with each QName prefix in `value`, outside quoted literals: an
/// NCName directly followed by one colon, as in `ds:Object` but not `child::x`.
fn qname_prefixes(value: &str, mut visit: impl FnMut(&str)) {
    let is_name = |character: char| {
        character.is_alphanumeric() || matches!(character, '_' | '-' | '.') || !character.is_ascii()
    };
    let bytes = value.as_bytes();
    let mut quote = None;
    let mut start = None;
    for (index, character) in value.char_indices() {
        if let Some(open) = quote {
            if character == open {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' => {
                quote = Some(character);
                start = None;
            }
            ':' => {
                let next_is_colon = bytes.get(index + 1) == Some(&b':');
                let previous_is_colon = index > 0 && bytes[index - 1] == b':';
                if let Some(begin) = start
                    && !next_is_colon
                    && !previous_is_colon
                    && (begin == 0 || bytes[begin - 1] != b':')
                {
                    visit(&value[begin..index]);
                }
                start = None;
            }
            character if is_name(character) => {
                if start.is_none()
                    && (character.is_alphabetic() || character == '_' || !character.is_ascii())
                {
                    start = Some(index);
                }
            }
            _ => start = None,
        }
    }
}

/// Declarations the stylesheet element inherits from `transform` and its ancestors.
///
/// The stylesheet is an element of the signed document, so a prefix it uses
/// without declaring is bound by the declarations in scope at it (Namespaces in
/// XML 1.0 section 6.1). Its markup alone carries only the declarations written
/// inside it. Only bindings the stylesheet refers to are added: a binding it
/// never uses would otherwise be copied into its literal result elements.
/// <https://www.w3.org/TR/2009/REC-xml-names-20091208/#scoping>
fn inherited_namespaces(transform: crate::xml::dom::Node<'_, '_>) -> Option<Inherited> {
    let first = transform.first_child()?;
    let root = transform.children().find(|child| child.is_element())?;
    let markup = transform.document().input_text().get(root.range())?;
    let (name, unresolved) = unresolved_references(markup)?;
    let mut declarations = String::new();
    for namespace in transform.namespaces() {
        let prefix = namespace.name();
        if !unresolved
            .iter()
            .any(|reference| reference.as_deref() == prefix)
        {
            continue;
        }
        declarations.push_str(" xmlns");
        if let Some(prefix) = prefix {
            declarations.push(':');
            declarations.push_str(prefix);
        }
        declarations.push_str("=\"");
        for character in namespace.uri().chars() {
            match character {
                '&' => declarations.push_str("&amp;"),
                '<' => declarations.push_str("&lt;"),
                '"' => declarations.push_str("&quot;"),
                // Attribute-value normalization would turn these into spaces.
                '\t' => declarations.push_str("&#9;"),
                '\n' => declarations.push_str("&#10;"),
                '\r' => declarations.push_str("&#13;"),
                character => declarations.push(character),
            }
        }
        declarations.push('"');
    }
    if declarations.is_empty() {
        return None;
    }
    Some(Inherited {
        at: root.range().start - first.range().start + 1 + name,
        declarations,
    })
}

/// The stylesheet document `semantics` compiles.
fn stylesheet_document<'a>(
    source: &'a str,
    inherited: Option<&Inherited>,
    semantics: XsltStylesheetSemantics,
) -> std::borrow::Cow<'a, str> {
    match (semantics, inherited) {
        (XsltStylesheetSemantics::Specification, Some(inherited)) => {
            let (head, tail) = source.split_at(inherited.at);
            std::borrow::Cow::Owned([head, &inherited.declarations, tail].concat())
        }
        _ => std::borrow::Cow::Borrowed(source),
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
                actual,
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
    let (source, inherited) = parameter.parts().ok_or_else(|| {
        TransformError::UnsupportedTransform("XSLT transform requires a stylesheet".into())
    })?;
    let (reservation, workspace) = scratch.reserve_workspace(allowance.max_workspace)?;
    let fail = |error, phase| map_error(error, phase, allowance, workspace, scratch);
    let exhausted = |needed: usize| Error::Budget {
        kind: BudgetKind::OwnedBytes,
        limit: workspace,
        actual: needed,
    };

    let stylesheet = stylesheet_document(source, inherited.as_deref(), semantics);
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
        .ok_or_else(|| fail(exhausted(assembled), Phase::Stylesheet))?;
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
    .map_err(|error| fail(error, Phase::Stylesheet))?;
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
        .ok_or_else(|| fail(exhausted(held), Phase::Input))?;
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
    .map_err(|error| fail(error, Phase::Input))?;
    drop(xml);
    let held = held
        .checked_add(source.retained_bytes())
        .ok_or_else(|| fail(exhausted(usize::MAX), Phase::Input))?;

    let execution_workspace = workspace
        .checked_sub(held)
        .ok_or_else(|| fail(exhausted(held), Phase::Execution))?;
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
        .map_err(|error| fail(error, Phase::Execution));
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
