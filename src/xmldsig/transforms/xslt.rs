//! XSLT transform adapter (XMLDSig 1.1 section 6.6.5).
//!
//! <https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-XSLT>

use std::cell::Cell;
use std::sync::Arc;

use super::{ExecutionData, TransformError, TransformExecutionBudget, TransformScratch};
use crate::c14n::scratch::Bytes as _;
use crate::document::{DocumentParseSettings, XmlDocumentError, XmlParseWorkBudget};
use crate::policy::{PolicyViolation, ResourcePolicy, resource_name};
use crate::xml::dom::storage::Storage as DomStorage;
use crate::xslt::{
    BudgetKind, CompileBudget, Compiler, Document, Error, ExecutionBudget, ExecutionOptions,
    ExecutionUsage, NoResolver, Parameters, ParseBudget,
};

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
        Ok(Self { source })
    }

    /// Markup that a parsed `<Transform>` already contains as element content.
    pub(super) fn from_parsed(source: String) -> Self {
        Self { source }
    }

    /// The stylesheet markup.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }
}

/// Stylesheet markup of one `<Transform>` element.
///
/// libxmlsec1 serializes each child with `xmlNodeDump` and parses the result as
/// a document (`xmlSecXsltReadNode` in its `xslt.c`). That keeps the
/// namespace declarations written on the stylesheet and drops the ones inherited
/// from `<Signature>`; literal result elements copy in-scope namespaces, so the
/// signed output of existing XSLT references depends on this choice. The source
/// text between the first and last child is the same markup.
pub(super) fn stylesheet_source<'a>(transform: crate::xml::dom::Node<'a, 'a>) -> Option<&'a str> {
    let first = transform.first_child()?;
    let last = transform.children().last()?;
    transform
        .document()
        .input_text()
        .get(first.range().start..last.range().end)
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

/// Apply `stylesheet` to the octets `input` and return the serialized result.
pub(super) fn execute<'d, S: TransformScratch, D: DomStorage>(
    stylesheet: &str,
    input: &[u8],
    allow_dtd: bool,
    budget: &TransformExecutionBudget,
    xml_parse: &XmlParseWorkBudget,
    scratch: &S,
) -> Result<ExecutionData<'d, S, D>, TransformError> {
    let allowance = &budget.xslt;
    let (reservation, workspace) = scratch.reserve_workspace(allowance.max_workspace)?;
    let fail = |error, phase| map_error(error, phase, allowance, workspace, scratch);

    xml_parse.charge_policy(stylesheet.len())?;
    let compiled = Compiler::new(
        Arc::new(NoResolver),
        CompileBudget::new(
            allowance.max_document_bytes,
            0,
            allowance.max_recursion,
            workspace,
        ),
    )
    .compile(stylesheet, None)
    .map_err(|error| fail(error, Phase::Stylesheet))?;

    xml_parse.charge_policy(input.len())?;
    let settings = DocumentParseSettings {
        allow_dtd,
        ..budget.xml_parse_settings
    };
    let xml = crate::xml_input_shared::decode_xml_in(
        input,
        settings.max_bytes,
        |_, _| Ok(()),
        &scratch.decoder(),
    )
    .map_err(S::decode_error)?;
    reject_document_type(xml.as_ref(), settings)?;
    let (entity_references, entity_expansion_bytes) = if allow_dtd {
        (
            crate::hard_limits::XML_ENTITY_EXPANSION_CEILING as usize,
            crate::hard_limits::XML_ENTITY_EXPANSION_WORK_BYTE_CEILING,
        )
    } else {
        (0, 0)
    };
    let source = Document::parse_with_budget(
        xml.as_ref(),
        None,
        ParseBudget::new(
            allowance.max_document_bytes,
            allowance.max_nodes,
            allowance.max_depth,
            entity_references,
            entity_expansion_bytes,
            workspace,
        ),
    )
    .map_err(|error| fail(error, Phase::Input))?;
    drop(xml);

    let result = compiled
        .execute(
            &source,
            &Parameters::new(),
            Arc::new(NoResolver),
            ExecutionOptions {
                budget: allowance.execution_budget(workspace),
                initial_mode: None,
                initial_template: None,
            },
        )
        .map_err(|error| fail(error, Phase::Execution))?;
    drop(source);
    drop(compiled);
    allowance.admit(&result.usage);
    let work = WORK_KINDS
        .into_iter()
        .try_fold(0usize, |total, kind| {
            total.checked_add(admitted(&result.usage, kind))
        })
        .expect("each kind is bounded by the policy work ceiling");
    scratch.charge(work)?;
    let output = result.serialized.bytes;
    drop(reservation);
    if S::ACCOUNTED {
        let mut accounted = scratch.bytes();
        accounted.append(&output)?;
        Ok(ExecutionData::Accounted(accounted))
    } else {
        Ok(ExecutionData::NativeBinary(output))
    }
}
