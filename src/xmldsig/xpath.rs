//! XPath 1.0 evaluation for XMLDSig transform node sets.
//!
//! `roxmltree` intentionally has no XPath engine, so transforms are evaluated
//! against an equivalent, short-lived SXD document. The mirror keeps a
//! bidirectional node map so the result can be projected back onto the
//! original document without serializing and reparsing signed input.

use std::cell::Cell;

mod mirror;
mod source;
pub(crate) mod storage;
use storage::{Bindings as _, Index as _, NamespaceIndex as _, NamespaceKey};

use crate::sxd_document as sxd_document_no_unsafe;
use crate::sxd_xpath as sxd_xpath_no_unsafe;
use crate::xml::dom::{Document, NodeId};
use sxd_document_no_unsafe::{Package, QName, dom};
use sxd_xpath_no_unsafe::{Factory, Value, function, nodeset};

use super::transforms::{
    MAX_XPATH_EXPRESSION_BYTES, MAX_XPATH_FILTERS, NodeFilterWorkBudget, XPathFilterOperation,
    XPathHereSemantics,
};
#[cfg(test)]
use super::transforms::{XPathExpression, XPathFilter};
#[cfg(test)]
use super::types::NodeSet;
use super::types::projection::{Keys, NativeKeys, Projection};
use super::types::{NodeSetMaterializationBudget, TransformError, transform_resource_limit};
use crate::c14n::prefix::{attribute_prefix, element_prefix};

pub(crate) trait CompiledExpression {
    fn evaluate<'d, N: Into<nodeset::Node<'d>>>(
        &self,
        context: &sxd_xpath_no_unsafe::context::ScopedContext<'_, 'd>,
        node: N,
        failure: &Cell<Option<structured_asn1::memory::MemoryError>>,
    ) -> Result<Value<'d>, sxd_xpath_no_unsafe::ExecutionError>;
}

impl CompiledExpression for sxd_xpath_no_unsafe::XPath {
    fn evaluate<'d, N: Into<nodeset::Node<'d>>>(
        &self,
        context: &sxd_xpath_no_unsafe::context::ScopedContext<'_, 'd>,
        node: N,
        _failure: &Cell<Option<structured_asn1::memory::MemoryError>>,
    ) -> Result<Value<'d>, sxd_xpath_no_unsafe::ExecutionError> {
        self.evaluate(context, node)
    }
}

pub(crate) struct AccountedProgram<'s, 'w, W: structured_asn1::memory::Work> {
    program: sxd_xpath_no_unsafe::arena::Program<'s>,
    work: &'w W,
}

impl<W: structured_asn1::memory::Work> CompiledExpression for AccountedProgram<'_, '_, W> {
    fn evaluate<'d, N: Into<nodeset::Node<'d>>>(
        &self,
        context: &sxd_xpath_no_unsafe::context::ScopedContext<'_, 'd>,
        node: N,
        failure: &Cell<Option<structured_asn1::memory::MemoryError>>,
    ) -> Result<Value<'d>, sxd_xpath_no_unsafe::ExecutionError> {
        self.program.evaluate_in(
            context,
            node,
            sxd_xpath_no_unsafe::runtime::Accounted {
                work: self.work,
                failure,
            },
        )
    }
}

pub(crate) trait XPathStorage: crate::c14n::scratch::Scratch {
    type Construction<'d, 'q>: mirror::Construction<'d>
    where
        Self: 'q;
    fn package(&self) -> Result<Package, structured_asn1::memory::MemoryError>;
    fn construction<'d, 'q>(&'q self, target: dom::Document<'d>) -> Self::Construction<'d, 'q>;
    type Runtime<'q>: sxd_xpath_no_unsafe::runtime::Runtime
    where
        Self: 'q;
    fn runtime<'q>(
        &'q self,
        failure: &'q Cell<Option<structured_asn1::memory::MemoryError>>,
    ) -> Self::Runtime<'q>;
    type Compiled<'s>: CompiledExpression;
    fn compile<'s>(&self, source: &'s str) -> Result<Self::Compiled<'s>, TransformError>;
    fn diagnostic(&self, message: std::fmt::Arguments<'_>) -> TransformError;
    fn formatted(&self, message: std::fmt::Arguments<'_>) -> Result<Self::Text, TransformError>;
    fn order_nodes<'d>(
        &self,
        nodes: &nodeset::Nodeset<'d>,
        context: &sxd_xpath_no_unsafe::context::Evaluation<'_, 'd>,
        failure: &Cell<Option<structured_asn1::memory::MemoryError>>,
    ) -> Result<Self::Values<nodeset::Node<'d>>, sxd_xpath_no_unsafe::ExecutionError>;
}

struct NamespaceResolver<'q, 'source, K: Keys> {
    bindings: &'q K::Bindings<'source>,
    execution: K::Execution,
    failure: &'q Cell<Option<structured_asn1::memory::MemoryError>>,
    source: std::marker::PhantomData<&'source str>,
}

impl<K: Keys> sxd_xpath_no_unsafe::context::NamespaceLookup for NamespaceResolver<'_, '_, K> {
    fn namespace_for(&self, prefix: &str) -> Result<Option<&str>, function::Error> {
        if self.failure.get().is_some() {
            return Err(function::Error::ProcessingStopped);
        }
        match self.bindings.resolve(prefix, self.execution) {
            Ok(uri) => Ok(uri),
            Err(cause) => {
                self.failure.set(Some(cause));
                Err(function::Error::ProcessingStopped)
            }
        }
    }
}

impl XPathStorage for crate::c14n::scratch::Native {
    type Construction<'d, 'q> = dom::Document<'d>;
    fn package(&self) -> Result<Package, structured_asn1::memory::MemoryError> {
        Ok(Package::new())
    }
    fn construction<'d, 'q>(&'q self, target: dom::Document<'d>) -> Self::Construction<'d, 'q> {
        target
    }
    type Runtime<'q> = sxd_xpath_no_unsafe::runtime::Native;
    fn runtime<'q>(
        &'q self,
        _: &'q Cell<Option<structured_asn1::memory::MemoryError>>,
    ) -> Self::Runtime<'q> {
        sxd_xpath_no_unsafe::runtime::Native
    }
    type Compiled<'s> = sxd_xpath_no_unsafe::XPath;
    fn order_nodes<'d>(
        &self,
        nodes: &nodeset::Nodeset<'d>,
        context: &sxd_xpath_no_unsafe::context::Evaluation<'_, 'd>,
        _: &Cell<Option<structured_asn1::memory::MemoryError>>,
    ) -> Result<Self::Values<nodeset::Node<'d>>, sxd_xpath_no_unsafe::ExecutionError> {
        nodes
            .document_order_with_context(context)
            .map_err(sxd_xpath_no_unsafe::ExecutionError::from)
    }

    fn compile<'s>(&self, source: &'s str) -> Result<Self::Compiled<'s>, TransformError> {
        Factory::new()
            .build(source)
            .map_err(|error| TransformError::XPath(error.to_string()))
    }

    fn diagnostic(&self, message: std::fmt::Arguments<'_>) -> TransformError {
        TransformError::XPath(std::fmt::format(message))
    }

    fn formatted(&self, message: std::fmt::Arguments<'_>) -> Result<Self::Text, TransformError> {
        Ok(std::fmt::format(message))
    }
}

impl<'w, W: structured_asn1::memory::Work> XPathStorage for crate::c14n::scratch::Accounted<'w, W> {
    type Construction<'d, 'q>
        = dom::current::Builder<'d, 'q, W>
    where
        Self: 'q;
    fn package(&self) -> Result<Package, structured_asn1::memory::MemoryError> {
        Package::try_current(self.0)
    }
    fn construction<'d, 'q>(&'q self, target: dom::Document<'d>) -> Self::Construction<'d, 'q> {
        dom::current::Builder::new(target, self.0)
    }
    type Runtime<'q>
        = sxd_xpath_no_unsafe::runtime::Accounted<'q, W>
    where
        Self: 'q;
    fn runtime<'q>(
        &'q self,
        failure: &'q Cell<Option<structured_asn1::memory::MemoryError>>,
    ) -> Self::Runtime<'q> {
        sxd_xpath_no_unsafe::runtime::Accounted {
            work: self.0,
            failure,
        }
    }
    type Compiled<'s> = AccountedProgram<'s, 'w, W>;
    fn order_nodes<'d>(
        &self,
        nodes: &nodeset::Nodeset<'d>,
        context: &sxd_xpath_no_unsafe::context::Evaluation<'_, 'd>,
        failure: &Cell<Option<structured_asn1::memory::MemoryError>>,
    ) -> Result<Self::Values<nodeset::Node<'d>>, sxd_xpath_no_unsafe::ExecutionError> {
        nodes
            .document_order_in(
                context,
                sxd_xpath_no_unsafe::runtime::Accounted {
                    work: self.0,
                    failure,
                },
            )
            .map(|nodes| nodes.into_values())
            .map_err(sxd_xpath_no_unsafe::ExecutionError::from)
    }

    fn compile<'s>(&self, source: &'s str) -> Result<Self::Compiled<'s>, TransformError> {
        sxd_xpath_no_unsafe::arena::Program::parse(source, self.0)
            .map(|program| AccountedProgram {
                program,
                work: self.0,
            })
            .map_err(|error| match error {
                sxd_xpath_no_unsafe::grammar::Fault::Resource(cause) => cause.into(),
                error => {
                    // Formatting an unexpected borrowed token can inspect its
                    // payload again. Admit that pass before Debug scans it.
                    if let Err(cause) = self.0.charge_work(source.len() as u64) {
                        return cause.into();
                    }
                    self.diagnostic(format_args!("{error}"))
                }
            })
    }

    fn diagnostic(&self, message: std::fmt::Arguments<'_>) -> TransformError {
        super::transforms::current_diagnostic(super::transforms::Diagnostic::XPath, message, self.0)
    }

    fn formatted(&self, message: std::fmt::Arguments<'_>) -> Result<Self::Text, TransformError> {
        use crate::xml::dom::storage::Storage as _;
        crate::xml::dom::storage::Accounted(self.0)
            .formatted(message)
            .map_err(|cause| match cause {
                crate::xml::dom::ParseError::SharedExecution(cause) => cause.into(),
                cause => TransformError::XmlParse(crate::document::XmlDocumentError::Parse(cause)),
            })
    }
}

const ALL_XPATH_NODES: &str = "//. | //@* | //namespace::*";
/// Bound ordinary XMLDSig XPath's per-node evaluation loop before user XPath runs.
/// Absolute ceiling for context-node evaluations in an ordinary XPath filter.
///
/// The signature-wide work budget is intentionally stricter for larger source
/// documents: an arbitrary expression can traverse the complete mirrored DOM
/// for every context node, and the XPath engine exposes no interrupt or step
/// counter that could safely distinguish a cheap expression from an expensive one.
const MAX_XPATH_CONTEXT_EVALUATIONS: usize = crate::hard_limits::XPATH_CONTEXT_EVALUATION_CEILING;
/// Bound conservative XPath evaluator node visits across one signature.
const MAX_XPATH_CUMULATIVE_EVALUATION_WORK: usize =
    crate::hard_limits::XPATH_EVALUATION_WORK_CEILING;
/// Bound operators, names, literals, and path punctuation in one expression.
const MAX_XPATH_EXPRESSION_COMPLEXITY: usize =
    crate::hard_limits::XPATH_EXPRESSION_COMPLEXITY_CEILING;
/// Bound strings copied into SXD before evaluating untrusted XPath.
const MAX_XPATH_MIRROR_STRING_BYTES: usize = crate::hard_limits::XPATH_MIRROR_STRING_BYTE_CEILING;
/// Bound conservative SXD string processing across one signature. The ceiling
/// accommodates comparison-heavy XMLDSig interoperability vectors while keeping
/// repeated non-interruptible source scans finite.
const MAX_XPATH_CUMULATIVE_STRING_WORK_BYTES: usize =
    crate::hard_limits::XPATH_STRING_WORK_BYTE_CEILING;
/// Namespace URI permanently bound to the reserved `xml` prefix.
const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

#[cfg(test)]
thread_local! {
    static FILTER2_PROJECTION_NODE_VISITS: Cell<usize> = const { Cell::new(0) };
}

pub(super) struct XPathWorkBudget {
    remaining: Cell<usize>,
    evaluation_limit_exceeded: Cell<bool>,
    mirror_bytes_remaining: Cell<usize>,
    string_work_bytes_remaining: Cell<usize>,
    limits: XPathWorkLimits,
}

#[derive(Clone, Copy)]
struct XPathWorkLimits {
    evaluation_work: usize,
    mirror_string_bytes: usize,
    string_work_bytes: usize,
    expression_bytes: usize,
    expression_complexity: usize,
    context_evaluations: usize,
    filters: usize,
}

impl Default for XPathWorkBudget {
    fn default() -> Self {
        Self {
            remaining: Cell::new(MAX_XPATH_CUMULATIVE_EVALUATION_WORK),
            evaluation_limit_exceeded: Cell::new(false),
            mirror_bytes_remaining: Cell::new(MAX_XPATH_MIRROR_STRING_BYTES),
            string_work_bytes_remaining: Cell::new(MAX_XPATH_CUMULATIVE_STRING_WORK_BYTES),
            limits: XPathWorkLimits {
                evaluation_work: MAX_XPATH_CUMULATIVE_EVALUATION_WORK,
                mirror_string_bytes: MAX_XPATH_MIRROR_STRING_BYTES,
                string_work_bytes: MAX_XPATH_CUMULATIVE_STRING_WORK_BYTES,
                expression_bytes: MAX_XPATH_EXPRESSION_BYTES,
                expression_complexity: MAX_XPATH_EXPRESSION_COMPLEXITY,
                context_evaluations: MAX_XPATH_CONTEXT_EVALUATIONS,
                filters: MAX_XPATH_FILTERS,
            },
        }
    }
}

impl XPathWorkBudget {
    #[cfg(test)]
    pub(super) fn with_limit(limit: usize) -> Self {
        Self {
            remaining: Cell::new(limit),
            evaluation_limit_exceeded: Cell::new(false),
            mirror_bytes_remaining: Cell::new(MAX_XPATH_MIRROR_STRING_BYTES),
            string_work_bytes_remaining: Cell::new(MAX_XPATH_CUMULATIVE_STRING_WORK_BYTES),
            limits: Self::default().limits,
        }
    }

    pub(super) fn with_limits(resources: &crate::policy::ResourcePolicy) -> Self {
        Self {
            remaining: Cell::new(resources.max_xpath_evaluation_work),
            evaluation_limit_exceeded: Cell::new(false),
            mirror_bytes_remaining: Cell::new(resources.max_xpath_mirror_string_bytes),
            string_work_bytes_remaining: Cell::new(resources.max_xpath_string_work_bytes),
            limits: XPathWorkLimits {
                evaluation_work: resources.max_xpath_evaluation_work,
                mirror_string_bytes: resources.max_xpath_mirror_string_bytes,
                string_work_bytes: resources.max_xpath_string_work_bytes,
                expression_bytes: resources.max_xpath_expression_bytes,
                expression_complexity: resources.max_xpath_expression_complexity,
                context_evaluations: resources.max_xpath_context_evaluations,
                filters: resources.max_xpath_filters,
            },
        }
    }

    pub(super) fn charge(&self, work: usize) -> Result<(), TransformError> {
        let remaining = self.remaining.get();
        let Some(next) = remaining.checked_sub(work) else {
            self.remaining.set(0);
            self.evaluation_limit_exceeded.set(true);
            let consumed = self.limits.evaluation_work.saturating_sub(remaining);
            return Err(transform_resource_limit(
                crate::policy::resource_name::XPATH_EVALUATION_WORK,
                self.limits.evaluation_work,
                consumed.saturating_add(work),
            ));
        };
        self.remaining.set(next);
        Ok(())
    }

    pub(super) fn validate_context_evaluations(&self, actual: usize) -> Result<(), TransformError> {
        if actual > self.limits.context_evaluations {
            return Err(transform_resource_limit(
                crate::policy::resource_name::XPATH_CONTEXT_EVALUATIONS,
                self.limits.context_evaluations,
                actual,
            ));
        }
        Ok(())
    }

    fn charge_function(&self, work: usize) -> Result<(), function::Error> {
        // The embedding boundary reconstructs the typed policy failure from
        // this same budget; do not allocate and then discard a diagnostic.
        self.charge(work)
            .map_err(|_| function::Error::ProcessingStopped)
    }

    fn map_evaluation_error(
        &self,
        error: impl std::fmt::Display,
        shared_failure: &Cell<Option<structured_asn1::memory::MemoryError>>,
        scratch: &impl XPathStorage,
    ) -> TransformError {
        if let Some(cause) = shared_failure.get() {
            return cause.into();
        }
        if self.evaluation_limit_exceeded.get() {
            transform_resource_limit(
                crate::policy::resource_name::XPATH_EVALUATION_WORK,
                self.limits.evaluation_work,
                self.limits.evaluation_work.saturating_add(1),
            )
        } else {
            scratch.diagnostic(format_args!("{error}"))
        }
    }

    fn charge_mirror_bytes(&self, bytes: usize) -> Result<(), TransformError> {
        let remaining = self.mirror_bytes_remaining.get();
        let Some(next) = remaining.checked_sub(bytes) else {
            self.mirror_bytes_remaining.set(0);
            let consumed = self.limits.mirror_string_bytes.saturating_sub(remaining);
            return Err(transform_resource_limit(
                crate::policy::resource_name::XPATH_MIRROR_STRING_BYTES,
                self.limits.mirror_string_bytes,
                consumed.saturating_add(bytes),
            ));
        };
        self.mirror_bytes_remaining.set(next);
        Ok(())
    }

    fn charge_string_work(
        &self,
        source_bytes: usize,
        evaluations: usize,
        scans_per_evaluation: usize,
    ) -> Result<(), TransformError> {
        let work = source_bytes
            .checked_mul(evaluations)
            .and_then(|work| work.checked_mul(scans_per_evaluation));
        let remaining = self.string_work_bytes_remaining.get();
        let Some(next) = work.and_then(|work| remaining.checked_sub(work)) else {
            self.string_work_bytes_remaining.set(0);
            let consumed = self.limits.string_work_bytes.saturating_sub(remaining);
            return Err(transform_resource_limit(
                crate::policy::resource_name::XPATH_STRING_WORK_BYTES,
                self.limits.string_work_bytes,
                work.map_or(usize::MAX, |work| consumed.saturating_add(work)),
            ));
        };
        self.string_work_bytes_remaining.set(next);
        Ok(())
    }
}

/// SXD's tokenizer rejects otherwise valid whitespace between a function QName
/// and `(`. Normalize only that token boundary, preserving quoted literals and
/// all whitespace that can affect string values or operator tokenization.
pub(super) fn is_xpath_whitespace(character: char) -> bool {
    // XPath 1.0 production S delegates to XML's four ASCII whitespace chars.
    matches!(character, ' ' | '\t' | '\r' | '\n')
}

#[cfg(test)]
pub(super) fn normalize_function_spacing(source: &str) -> String {
    match source::normalize(source, &crate::c14n::scratch::Native)
        .expect("native normalization accepts representable input")
    {
        source::Normalized::Original(source) => source.to_owned(),
        source::Normalized::Rewritten(source) => source,
    }
}

#[cfg(test)]
fn compile_xpath(source: &str) -> Result<sxd_xpath_no_unsafe::XPath, String> {
    compile_xpath_with_policy_limits(
        source,
        MAX_XPATH_EXPRESSION_BYTES,
        MAX_XPATH_EXPRESSION_COMPLEXITY,
    )
}

pub(super) fn compile_xpath_with_policy_limits(
    source: &str,
    max_expression_bytes: usize,
    max_expression_complexity: usize,
) -> Result<sxd_xpath_no_unsafe::XPath, String> {
    compile_native_xpath(source, max_expression_bytes, max_expression_complexity).map_err(|error| {
        match error {
            TransformError::XPath(message) => message,
            error => error.to_string(),
        }
    })
}

pub(super) fn compile_native_xpath(
    source: &str,
    max_expression_bytes: usize,
    max_expression_complexity: usize,
) -> Result<sxd_xpath_no_unsafe::XPath, TransformError> {
    if source.is_empty() || source.len() > max_expression_bytes {
        return Err(TransformError::XPath(format!(
            "XPath expression length must be between 1 and {max_expression_bytes} bytes"
        )));
    }
    if xpath_expression_complexity(source) > max_expression_complexity {
        return Err(TransformError::XPath(format!(
            "XPath expression complexity exceeds {max_expression_complexity} tokens"
        )));
    }
    let normalized = source::normalize(source, &crate::c14n::scratch::Native)?;
    Factory::new()
        .build(normalized.view()?)
        .map_err(|error| TransformError::XPath(error.to_string()))
}

pub(super) fn validate_xpath_current<W: structured_asn1::memory::Work>(
    source: &str,
    scratch: &crate::c14n::scratch::Accounted<'_, W>,
) -> Result<(), TransformError> {
    let normalized = source::normalize(source, scratch)?;
    scratch.compile(normalized.view()?).map(|_| ())
}

pub(super) fn xpath_expression_complexity(source: &str) -> usize {
    let mut chars = source.chars().peekable();
    let mut tokens = 0_usize;
    while let Some(character) = chars.next() {
        if is_xpath_whitespace(character) {
            continue;
        }
        tokens = tokens.saturating_add(1);
        if matches!(character, '\'' | '"') {
            for literal_character in chars.by_ref() {
                if literal_character == character {
                    break;
                }
            }
        } else if character.is_alphanumeric() || matches!(character, '_' | ':' | '-' | '.') {
            while chars
                .peek()
                .is_some_and(|next| next.is_alphanumeric() || matches!(next, '_' | ':' | '-' | '.'))
            {
                chars.next();
            }
        }
    }
    tokens
}

/// Count conservative full-source string passes before entering SXD.
///
/// Linear XPath 1.0 built-ins, numeric coercions, argument separators, and
/// comparison operators each contribute one pass so repeated node-set-to-value
/// conversions cannot hide behind one expression. Quoted literals are excluded;
/// unknown coercion paths are covered separately by the mandatory baseline scan.
pub(super) fn xpath_string_scan_count(source: &str) -> usize {
    let bytes = source.as_bytes();
    let mut scans = 0_usize;
    let mut index = 0_usize;
    let mut quote = None;
    let mut can_end_operand = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if matches!(byte, b'\'' | b'"') {
            if quote == Some(byte) {
                quote = None;
                can_end_operand = true;
            } else if quote.is_none() {
                quote = Some(byte);
            }
            index += 1;
            continue;
        }
        if quote.is_some() {
            index += 1;
            continue;
        }
        if byte.is_ascii_digit() {
            can_end_operand = true;
            index += 1;
            continue;
        }
        if !(byte.is_ascii_alphabetic() || byte == b'_') {
            match byte {
                b',' | b'=' | b'<' | b'>' => {
                    // This charge matches xml-sec-sxd-xpath 0.1.0 rather than
                    // XPath's abstract pairwise wording: node-set equality
                    // builds one HashSet<String> per operand and tests set
                    // intersection, while relational comparison coerces each
                    // operand once through Value::number(). There is no nested
                    // node-pair loop to charge quadratically. Re-audit this
                    // invariant before changing the pinned evaluator version.
                    scans = scans.saturating_add(1);
                    can_end_operand = false;
                }
                b'+' | b'-' => {
                    scans = scans.saturating_add(1);
                    can_end_operand = false;
                }
                b'*' if can_end_operand => {
                    scans = scans.saturating_add(1);
                    can_end_operand = false;
                }
                b'*' | b'.' | b')' | b']' => can_end_operand = true,
                b'(' | b'[' | b'/' | b'|' | b'@' | b':' | b'!' => {
                    can_end_operand = false;
                }
                _ => {}
            }
            index += 1;
            continue;
        }

        let name_start = index;
        index += 1;
        while bytes
            .get(index)
            .is_some_and(|byte| is_xpath_identifier_byte(*byte))
        {
            index += 1;
        }
        let mut call_start = index;
        while bytes
            .get(call_start)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        {
            call_start += 1;
        }
        let name = &source[name_start..index];
        if name.ends_with("::") {
            can_end_operand = false;
        } else if bytes.get(call_start) == Some(&b'(') {
            if is_xpath_value_scanning_function(name) {
                scans = scans.saturating_add(1);
            }
            can_end_operand = false;
        } else if can_end_operand && matches!(name, "div" | "mod") {
            scans = scans.saturating_add(1);
            can_end_operand = false;
        } else {
            can_end_operand = !(can_end_operand && matches!(name, "and" | "or"));
        }
    }
    scans
}

pub(super) fn xpath_may_read_node_values(source: &str) -> bool {
    let scans = xpath_string_scan_count(source);
    if scans == 0 {
        return false;
    }

    // A top-level comparison between count(node-set) and a number observes
    // cardinality only. Keep this structural XMLDSig here() idiom distinct
    // from node-set/string comparisons, which coerce mutable node text.
    scans != 1 || !is_count_number_comparison(source)
}

/// Whether XPath value coercion can observe mutable element character data.
///
/// Attribute-to-literal comparisons are value reads, but XMLDSig fills neither
/// attributes nor their owners while constructing a signature. Keep those
/// predicates out of the mutable-node dependency graph; every other coercion
/// remains conservative because it can consume an element or text string-value.
pub(super) fn xpath_may_read_mutable_character_data(source: &str) -> bool {
    xpath_may_read_node_values(source) && !comparisons_are_attribute_to_scalar(source)
}

fn comparisons_are_attribute_to_scalar(source: &str) -> bool {
    let bytes = source.as_bytes();
    let mut quote = None;
    let mut index = 0_usize;
    let mut comparisons = 0_usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if matches!(byte, b'\'' | b'"') {
            if quote == Some(byte) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(byte);
            }
            index += 1;
            continue;
        }
        if quote.is_some() {
            index += 1;
            continue;
        }
        let operator_len = match byte {
            b'=' => 1,
            b'!' if bytes.get(index + 1) == Some(&b'=') => 2,
            b'<' | b'>' => 1 + usize::from(bytes.get(index + 1) == Some(&b'=')),
            _ => {
                index += 1;
                continue;
            }
        };
        comparisons = comparisons.saturating_add(1);
        let left = source[..index].trim_end_matches(is_xpath_whitespace);
        let right = source[index + operator_len..].trim_start_matches(is_xpath_whitespace);
        if !(operand_ends_in_attribute(left) && operand_starts_with_scalar(right)
            || operand_ends_in_scalar(left) && operand_starts_with_attribute(right))
        {
            return false;
        }
        index += operator_len;
    }
    comparisons > 0 && xpath_string_scan_count(source) == comparisons
}

fn operand_ends_in_attribute(source: &str) -> bool {
    let operand = source.trim_end_matches(is_xpath_whitespace);
    let name_start = operand
        .as_bytes()
        .iter()
        .rposition(|byte| !is_xpath_identifier_byte(*byte))
        .map_or(0, |index| index + 1);
    name_start > 0 && operand.as_bytes().get(name_start - 1) == Some(&b'@')
}

fn operand_starts_with_attribute(source: &str) -> bool {
    source
        .trim_start_matches(is_xpath_whitespace)
        .starts_with('@')
}

fn operand_ends_in_scalar(source: &str) -> bool {
    let operand = source.trim_end_matches(is_xpath_whitespace);
    operand.ends_with('\'')
        || operand.ends_with('"')
        || operand
            .split(|byte: char| is_xpath_whitespace(byte) || matches!(byte, '(' | ','))
            .next_back()
            .is_some_and(|value| value.parse::<f64>().is_ok())
}

fn operand_starts_with_scalar(source: &str) -> bool {
    let operand = source.trim_start_matches(is_xpath_whitespace);
    operand.starts_with(['\'', '"'])
        || operand
            .split(|byte: char| is_xpath_whitespace(byte) || matches!(byte, ')' | ','))
            .next()
            .is_some_and(|value| value.parse::<f64>().is_ok())
}

fn is_count_number_comparison(source: &str) -> bool {
    let bytes = source.as_bytes();
    let mut depth = 0_usize;
    let mut quote = None;
    let mut index = 0_usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if matches!(byte, b'\'' | b'"') {
            if quote == Some(byte) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(byte);
            }
            index += 1;
            continue;
        }
        if quote.is_some() {
            index += 1;
            continue;
        }
        match byte {
            b'(' | b'[' => depth = depth.saturating_add(1),
            b')' | b']' => depth = depth.saturating_sub(1),
            b'=' | b'<' | b'>' if depth == 0 => {
                let operator_len = usize::from(bytes.get(index + 1) == Some(&b'=')) + 1;
                let left = source[..index].trim_matches(is_xpath_whitespace);
                let right = source[index + operator_len..].trim_matches(is_xpath_whitespace);
                return (is_count_call(left) && is_xpath_number(right))
                    || (is_xpath_number(left) && is_count_call(right));
            }
            b'!' if depth == 0 && bytes.get(index + 1) == Some(&b'=') => {
                let left = source[..index].trim_matches(is_xpath_whitespace);
                let right = source[index + 2..].trim_matches(is_xpath_whitespace);
                return (is_count_call(left) && is_xpath_number(right))
                    || (is_xpath_number(left) && is_count_call(right));
            }
            _ => {}
        }
        index += 1;
    }
    false
}

fn is_count_call(source: &str) -> bool {
    let Some(arguments) = source.strip_prefix("count(") else {
        return false;
    };
    arguments
        .strip_suffix(')')
        .is_some_and(|arguments| !arguments.is_empty())
}

fn is_xpath_number(source: &str) -> bool {
    !source.is_empty() && source.parse::<f64>().is_ok()
}

fn is_xpath_value_scanning_function(name: &str) -> bool {
    matches!(
        name,
        "string"
            | "concat"
            | "starts-with"
            | "contains"
            | "substring-before"
            | "substring-after"
            | "substring"
            | "string-length"
            | "normalize-space"
            | "translate"
            | "number"
            | "sum"
            | "floor"
            | "ceiling"
            | "round"
            | "id"
            | "lang"
    )
}

/// Estimate one XPath evaluation before entering SXD's non-interruptible engine.
///
/// One top-level traversal is covered by the baseline document-size charge.
/// Composed scanning steps gain one document-size factor, while independent
/// expression branches add their traversal costs. Predicate scans inherit the
/// enclosing path depth and gain another factor per predicate level. Saturation
/// deliberately turns arithmetic overflow into a budget rejection. `scratch`
/// pays for the source scan and owns the per-predicate state.
fn xpath_evaluation_work<S: crate::c14n::scratch::Scratch>(
    source: &str,
    document_size: usize,
    mode: XPathEvaluationMode,
    scratch: &S,
) -> Result<usize, crate::c14n::C14nError> {
    use crate::c14n::scratch::List as _;
    scratch.charge(source.len())?;
    let bytes = source.as_bytes();
    let mut work = document_size;
    let mut predicate_depth = 0_usize;
    let mut top_level_path_scans = 0_usize;
    let mut top_level_path_started = false;
    let mut top_level_path_branches = 0_usize;
    let mut predicate_path_scans = scratch.values();
    let mut predicate_path_started = scratch.values();
    let mut parent_steps = 0_usize;
    let mut quote = None;
    let mut index = 0_usize;

    while index < bytes.len() {
        let byte = bytes[index];
        if matches!(byte, b'\'' | b'"') {
            if quote == Some(byte) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(byte);
            }
            index += 1;
            continue;
        }
        if quote.is_some() {
            index += 1;
            continue;
        }
        if let Some(operator_len) = xpath_word_operator_len(bytes, index) {
            reset_xpath_path_scan_depth(
                predicate_depth,
                &mut top_level_path_scans,
                &mut predicate_path_scans,
                &mut top_level_path_started,
                &mut predicate_path_started,
            );
            index = index.saturating_add(operator_len);
            continue;
        }

        match byte {
            b'[' => {
                predicate_depth = predicate_depth.saturating_add(1);
                predicate_path_scans.push(0)?;
                predicate_path_started.push(false)?;
            }
            b']' => {
                predicate_depth = predicate_depth.saturating_sub(1);
                predicate_path_scans.pop();
                predicate_path_started.pop();
            }
            b'/' => {
                let descendant_abbreviation = bytes.get(index + 1) == Some(&b'/');
                let next_step_is_parent = !descendant_abbreviation
                    && bytes.get(index + 1..index.saturating_add(3)) == Some(b"..");
                let next_step_has_explicit_axis = !descendant_abbreviation
                    && xpath_explicit_axis_after(bytes, index.saturating_add(1));
                if descendant_abbreviation || (!next_step_is_parent && !next_step_has_explicit_axis)
                {
                    charge_xpath_path_branch(
                        &mut work,
                        document_size,
                        predicate_depth,
                        top_level_path_scans,
                        &mut top_level_path_started,
                        &mut top_level_path_branches,
                        &mut predicate_path_started,
                    );
                }
                if descendant_abbreviation {
                    charge_xpath_document_scan(
                        &mut work,
                        document_size,
                        predicate_depth,
                        &mut top_level_path_scans,
                        &mut predicate_path_scans,
                    );
                    index += 1;
                }
            }
            b'.' if bytes.get(index + 1) == Some(&b'.') => {
                parent_steps = parent_steps.saturating_add(1);
                index += 1;
            }
            b':' if bytes.get(index + 1) == Some(&b':') => {
                let mut axis_start = index;
                while axis_start > 0 && is_xpath_name_byte(bytes[axis_start - 1]) {
                    axis_start -= 1;
                }
                let axis = &source[axis_start..index];
                if axis == "child" || is_document_scanning_axis(axis) {
                    charge_xpath_path_branch(
                        &mut work,
                        document_size,
                        predicate_depth,
                        top_level_path_scans,
                        &mut top_level_path_started,
                        &mut top_level_path_branches,
                        &mut predicate_path_started,
                    );
                }
                if is_document_scanning_axis(axis) {
                    charge_xpath_document_scan(
                        &mut work,
                        document_size,
                        predicate_depth,
                        &mut top_level_path_scans,
                        &mut predicate_path_scans,
                    );
                } else if axis == "parent" {
                    parent_steps = parent_steps.saturating_add(1);
                }
                index += 1;
            }
            b'|' | b',' | b'+' | b'=' | b'<' | b'>' => reset_xpath_path_scan_depth(
                predicate_depth,
                &mut top_level_path_scans,
                &mut predicate_path_scans,
                &mut top_level_path_started,
                &mut predicate_path_started,
            ),
            _ => {}
        }
        index += 1;
    }

    work = work
        .saturating_add(document_size.saturating_mul(top_level_path_branches.saturating_sub(1)));

    // Filter2 selects from the document in one evaluation, so every parent step
    // can run for each selected node. XMLDSig XPath evaluates once per input node;
    // within each such evaluation one parent step remains constant work.
    let parent_step_contexts = match mode {
        XPathEvaluationMode::XmlDsigPerNodeFilter => 1,
        XPathEvaluationMode::Filter2NodeSetSelection => document_size,
    };
    work = work.saturating_add(parent_step_contexts.saturating_mul(parent_steps));

    Ok(work)
}

fn charge_xpath_path_branch(
    work: &mut usize,
    document_size: usize,
    predicate_depth: usize,
    top_level_path_scans: usize,
    top_level_path_started: &mut bool,
    top_level_path_branches: &mut usize,
    predicate_path_started: &mut [bool],
) {
    if predicate_depth == 0 {
        if !*top_level_path_started {
            *top_level_path_started = true;
            *top_level_path_branches = top_level_path_branches.saturating_add(1);
        }
        return;
    }

    let Some(path_started) = predicate_path_started.get_mut(predicate_depth - 1) else {
        *work = usize::MAX;
        return;
    };
    if !*path_started {
        let exponent = top_level_path_scans.max(1).saturating_add(predicate_depth);
        *work = work.saturating_add(document_traversal_work(document_size, exponent));
        *path_started = true;
    }
}

fn charge_xpath_document_scan(
    work: &mut usize,
    document_size: usize,
    predicate_depth: usize,
    top_level_path_scans: &mut usize,
    predicate_path_scans: &mut [usize],
) {
    if predicate_depth == 0 {
        *top_level_path_scans = top_level_path_scans.saturating_add(1);
        if *top_level_path_scans > 1 {
            *work = work.saturating_add(document_traversal_work(
                document_size,
                *top_level_path_scans,
            ));
        }
        return;
    }

    let Some(predicate_scans) = predicate_path_scans.get_mut(predicate_depth - 1) else {
        *work = usize::MAX;
        return;
    };
    *predicate_scans = predicate_scans.saturating_add(1);
    if *predicate_scans > 1 {
        let exponent = (*top_level_path_scans)
            .max(1)
            .saturating_add(predicate_depth)
            .saturating_add(predicate_scans.saturating_sub(1));
        *work = work.saturating_add(document_traversal_work(document_size, exponent));
    }
}

fn reset_xpath_path_scan_depth(
    predicate_depth: usize,
    top_level_path_scans: &mut usize,
    predicate_path_scans: &mut [usize],
    top_level_path_started: &mut bool,
    predicate_path_started: &mut [bool],
) {
    if predicate_depth == 0 {
        *top_level_path_scans = 0;
        *top_level_path_started = false;
    } else if let Some(predicate_scans) = predicate_path_scans.get_mut(predicate_depth - 1) {
        *predicate_scans = 0;
        if let Some(path_started) = predicate_path_started.get_mut(predicate_depth - 1) {
            *path_started = false;
        }
    }
}

fn document_traversal_work(document_size: usize, exponent: usize) -> usize {
    (0..exponent).fold(1_usize, |work, _| work.saturating_mul(document_size))
}

fn xpath_word_operator_len(source: &[u8], index: usize) -> Option<usize> {
    [b"and".as_slice(), b"or", b"div", b"mod"]
        .into_iter()
        .find(|operator| {
            source[index..].starts_with(operator)
                && (index == 0 || !is_xpath_identifier_byte(source[index - 1]))
                && source
                    .get(index + operator.len())
                    .is_none_or(|byte| !is_xpath_identifier_byte(*byte))
        })
        .map(<[u8]>::len)
}

fn xpath_explicit_axis_after(source: &[u8], mut index: usize) -> bool {
    while source
        .get(index)
        .is_some_and(|byte| is_xpath_name_byte(*byte))
    {
        index = index.saturating_add(1);
    }
    source.get(index..index.saturating_add(2)) == Some(b"::")
}

fn is_xpath_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

fn is_xpath_identifier_byte(byte: u8) -> bool {
    byte >= 0x80 || byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':')
}

fn is_document_scanning_axis(axis: &str) -> bool {
    matches!(
        axis,
        "ancestor"
            | "ancestor-or-self"
            | "descendant"
            | "descendant-or-self"
            | "following"
            | "following-sibling"
            | "preceding"
            | "preceding-sibling"
    )
}

struct Mirror<
    'source,
    'd,
    K: Keys = NativeKeys,
    D: crate::xml::dom::storage::Storage = crate::xml::dom::storage::Native,
> {
    source: &'source Document<'source, D>,
    elements: K::Index<(usize, usize, usize), NodeId>,
    attributes: K::Index<(usize, usize, usize), (NodeId, usize)>,
    namespaces: K::NamespaceIndex<'source>,
    texts: K::Index<(usize, usize, usize), NodeId>,
    comments: K::Index<(usize, usize, usize), NodeId>,
    processing_instructions: K::Index<(usize, usize, usize), NodeId>,
    lifetime: std::marker::PhantomData<dom::Document<'d>>,
    #[cfg(test)]
    target: dom::Document<'d>,
}

#[cfg(test)]
impl<'source, 'd> Mirror<'source, 'd, NativeKeys> {
    fn build(source: &'source Document<'source>, target: dom::Document<'d>) -> Self {
        Self::build_in(source, target, ()).expect("native mirror has no shared execution ceiling")
    }
}

impl<'source, 'd, K: Keys, D: crate::xml::dom::storage::Storage> Mirror<'source, 'd, K, D> {
    /// Measures exactly the source strings passed to SXD by [`Self::build`].
    ///
    /// Keep this traversal structurally aligned with `build`: unlike the
    /// node-set budget, it includes character data and attribute values, and
    /// charges repeated namespace registrations separately.
    fn projected_string_bytes(source: &Document<'_, D>) -> Result<usize, TransformError> {
        let mut projected_bytes = 0_usize;
        for node in source.descendants().filter(|node| !node.is_root()) {
            if node.is_element() {
                projected_bytes = charge_xpath_mirror_bytes(
                    projected_bytes,
                    node.tag_name().namespace().map_or(0, str::len),
                )?;
                projected_bytes =
                    charge_xpath_mirror_bytes(projected_bytes, node.tag_name().name().len())?;

                for namespace in node.namespaces() {
                    projected_bytes = charge_xpath_mirror_bytes(
                        projected_bytes,
                        namespace.name().map_or(0, str::len),
                    )?;
                    projected_bytes =
                        charge_xpath_mirror_bytes(projected_bytes, namespace.uri().len())?;
                    if namespace.name().is_none() {
                        // Mirror::build stores the default URI both as SXD's
                        // default namespace and as the empty-prefix axis entry.
                        projected_bytes =
                            charge_xpath_mirror_bytes(projected_bytes, namespace.uri().len())?;
                    }
                }

                projected_bytes =
                    charge_xpath_mirror_bytes(projected_bytes, element_prefix(node).len())?;
                for attribute in node.attributes() {
                    projected_bytes = charge_xpath_mirror_bytes(
                        projected_bytes,
                        attribute.namespace().map_or(0, str::len),
                    )?;
                    projected_bytes =
                        charge_xpath_mirror_bytes(projected_bytes, attribute.name().len())?;
                    projected_bytes =
                        charge_xpath_mirror_bytes(projected_bytes, attribute.value().len())?;
                    projected_bytes = charge_xpath_mirror_bytes(
                        projected_bytes,
                        attribute_prefix(node, attribute).len(),
                    )?;
                }
            } else if node.is_text() || node.is_comment() {
                projected_bytes =
                    charge_xpath_mirror_bytes(projected_bytes, node.text().map_or(0, str::len))?;
            } else if let Some(pi) = node.pi() {
                projected_bytes = charge_xpath_mirror_bytes(projected_bytes, pi.target.len())?;
                projected_bytes =
                    charge_xpath_mirror_bytes(projected_bytes, pi.value.map_or(0, str::len))?;
            }
        }
        Ok(projected_bytes)
    }

    fn build_in(
        source: &'source Document<'source, D>,
        target: dom::Document<'d>,
        execution: K::Execution,
    ) -> Result<Self, crate::c14n::C14nError> {
        use mirror::Construction as _;
        let scratch = K::scratch(execution);
        let construction = scratch.construction(target);
        let mut mirror = Self {
            source,
            elements: K::index(execution),
            attributes: K::index(execution),
            namespaces: K::namespace_index(execution),
            texts: K::index(execution),
            comments: K::index(execution),
            processing_instructions: K::index(execution),
            lifetime: std::marker::PhantomData,
            #[cfg(test)]
            target,
        };
        let mut parents = K::index::<usize, dom::Element<'d>>(execution);

        // Descendants are yielded in document order, so every element parent
        // has already been mirrored when one of its children is encountered.
        for source_node in source.descendants().filter(|node| !node.is_root()) {
            let source_parent = source_node.parent();
            K::admit(execution, 1)?;
            let target_parent = match source_parent {
                Some(node) => parents
                    .lookup(&(node.id().get() as usize), execution)?
                    .copied(),
                None => None,
            };

            if source_node.is_element() {
                let name = QName::with_namespace_uri(
                    source_node.tag_name().namespace(),
                    source_node.tag_name().name(),
                );
                let element = construction.element(name)?;
                construction.declarations(
                    element,
                    source_node
                        .namespaces()
                        .map(|namespace| (namespace.name(), namespace.uri())),
                )?;

                // SXD's namespaces_in_scope() always injects the predefined
                // xml binding, even when no prefix was registered explicitly.
                for (ordinal, namespace) in source_node.namespaces().enumerate() {
                    mirror.namespaces.insert_namespace(
                        NamespaceKey {
                            owner: element.identity_key(),
                            prefix: namespace.name().unwrap_or(""),
                            uri: namespace.uri(),
                        },
                        ordinal,
                    )?;
                }
                let prefix = element_prefix(source_node);
                construction.element_prefix(element, (!prefix.is_empty()).then_some(prefix))?;

                for (ordinal, attribute) in source_node.attributes().enumerate() {
                    let name = QName::with_namespace_uri(attribute.namespace(), attribute.name());
                    let target_attribute =
                        construction.attribute(element, name, attribute.value())?;
                    mirror
                        .attributes
                        .insert(target_attribute.identity_key(), (source_node.id(), ordinal))?;
                    let prefix = attribute_prefix(source_node, attribute);
                    construction.attribute_prefix(
                        target_attribute,
                        (!prefix.is_empty()).then_some(prefix),
                    )?;
                }

                match target_parent {
                    Some(parent) => construction.append_element(parent, element.into())?,
                    None => construction.append_root(element.into())?,
                }
                parents.insert(source_node.id().get() as usize, element)?;
                mirror
                    .elements
                    .insert(element.identity_key(), source_node.id())?;
            } else if source_node.is_text() {
                // roxmltree already coalesces adjacent character data across
                // CDATA boundaries into the single text node required by the
                // XPath 1.0 data model. It also omits whitespace outside the
                // document element, so every mirrored text has an element parent.
                if let Some(parent) = target_parent {
                    let text = construction.text(source_node.text().unwrap_or_default())?;
                    construction.append_element(parent, text.into())?;
                    mirror.texts.insert(text.identity_key(), source_node.id())?;
                }
            } else if source_node.is_comment() {
                let comment = construction.comment(source_node.text().unwrap_or_default())?;
                match target_parent {
                    Some(parent) => construction.append_element(parent, comment.into())?,
                    None => construction.append_root(comment.into())?,
                }
                mirror
                    .comments
                    .insert(comment.identity_key(), source_node.id())?;
            } else if source_node.is_pi()
                && let Some(pi) = source_node.pi()
            {
                let processing_instruction = construction.pi(pi.target, pi.value)?;
                match target_parent {
                    Some(parent) => {
                        construction.append_element(parent, processing_instruction.into())?
                    }
                    None => construction.append_root(processing_instruction.into())?,
                }
                mirror
                    .processing_instructions
                    .insert(processing_instruction.identity_key(), source_node.id())?;
            }
        }

        Ok(mirror)
    }

    fn project_exact_node<'a>(
        &self,
        source: &'a Document<'a, D>,
        result: &mut Projection<'a, K, D>,
        node: &nodeset::Node<'d>,
        budget: &NodeSetMaterializationBudget,
    ) -> Result<(), TransformError> {
        match node {
            nodeset::Node::Root(_) => result.insert_tree(source.root(), Some(budget))?,
            nodeset::Node::Element(element) => {
                if let Some(source_node) = self.lookup_node(
                    source,
                    &self.elements,
                    element.identity_key(),
                    result.execution(),
                )? {
                    result.insert_tree(source_node, Some(budget))?;
                }
            }
            node => self.project_leaf(source, result, node, budget)?,
        }
        Ok(())
    }

    fn project_expanded<'a>(
        &self,
        source: &'a Document<'a, D>,
        input: &Projection<'a, K, D>,
        selected: nodeset::Nodeset<'d>,
        materialization_budget: &NodeSetMaterializationBudget,
    ) -> Result<Projection<'a, K, D>, TransformError> {
        let execution = input.execution();
        let mut result = input.empty_like();
        let mut selected_elements = input.empty_like();
        let mut root_selected = false;

        // Non-container XPath nodes have no descendants and are projected
        // exactly. Element/root selections are expanded together below.
        // Projection is set union by original identity, not an ordered XPath
        // sequence. Borrow the entries; document-order keys and namespace
        // copies cannot affect the resulting membership.
        use sxd_xpath_no_unsafe::runtime::Runtime as _;
        let scratch = K::scratch(execution);
        let failure = Cell::new(None);
        let runtime = scratch.runtime(&failure);
        let entries = runtime
            .nodes(&selected)
            .map_err(|error| match failure.get() {
                Some(cause) => TransformError::from(cause),
                None => scratch.diagnostic(format_args!("{error}")),
            })?;
        for node in entries {
            match node {
                nodeset::Node::Root(_) => root_selected = true,
                nodeset::Node::Element(element) => {
                    if let Some(source_node) =
                        self.lookup_node(source, &self.elements, element.identity_key(), execution)?
                    {
                        selected_elements.insert_tree(source_node, Some(materialization_budget))?;
                    }
                }
                node => self.project_leaf(source, &mut result, node, materialization_budget)?,
            }
        }

        // The semantic arena is contiguous preorder. An admitted subtree end
        // replaces a DFS stack; nested selections never rewalk descendants or
        // need a second native set of selected identities.
        if !root_selected && selected_elements.len() == 0 {
            return Ok(result);
        }
        input.admit_walk(source.descendants().len())?;
        let mut selected_end = if root_selected {
            source.descendants().len()
        } else {
            0
        };
        for node in source.descendants() {
            #[cfg(test)]
            FILTER2_PROJECTION_NODE_VISITS.with(|visits| visits.set(visits.get() + 1));
            let ordinal = node.id().get() as usize;
            if ordinal >= selected_end && selected_elements.contains_tree(node)? {
                // Node IDs and subtree lengths originate in the same bounded
                // arena; the subtree end cannot exceed its total length.
                selected_end = ordinal + node.descendants().len();
                debug_assert!(selected_end <= source.descendants().len());
            }
            if ordinal < selected_end {
                result.insert_tree(node, Some(materialization_budget))?;
                if node.is_element() {
                    for (ordinal, _) in node.attributes().enumerate() {
                        result.insert_attribute_at(node, ordinal, materialization_budget)?;
                    }
                    for (ordinal, _) in node.namespaces().enumerate() {
                        result.insert_namespace_at(node, ordinal, materialization_budget)?;
                    }
                }
            }
        }

        Ok(result)
    }

    fn owns_source(&self, source: &Document<'_, D>) -> bool {
        std::ptr::eq(self.source, source)
    }

    fn lookup_node<'a>(
        &self,
        source: &'a Document<'a, D>,
        index: &K::Index<(usize, usize, usize), NodeId>,
        key: (usize, usize, usize),
        execution: K::Execution,
    ) -> Result<Option<crate::xml::dom::Node<'a, 'a, D>>, structured_asn1::memory::MemoryError>
    {
        if !self.owns_source(source) {
            return Ok(None);
        }
        Ok(index
            .lookup(&key, execution)?
            .and_then(|id| source.get_node(*id)))
    }

    fn attribute_source<'a>(
        &self,
        source: &'a Document<'a, D>,
        attribute: dom::Attribute<'d>,
        execution: K::Execution,
    ) -> Result<
        Option<(crate::xml::dom::Node<'a, 'a, D>, usize)>,
        structured_asn1::memory::MemoryError,
    > {
        if !self.owns_source(source) {
            return Ok(None);
        }
        let Some((owner, ordinal)) = self
            .attributes
            .lookup(&attribute.identity_key(), execution)?
        else {
            return Ok(None);
        };
        Ok(source.get_node(*owner).map(|owner| (owner, *ordinal)))
    }
    fn namespace_source<'a>(
        &self,
        source: &'a Document<'a, D>,
        namespace: &nodeset::Namespace<'d>,
        execution: K::Execution,
    ) -> Result<
        Option<(crate::xml::dom::Node<'a, 'a, D>, usize)>,
        structured_asn1::memory::MemoryError,
    > {
        let Some(owner) = self.lookup_node(
            source,
            &self.elements,
            namespace.parent().identity_key(),
            execution,
        )?
        else {
            return Ok(None);
        };
        let Some(ordinal) = self.namespaces.lookup_namespace(
            &NamespaceKey {
                owner: namespace.parent().identity_key(),
                prefix: namespace.prefix(),
                uri: namespace.uri(),
            },
            execution,
        )?
        else {
            return Ok(None);
        };
        Ok(Some((owner, ordinal)))
    }

    fn project_leaf<'a>(
        &self,
        source: &'a Document<'a, D>,
        result: &mut Projection<'a, K, D>,
        node: &nodeset::Node<'d>,
        budget: &NodeSetMaterializationBudget,
    ) -> Result<(), TransformError> {
        let execution = result.execution();
        match node {
            nodeset::Node::Attribute(attribute) => {
                if let Some((owner, ordinal)) =
                    self.attribute_source(source, *attribute, execution)?
                {
                    result.insert_attribute_at(owner, ordinal, budget)?;
                }
            }
            nodeset::Node::Namespace(namespace) => {
                if let Some((owner, ordinal)) =
                    self.namespace_source(source, namespace, execution)?
                {
                    result.insert_namespace_at(owner, ordinal, budget)?;
                }
            }
            nodeset::Node::Text(text) => {
                if let Some(node) =
                    self.lookup_node(source, &self.texts, text.identity_key(), execution)?
                {
                    result.insert_tree(node, Some(budget))?;
                }
            }
            nodeset::Node::Comment(comment) => {
                if let Some(node) =
                    self.lookup_node(source, &self.comments, comment.identity_key(), execution)?
                {
                    result.insert_tree(node, Some(budget))?;
                }
            }
            nodeset::Node::ProcessingInstruction(pi) => {
                if let Some(node) = self.lookup_node(
                    source,
                    &self.processing_instructions,
                    pi.identity_key(),
                    execution,
                )? {
                    result.insert_tree(node, Some(budget))?;
                }
            }
            nodeset::Node::Root(_) | nodeset::Node::Element(_) => {
                unreachable!("container projection is selected by the caller")
            }
        }
        Ok(())
    }

    fn input_contains<'a>(
        &self,
        source: &'a Document<'a, D>,
        input: &Projection<'a, K, D>,
        node: &nodeset::Node<'d>,
    ) -> Result<bool, crate::c14n::C14nError> {
        let execution = input.execution();
        match node {
            nodeset::Node::Root(_) => input.contains_tree(source.root()),
            nodeset::Node::Element(element) => {
                match self.lookup_node(source, &self.elements, element.identity_key(), execution)? {
                    Some(node) => input.contains_tree(node),
                    None => Ok(false),
                }
            }
            nodeset::Node::Attribute(attribute) => {
                match self.attribute_source(source, *attribute, execution)? {
                    Some((owner, ordinal)) => input.contains_attribute_at(owner, ordinal),
                    None => Ok(false),
                }
            }
            nodeset::Node::Text(text) => {
                match self.lookup_node(source, &self.texts, text.identity_key(), execution)? {
                    Some(node) => input.contains_tree(node),
                    None => Ok(false),
                }
            }
            nodeset::Node::Comment(comment) => {
                match self.lookup_node(source, &self.comments, comment.identity_key(), execution)? {
                    Some(node) => input.contains_tree(node),
                    None => Ok(false),
                }
            }
            nodeset::Node::Namespace(namespace) => {
                match self.namespace_source(source, namespace, execution)? {
                    Some((owner, ordinal)) => input.contains_namespace_at(owner, ordinal),
                    None => Ok(false),
                }
            }
            nodeset::Node::ProcessingInstruction(pi) => {
                match self.lookup_node(
                    source,
                    &self.processing_instructions,
                    pi.identity_key(),
                    execution,
                )? {
                    Some(node) => input.contains_tree(node),
                    None => Ok(false),
                }
            }
        }
    }
}

fn charge_xpath_mirror_bytes(current: usize, additional: usize) -> Result<usize, TransformError> {
    super::types::charge_resource_bytes(
        current,
        additional,
        MAX_XPATH_MIRROR_STRING_BYTES,
        crate::policy::resource_name::XPATH_MIRROR_STRING_BYTES,
    )
}

/// Resolves XML Signature's `here()` function to the node selected by the
/// caller's standards/compatibility policy. The current query owns the path;
/// the evaluator borrows this extension rather than boxing it as a static one.
struct HereFunction<'s, L, K: Keys> {
    context: HereContext<L>,
    execution: K::Execution,
    failure: &'s Cell<Option<structured_asn1::memory::MemoryError>>,
}

enum HereContext<L> {
    Path(L),
    CrossDocument,
    MissingParameterNode,
}

impl<L: std::ops::Deref<Target = [usize]>, K: Keys> function::Function for HereFunction<'_, L, K> {
    fn evaluate_borrowed<'c, 'd>(
        &self,
        context: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: &mut [Value<'d>],
    ) -> Result<Value<'d>, function::Error> {
        function::Args::new(args).exactly(0)?;
        let path = match &self.context {
            HereContext::Path(path) => path,
            // XMLDSig XPath and Filter 2.0 require an error when the parameter
            // carrying the expression belongs to another XML document.
            HereContext::CrossDocument => {
                return Err(function::Error::Static {
                    what: "here() parameter and evaluation context must appear in the same XML document",
                });
            }
            HereContext::MissingParameterNode => {
                return Err(function::Error::Static {
                    what: "here() requires an XPath expression parsed from an XML parameter",
                });
            }
        };
        let mut node = nodeset::Node::Root(context.node.document().root());
        for &index in &**path {
            context.charge_work(1)?;
            node = node.child_at(index).ok_or(function::Error::Static {
                what: "here() context node no longer exists",
            })?;
        }
        use sxd_xpath_no_unsafe::runtime::{Runtime as _, Set as _};
        let scratch = K::scratch(self.execution);
        let runtime = scratch.runtime(self.failure);
        let mut result = runtime.set();
        result.insert(context, node)?;
        Ok(Value::Nodeset(result.finish()))
    }
}

/// SXD omits XPath's DTD-aware `id()` function. XMLDSig commonly identifies
/// elements through `Id`, `ID`, `id`, xml:id, or retained DTD ID type,
/// matching this crate's semantic DOM without requiring a validating parser.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Identifier<'a>(&'a str);

struct NumberLexical(f64);

impl std::fmt::Display for NumberLexical {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        sxd_xpath_no_unsafe::write_xpath_number(output, self.0)
    }
}

impl structured_asn1::memory::HashWork for Identifier<'_> {
    fn hash_work(&self) -> Result<u64, structured_asn1::memory::MemoryError> {
        structured_asn1::memory::HashWork::hash_work(self.0)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum IdMatch {
    Absent,
    First,
    Repeated,
    Ambiguous,
}

struct IdRequests<'a, K: Keys> {
    identifiers: K::Index<Identifier<'a>, Option<(usize, usize, usize)>>,
}

struct IdTextStack<'q, L> {
    frames: L,
    failure: &'q Cell<Option<structured_asn1::memory::MemoryError>>,
}

impl<'d, L: crate::c14n::scratch::List<(nodeset::Node<'d>, usize)>> nodeset::TextStack<'d>
    for IdTextStack<'_, L>
{
    fn push(
        &mut self,
        frame: (nodeset::Node<'d>, usize),
        _context: &sxd_xpath_no_unsafe::context::Evaluation<'_, '_>,
    ) -> Result<(), function::Error> {
        self.frames.push(frame).map_err(|error| match error {
            crate::c14n::C14nError::SharedExecution(cause) => {
                if self.failure.get().is_none() {
                    self.failure.set(Some(cause));
                }
                function::Error::ProcessingStopped
            }
            error => function::Error::Other {
                what: error.to_string(),
            },
        })
    }

    fn pop(&mut self) -> Option<(nodeset::Node<'d>, usize)> {
        self.frames.pop()
    }
}

impl<'a, K: Keys> IdRequests<'a, K> {
    fn new(
        values: impl IntoIterator<Item = &'a str>,
        execution: K::Execution,
    ) -> Result<Self, structured_asn1::memory::MemoryError> {
        let mut identifiers = K::index(execution);
        for value in values {
            K::admit(execution, value.len())?;
            for word in value.split(is_xpath_whitespace) {
                if !word.is_empty() {
                    identifiers.insert(Identifier(word), None)?;
                }
            }
        }
        Ok(Self { identifiers })
    }

    fn select(
        &mut self,
        value: &'a str,
        identity: (usize, usize, usize),
        execution: K::Execution,
    ) -> Result<IdMatch, structured_asn1::memory::MemoryError> {
        match self.identifiers.lookup(&Identifier(value), execution)? {
            None => Ok(IdMatch::Absent),
            Some(Some(previous)) if *previous == identity => Ok(IdMatch::Repeated),
            Some(Some(_)) => Ok(IdMatch::Ambiguous),
            Some(None) => {
                self.identifiers.insert(Identifier(value), Some(identity))?;
                Ok(IdMatch::First)
            }
        }
    }
}

struct IdFunction<'s, 'i, 'r, K: Keys, D: crate::xml::dom::storage::Storage> {
    work_budget: &'s XPathWorkBudget,
    document_scan_cost: usize,
    source: &'s Document<'i, D>,
    elements: &'s K::Index<(usize, usize, usize), NodeId>,
    execution: K::Execution,
    failure: &'s Cell<Option<structured_asn1::memory::MemoryError>>,
    registrations: &'r [crate::xml::IdAttributeRegistration],
}

impl<K: Keys, D: crate::xml::dom::storage::Storage> function::Function
    for IdFunction<'_, '_, '_, K, D>
{
    fn evaluate_borrowed<'c, 'd>(
        &self,
        context: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: &mut [Value<'d>],
    ) -> Result<Value<'d>, function::Error> {
        let mut args = function::Args::new(args);
        args.exactly(1)?;
        let argument = args.pop_value()?;
        use crate::c14n::scratch::{List as _, Scratch as _, TextBuilder as _};
        let scratch = K::scratch(self.execution);
        use sxd_xpath_no_unsafe::runtime::{Runtime as _, Set as _};
        let runtime = scratch.runtime(self.failure);
        let stop = |cause: structured_asn1::memory::MemoryError| {
            if self.failure.get().is_none() {
                self.failure.set(Some(cause));
            }
            function::Error::ProcessingStopped
        };
        let stop_storage = |error: crate::c14n::C14nError| {
            if let crate::c14n::C14nError::SharedExecution(cause) = error {
                stop(cause)
            } else {
                function::Error::Other {
                    what: error.to_string(),
                }
            }
        };
        let mut values = scratch.values();
        let scalar = match &argument {
            Value::Nodeset(nodes) => {
                // XPath 1.0 section 4.1 takes the union of the IDs in each
                // string-value: argument document order cannot change it.
                // https://www.w3.org/TR/1999/REC-xpath-19991116/#function-id
                let mut stack = IdTextStack {
                    frames: scratch.values(),
                    failure: self.failure,
                };
                for node in runtime.nodes(nodes)? {
                    let mut text = scratch.builder();
                    node.visit_string_value_with_stack(context, &mut stack, |chunk| {
                        text.append(chunk).map_err(stop_storage)?;
                        Ok(true)
                    })?;
                    values
                        .push(text.finish().map_err(stop_storage)?)
                        .map_err(stop_storage)?;
                }
                None
            }
            Value::Number(number) => {
                values
                    .push(
                        scratch
                            .formatted(format_args!("{}", NumberLexical(*number)))
                            .map_err(|error| match error {
                                TransformError::C14n(crate::c14n::C14nError::SharedExecution(
                                    cause,
                                )) => stop(cause),
                                error => function::Error::Other {
                                    what: error.to_string(),
                                },
                            })?,
                    )
                    .map_err(stop_storage)?;
                None
            }
            Value::String(text) => Some(text.as_str()),
            Value::AccountedString(text) => Some(text.as_str()),
            Value::ResultTreeFragment(_, text) => Some(text.as_str()),
            Value::Boolean(value) => Some(if *value { "true" } else { "false" }),
        };
        let mut requests = match scalar {
            Some(text) => IdRequests::<K>::new(std::iter::once(text), self.execution),
            None => IdRequests::<K>::new(values.iter().map(|text| &**text), self.execution),
        }
        .map_err(stop)?;

        // The custom id() implementation performs its own full-document scan in
        // addition to the XPath engine's work, so it must consume the same meter.
        self.work_budget.charge_function(self.document_scan_cost)?;

        let mut stack = scratch.values();
        stack
            .push(nodeset::Node::Root(context.node.document().root()))
            .map_err(stop_storage)?;
        let mut result = runtime.set();
        while let Some(node) = stack.pop() {
            // Indexed children borrow the evaluation document without creating
            // a fresh child vector for each element in the ID scan.
            for index in 0..node.children_len() {
                K::admit(self.execution, 1).map_err(stop)?;
                if let Some(child) = node.child_at(index) {
                    stack.push(child).map_err(stop_storage)?;
                }
            }
            let Some(element) = node.element() else {
                continue;
            };
            let source_id = self
                .elements
                .lookup(&element.identity_key(), self.execution)
                .map_err(|error| {
                    if self.failure.get().is_none() {
                        self.failure.set(Some(error));
                    }
                    function::Error::ProcessingStopped
                })?;
            let Some(source) = source_id.and_then(|id| self.source.get_node(*id)) else {
                continue;
            };
            let mut selected = false;
            for attribute in source.attributes() {
                K::admit(self.execution, 1).map_err(stop)?;
                // Match the URI resolver's local-name policy: WS-Security's
                // namespaced wsu:Id and XML's xml:id are ID attributes too.
                // XPath 1.0 section 4.1: ID type comes from the source XML
                // data model, not the temporary evaluator's untyped DOM.
                // https://www.w3.org/TR/1999/REC-xpath-19991116/#function-id
                let recognized = crate::xml::is_id_attribute(source, attribute, self.registrations);
                let value = attribute.value();
                if !recognized {
                    continue;
                }
                match requests
                    .select(value, element.identity_key(), self.execution)
                    .map_err(stop)?
                {
                    IdMatch::Absent | IdMatch::Repeated => {}
                    IdMatch::First => selected = true,
                    IdMatch::Ambiguous => {
                        return Err(function::Error::Static {
                            what: "id() matched a duplicate identifier",
                        });
                    }
                }
            }
            if selected {
                result.insert(context, element.into())?;
            }
        }
        Ok(Value::Nodeset(result.finish()))
    }
}

struct LangFunction<'s, K: Keys> {
    work_budget: &'s XPathWorkBudget,
    execution: K::Execution,
    failure: &'s Cell<Option<structured_asn1::memory::MemoryError>>,
}

impl<K: Keys> function::Function for LangFunction<'_, K> {
    fn evaluate_borrowed<'c, 'd>(
        &self,
        context: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: &mut [Value<'d>],
    ) -> Result<Value<'d>, function::Error> {
        let mut args = function::Args::new(args);
        args.exactly(1)?;
        let argument = args.pop_value()?;
        use sxd_xpath_no_unsafe::runtime::Runtime as _;
        let scratch = K::scratch(self.execution);
        let runtime = scratch.runtime(self.failure);
        let requested = runtime.value_text(context, &argument)?;
        let admit = |units| {
            K::admit(self.execution, units).map_err(|cause| {
                if self.failure.get().is_none() {
                    self.failure.set(Some(cause));
                }
                function::Error::ProcessingStopped
            })
        };
        let mut node = Some(runtime.clone_node(context, &context.node)?);
        while let Some(current) = node {
            admit(1)?;
            self.work_budget.charge_function(1)?;
            if let Some(element) = current.element() {
                for index in 0..element.attributes_len() {
                    admit(1)?;
                    let attribute = element
                        .attribute_at(index)
                        .expect("retained attribute slot");
                    let stored_name = attribute.name();
                    let name = sxd_document_no_unsafe::as_qname!(stored_name);
                    admit(
                        name.local_part()
                            .len()
                            .saturating_add(name.namespace_uri().map_or(0, str::len)),
                    )?;
                    if name.local_part() == "lang" && name.namespace_uri() == Some(XML_NS) {
                        let stored_value = attribute.value();
                        let language = sxd_document_no_unsafe::as_str!(stored_value);
                        admit(
                            language
                                .len()
                                .saturating_add(requested.len())
                                .saturating_mul(2),
                        )?;
                        // XPath 1.0 §4.3: match xml:lang case-insensitively,
                        // allowing a hyphen-delimited sublanguage suffix.
                        // https://www.w3.org/TR/1999/REC-xpath-19991116/#function-lang
                        let matches = language.eq_ignore_ascii_case(&requested)
                            || (language.as_bytes().get(requested.len()) == Some(&b'-')
                                && language
                                    .get(..requested.len())
                                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(&requested)));
                        return Ok(Value::Boolean(matches));
                    }
                }
            }
            node = current.parent();
        }
        Ok(Value::Boolean(false))
    }
}

fn here_path<D: crate::xml::dom::storage::Storage, S: crate::c14n::scratch::Scratch>(
    document: &Document<'_, D>,
    here_node: Option<NodeId>,
    scratch: &S,
) -> Result<Option<S::Values<usize>>, TransformError> {
    let Some(mut node) = here_node.and_then(|id| document.get_node(id)) else {
        return Ok(None);
    };
    let mut path = scratch.values();
    while let Some(parent) = node.parent() {
        scratch.charge(parent.children().len())?;
        let index = parent
            .children()
            .position(|child| child == node)
            .ok_or(TransformError::CrossDocumentNodeSetInput)?;
        crate::c14n::scratch::List::push(&mut path, index)?;
        node = parent;
    }
    scratch.charge(path.len())?;
    path.reverse();
    Ok(Some(path))
}

#[derive(Clone, Copy)]
pub(super) enum XPathDocumentRelation {
    SameDocument,
    CrossDocument,
}

impl XPathDocumentRelation {
    pub(super) fn between<
        L: crate::xml::dom::storage::Storage,
        R: crate::xml::dom::storage::Storage,
    >(
        left: &Document<'_, L>,
        right: &Document<'_, R>,
    ) -> Self {
        if std::ptr::eq(
            std::ptr::from_ref(left).cast::<()>(),
            std::ptr::from_ref(right).cast::<()>(),
        ) {
            Self::SameDocument
        } else {
            Self::CrossDocument
        }
    }
}

#[derive(Clone, Copy)]
enum XPathEvaluationMode {
    XmlDsigPerNodeFilter,
    Filter2NodeSetSelection,
}

#[derive(Clone, Copy)]
pub(super) struct XPathRequestContext<'r> {
    here_semantics: XPathHereSemantics,
    registrations: &'r [crate::xml::IdAttributeRegistration],
}

impl<'r> XPathRequestContext<'r> {
    pub(super) fn new(
        here_semantics: XPathHereSemantics,
        registrations: &'r [crate::xml::IdAttributeRegistration],
    ) -> Self {
        Self {
            here_semantics,
            registrations,
        }
    }
}

impl From<XPathHereSemantics> for XPathRequestContext<'_> {
    fn from(semantics: XPathHereSemantics) -> Self {
        Self::new(semantics, &[])
    }
}

fn evaluate_expression<'a, 'r, K: Keys, D: crate::xml::dom::storage::Storage>(
    input: &Projection<'a, K, D>,
    expression: &impl super::transforms::ExpressionParameter,
    mode: XPathEvaluationMode,
    request: impl Into<XPathRequestContext<'r>>,
    document_relation: XPathDocumentRelation,
    work_budget: &XPathWorkBudget,
    materialization_budget: &NodeSetMaterializationBudget,
) -> Result<Projection<'a, K, D>, TransformError> {
    use crate::c14n::scratch::{List as _, Scratch as _};
    let request = request.into();
    let expression_bytes = expression.expression().len();
    if expression_bytes > work_budget.limits.expression_bytes {
        return Err(transform_resource_limit(
            crate::policy::resource_name::XPATH_EXPRESSION_BYTES,
            work_budget.limits.expression_bytes,
            expression_bytes,
        ));
    }
    K::admit(input.execution(), expression_bytes).map_err(crate::c14n::C14nError::from)?;
    let expression_complexity = xpath_expression_complexity(expression.expression());
    if expression_complexity > work_budget.limits.expression_complexity {
        return Err(transform_resource_limit(
            crate::policy::resource_name::XPATH_EXPRESSION_COMPLEXITY,
            work_budget.limits.expression_complexity,
            expression_complexity,
        ));
    }
    let scratch = K::scratch(input.execution());
    let normalized = source::normalize(expression.expression(), &scratch)?;
    let xpath = scratch.compile(normalized.view()?)?;

    let document = input.document();
    let document_size = input.measure_document(materialization_budget)?;
    // The node-set preflight bounds map cardinality and inherited namespace
    // amplification. This separate preflight accounts for every string copied
    // by Mirror::build before allocating the secondary DOM.
    let mirror_bytes = Mirror::<K, D>::projected_string_bytes(document)?;
    work_budget.charge_mirror_bytes(mirror_bytes)?;
    work_budget.charge(document_size)?;
    let package = scratch.package()?;
    let target = package.as_document();
    let mirror = Mirror::<K, D>::build_in(document, target, input.execution())?;
    let shared_failure = Cell::new(None);
    let admit_work = |units| {
        if shared_failure.get().is_some() {
            return Err(function::Error::ProcessingStopped);
        }
        if let Err(cause) = K::admit(input.execution(), units) {
            shared_failure.set(Some(cause));
            return Err(function::Error::ProcessingStopped);
        }
        Ok(())
    };
    let mut bindings = K::bindings(input.execution());
    for (prefix, uri) in expression.namespaces() {
        bindings.bind(prefix, uri)?;
    }
    // The XML namespace binding is implicit and roxmltree therefore does not
    // expose it through element namespace declarations. Enforce it at the
    // evaluation boundary for both parsed and programmatic expressions.
    bindings.bind("xml", XML_NS)?;
    let resolve_namespace = NamespaceResolver::<K> {
        bindings: &bindings,
        execution: input.execution(),
        failure: &shared_failure,
        source: std::marker::PhantomData,
    };
    let here_function = HereFunction::<_, K> {
        execution: input.execution(),
        failure: &shared_failure,
        context: match document_relation {
            XPathDocumentRelation::CrossDocument => HereContext::CrossDocument,
            XPathDocumentRelation::SameDocument => here_path(
                document,
                expression.here_context_node(request.here_semantics),
                &scratch,
            )?
            .map_or(HereContext::MissingParameterNode, HereContext::Path),
        },
    };
    let id_function = IdFunction::<K, D> {
        work_budget,
        document_scan_cost: document_size,
        source: document,
        elements: &mirror.elements,
        execution: input.execution(),
        failure: &shared_failure,
        registrations: request.registrations,
    };
    let lang_function = LangFunction::<K> {
        work_budget,
        execution: input.execution(),
        failure: &shared_failure,
    };
    let functions: [(QName<'_>, &dyn function::Function); 3] = [
        (QName::new("here"), &here_function),
        (QName::new("id"), &id_function),
        (QName::new("lang"), &lang_function),
    ];
    let mut context = sxd_xpath_no_unsafe::context::ScopedContext::new();
    if <K::Scratch as crate::c14n::scratch::Scratch>::ACCOUNTED {
        context.set_work_admission(&admit_work);
    }
    context.set_namespace_lookup(&resolve_namespace);
    context.set_function_view(&functions);

    let evaluation_work =
        xpath_evaluation_work(expression.expression(), document_size, mode, &scratch)?;
    // One more full pass over the source, paid like the estimate above.
    scratch.charge(expression_bytes)?;
    let string_scans = xpath_string_scan_count(expression.expression()).max(1);

    if matches!(mode, XPathEvaluationMode::XmlDsigPerNodeFilter) {
        // XMLDSig 1.1 section 6.6.3 requires a fresh context for every input
        // node with position=1 and size=1. Do not evaluate these nodes as one
        // XPath sequence: position() and last() are normatively constant here.
        // https://www.w3.org/TR/xmldsig-core/#sec-XPath
        let all_nodes_xpath = scratch.compile(ALL_XPATH_NODES)?;
        work_budget.charge(document_size)?;
        let all_nodes = all_nodes_xpath
            .evaluate(&context, target.root(), &shared_failure)
            .map_err(|error| work_budget.map_evaluation_error(error, &shared_failure, &scratch))?;
        let Value::Nodeset(all_nodes) = all_nodes else {
            unreachable!("the fixed all-nodes XPath expression returns a node-set");
        };
        let ordering_context =
            sxd_xpath_no_unsafe::context::Evaluation::new(&context, target.root().into());
        let mut ordered_nodes = scratch
            .order_nodes(&all_nodes, &ordering_context, &shared_failure)
            .map_err(|error| work_budget.map_evaluation_error(error, &shared_failure, &scratch))?;
        let mut kept = 0;
        for index in 0..ordered_nodes.len() {
            let vacant = nodeset::Node::Root(ordered_nodes[index].document().root());
            let node = std::mem::replace(&mut ordered_nodes[index], vacant);
            if mirror.input_contains(document, input, &node)? {
                ordered_nodes[kept] = node;
                kept += 1;
            }
        }
        while ordered_nodes.len() > kept {
            ordered_nodes.pop();
        }
        work_budget.validate_context_evaluations(ordered_nodes.len())?;
        // SXD has no interrupt hook and XPath coercions can materialize or scan
        // any mirrored string. Charge the complete source string volume for
        // every context before entering the evaluator; syntax-based discounts
        // would leave alternate coercion paths able to bypass this ceiling.
        work_budget.charge_string_work(mirror_bytes, ordered_nodes.len(), string_scans)?;
        let mut selected = input.empty_like();
        for node in &*ordered_nodes {
            // SXD exposes no interrupt hook. Charge nested predicate scans
            // before execution so they cannot hide cubic work inside one call.
            work_budget.charge(evaluation_work)?;
            K::admit(input.execution(), 1)?;
            let include = xpath
                .evaluate(&context, node.clone(), &shared_failure)
                .map_err(|error| {
                    work_budget.map_evaluation_error(error, &shared_failure, &scratch)
                })?
                .into_boolean();
            if include {
                mirror.project_exact_node(document, &mut selected, node, materialization_budget)?;
            }
        }
        return Ok(selected);
    }

    work_budget.charge(evaluation_work)?;
    work_budget.charge_string_work(mirror_bytes, 1, string_scans)?;
    let value = xpath
        .evaluate(&context, target.root(), &shared_failure)
        .map_err(|error| work_budget.map_evaluation_error(error, &shared_failure, &scratch))?;
    let Value::Nodeset(selected) = value else {
        return Err(scratch.diagnostic(format_args!(
            "XPath Filter 2.0 expression must return a node-set"
        )));
    };
    mirror.project_expanded(document, input, selected, materialization_budget)
}

#[cfg(test)]
pub(super) fn apply_xpath_filter<'a>(
    input: NodeSet<'a>,
    expression: &XPathExpression,
) -> Result<NodeSet<'a>, TransformError> {
    apply_xpath_filter_with_semantics(
        input,
        expression,
        XPathHereSemantics::default(),
        XPathDocumentRelation::SameDocument,
        &XPathWorkBudget::default(),
    )
}

#[cfg(test)]
pub(super) fn apply_xpath_filter_with_semantics<'a>(
    input: NodeSet<'a>,
    expression: &XPathExpression,
    here_semantics: XPathHereSemantics,
    document_relation: XPathDocumentRelation,
    work_budget: &XPathWorkBudget,
) -> Result<NodeSet<'a>, TransformError> {
    apply_xpath_filter_with_semantics_and_budget(
        input,
        expression,
        here_semantics,
        document_relation,
        work_budget,
        &NodeFilterWorkBudget::default(),
        &NodeSetMaterializationBudget::default(),
    )
}

#[cfg(test)]
pub(super) fn apply_xpath_filter_with_semantics_and_budget<'a, 'r>(
    input: NodeSet<'a>,
    expression: &XPathExpression,
    request: impl Into<XPathRequestContext<'r>>,
    document_relation: XPathDocumentRelation,
    work_budget: &XPathWorkBudget,
    node_filter_budget: &NodeFilterWorkBudget,
    materialization_budget: &NodeSetMaterializationBudget,
) -> Result<NodeSet<'a>, TransformError> {
    apply_xpath_projection_with_budget(
        input.projection,
        expression,
        request,
        document_relation,
        work_budget,
        node_filter_budget,
        materialization_budget,
    )
    .map(|projection| NodeSet { projection })
}

pub(super) fn apply_xpath_projection_with_budget<
    'a,
    'r,
    K: Keys,
    D: crate::xml::dom::storage::Storage,
>(
    mut input: Projection<'a, K, D>,
    expression: &impl super::transforms::ExpressionParameter,
    request: impl Into<XPathRequestContext<'r>>,
    document_relation: XPathDocumentRelation,
    work_budget: &XPathWorkBudget,
    node_filter_budget: &NodeFilterWorkBudget,
    materialization_budget: &NodeSetMaterializationBudget,
) -> Result<Projection<'a, K, D>, TransformError> {
    let selected = evaluate_expression(
        &input,
        expression,
        XPathEvaluationMode::XmlDsigPerNodeFilter,
        request,
        document_relation,
        work_budget,
        materialization_budget,
    )?;
    node_filter_budget.charge(input.len())?;
    input.intersect(&selected)?;
    Ok(input)
}

#[cfg(test)]
pub(super) fn apply_xpath_filter2<'a>(
    input: NodeSet<'a>,
    filters: &[XPathFilter],
) -> Result<NodeSet<'a>, TransformError> {
    apply_xpath_filter2_with_semantics(
        input,
        filters,
        XPathHereSemantics::default(),
        XPathDocumentRelation::SameDocument,
        &XPathWorkBudget::default(),
    )
}

#[cfg(test)]
pub(super) fn apply_xpath_filter2_with_semantics<'a>(
    input: NodeSet<'a>,
    filters: &[XPathFilter],
    here_semantics: XPathHereSemantics,
    document_relation: XPathDocumentRelation,
    work_budget: &XPathWorkBudget,
) -> Result<NodeSet<'a>, TransformError> {
    apply_xpath_filter2_with_semantics_and_budget(
        input,
        filters,
        here_semantics,
        document_relation,
        work_budget,
        &NodeFilterWorkBudget::default(),
        &NodeSetMaterializationBudget::default(),
    )
}

#[cfg(test)]
pub(super) fn apply_xpath_filter2_with_semantics_and_budget<'a, 'r>(
    input: NodeSet<'a>,
    filters: &[XPathFilter],
    request: impl Into<XPathRequestContext<'r>>,
    document_relation: XPathDocumentRelation,
    work_budget: &XPathWorkBudget,
    node_filter_budget: &NodeFilterWorkBudget,
    materialization_budget: &NodeSetMaterializationBudget,
) -> Result<NodeSet<'a>, TransformError> {
    apply_xpath_projection2_with_budget(
        input.projection,
        filters,
        request,
        document_relation,
        work_budget,
        node_filter_budget,
        materialization_budget,
    )
    .map(|projection| NodeSet { projection })
}

pub(super) fn apply_xpath_projection2_with_budget<
    'a,
    'r,
    K: Keys,
    D: crate::xml::dom::storage::Storage,
>(
    input: Projection<'a, K, D>,
    filters: &[impl super::transforms::FilterParameter],
    request: impl Into<XPathRequestContext<'r>>,
    document_relation: XPathDocumentRelation,
    work_budget: &XPathWorkBudget,
    node_filter_budget: &NodeFilterWorkBudget,
    materialization_budget: &NodeSetMaterializationBudget,
) -> Result<Projection<'a, K, D>, TransformError> {
    let request = request.into();
    if filters.is_empty() || filters.len() > work_budget.limits.filters {
        if filters.is_empty() {
            return Err(TransformError::XPath(
                "XPath Filter 2.0 requires at least one expression".into(),
            ));
        }
        return Err(transform_resource_limit(
            crate::policy::resource_name::XPATH_FILTERS,
            work_budget.limits.filters,
            filters.len(),
        ));
    }
    let mut result = input.entire_document_like(materialization_budget)?;
    for filter in filters {
        let selected = evaluate_expression(
            &input,
            filter.xpath(),
            XPathEvaluationMode::Filter2NodeSetSelection,
            request,
            document_relation,
            work_budget,
            materialization_budget,
        )?;
        match filter.operation() {
            XPathFilterOperation::Intersect => {
                node_filter_budget.charge(result.len())?;
                result.intersect(&selected)?;
            }
            XPathFilterOperation::Subtract => {
                node_filter_budget.charge(result.len())?;
                result.subtract(&selected)?;
            }
            XPathFilterOperation::Union => {
                node_filter_budget.charge(selected.len())?;
                result.union(&selected, materialization_budget)?;
            }
        }
    }
    node_filter_budget.charge(result.len())?;
    result.intersect(&input)?;
    Ok(result)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests use fixed XML and XPath fixtures")]
mod tests {
    use super::*;
    use crate::c14n::{C14nAlgorithm, C14nMode, canonicalize_with_visibility};
    use crate::xml::dom::Document;
    use crate::xmldsig::TransformData;

    #[test]
    fn mirror_default_namespace_undeclaration_shadows_ancestors() {
        // XPath 1.0 §5.4: xmlns="" hides the inherited default binding;
        // it does not expose an empty namespace node or resurrect the parent.
        let source = Document::parse("<root xmlns='urn:parent'><child xmlns=''/></root>").unwrap();
        let package = Package::new();
        let target = package.as_document();
        let _mirror = Mirror::build(&source, target);
        let root = target.root().child_at(0).unwrap().element().unwrap();
        let child = root.child_at(0).unwrap().element().unwrap();
        let context = sxd_xpath_no_unsafe::Context::new();
        let count = Factory::new().build("count(namespace::*)").unwrap();
        assert_eq!(count.evaluate(&context, root).unwrap(), Value::Number(2.0));
        assert_eq!(count.evaluate(&context, child).unwrap(), Value::Number(1.0));
    }

    #[test]
    fn current_mirror_and_evaluator_match_native_namespace_and_text_semantics() {
        // One mirror walk and one evaluator kernel must preserve identities,
        // names, default undeclarations, shadowing, attributes and mixed text.
        use super::super::types::projection::PaidKeys;
        use std::sync::Arc;
        use structured_asn1::memory::{Memory, MemoryAccount};
        for xml in [
            "<root xmlns='urn:parent'><child xmlns=''>a<b/>b</child></root>",
            "<?p v?><root xmlns:p='urn:one' p:a='v'><p:child xmlns:p='urn:two'>x<!--c-->y</p:child></root>",
        ] {
            let source = Document::parse(xml).unwrap();
            let native_package = Package::new();
            let native_target = native_package.as_document();
            let _native_mirror = Mirror::build(&source, native_target);
            let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 22, 1 << 24)));
            let current_package = Package::try_current(&memory).unwrap();
            let current_target = current_package.as_document();
            let current_mirror =
                Mirror::<PaidKeys<'_, Memory>>::build_in(&source, current_target, &memory).unwrap();
            let failure = Cell::new(None);
            let admit = |units| {
                memory.charge_work(units as u64).map_err(|cause| {
                    failure.set(Some(cause));
                    function::Error::ProcessingStopped
                })
            };
            let native_context = sxd_xpath_no_unsafe::Context::new();
            let mut current_context = sxd_xpath_no_unsafe::Context::new();
            current_context.set_work_admission(&admit);
            for query in [
                "count(//node())",
                "count(//@*)",
                "count(//namespace::*)",
                "count(/*/*/namespace::*)",
                "string(/*/*)",
                "name(/*/*)",
                "namespace-uri(/*/*)",
                "normalize-space(string(/*))",
                "count((//* | //@* | //namespace::*)[position() > 1])",
            ] {
                let native = Factory::new()
                    .build(query)
                    .unwrap()
                    .evaluate(&native_context, native_target.root())
                    .unwrap();
                let program = sxd_xpath_no_unsafe::arena::Program::parse(query, &memory).unwrap();
                let current = program
                    .evaluate_in(
                        &current_context,
                        current_target.root(),
                        sxd_xpath_no_unsafe::runtime::Accounted {
                            work: &memory,
                            failure: &failure,
                        },
                    )
                    .unwrap();
                assert_eq!(current, native, "{query} on {xml}");
                assert_eq!(failure.get(), None);
            }
            drop(current_mirror);
            assert!(memory.used() > 0, "actual arena storage remains retained");
            drop(current_package);
            assert_eq!(memory.used(), 0);
        }
    }

    #[test]
    fn lang_reads_current_arena_without_an_attribute_snapshot() {
        // The extension must use borrowed/indexed attributes just like axes:
        // current arenas deliberately have no native snapshot allocation path.
        use function::Function as _;
        use std::sync::Arc;
        use structured_asn1::memory::{Memory, MemoryAccount};
        let memory = Memory::new(Arc::new(MemoryAccount::new(65536, 65536)));
        let package = Package::try_current(&memory).unwrap();
        let document = package.as_document();
        let builder = dom::current::Builder::new(document, &memory);
        let root = builder.element(QName::new("root")).unwrap();
        builder.append_root(root.into()).unwrap();
        builder
            .attribute(
                root,
                QName::with_namespace_uri(Some(XML_NS), "lang"),
                "en-GB",
            )
            .unwrap();
        let context = sxd_xpath_no_unsafe::Context::new();
        let evaluation = sxd_xpath_no_unsafe::context::Evaluation::new(&context, root.into());
        let budget = XPathWorkBudget::default();
        let failure = Cell::new(None);
        let function = LangFunction::<super::super::types::projection::PaidKeys<'_, Memory>> {
            work_budget: &budget,
            execution: &memory,
            failure: &failure,
        };
        assert_eq!(
            function.evaluate_borrowed(&evaluation, &mut [Value::from("en")]),
            Ok(Value::Boolean(true))
        );
        assert_eq!(
            function.evaluate_borrowed(&evaluation, &mut [Value::from("fr")]),
            Ok(Value::Boolean(false))
        );
    }

    #[test]
    fn current_id_requests_refuse_unfunded_storage_and_preserve_duplicates() {
        // Identifier state must own its actual current-query map. Repeated
        // requested words and two ID attributes on one element are not an
        // ambiguity, while the same ID on distinct elements is an error.
        use super::super::types::projection::PaidKeys;
        use std::sync::Arc;
        use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
        let denied = Memory::new(Arc::new(MemoryAccount::new(0, 4096)));
        assert!(matches!(
            IdRequests::<PaidKeys<'_, Memory>>::new(["a a b"], &denied),
            Err(MemoryError::LimitExceeded)
        ));
        assert_eq!(denied.used(), 0);
        let exhausted = Memory::new(Arc::new(MemoryAccount::new(4096, 0)));
        assert!(matches!(
            IdRequests::<PaidKeys<'_, Memory>>::new(["a"], &exhausted),
            Err(MemoryError::WorkExceeded)
        ));
        let memory = Memory::new(Arc::new(MemoryAccount::new(4096, 4096)));
        let mut requests = IdRequests::<PaidKeys<'_, Memory>>::new(["a a b"], &memory).unwrap();
        assert!(memory.used() > 0);
        assert_eq!(
            requests.select("a", (1, 2, 3), &memory).unwrap(),
            IdMatch::First
        );
        assert_eq!(
            requests.select("a", (1, 2, 3), &memory).unwrap(),
            IdMatch::Repeated
        );
        assert_eq!(
            requests.select("a", (1, 2, 4), &memory).unwrap(),
            IdMatch::Ambiguous
        );
        assert_eq!(
            requests.select("missing", (1, 2, 4), &memory).unwrap(),
            IdMatch::Absent
        );
        drop(requests);
        assert_eq!(memory.used(), 0);
    }

    #[test]
    fn current_id_text_walk_refuses_actual_stack_before_descendant_text() {
        // Isolate the shared text-walk kernel from fixture creation and AST
        // construction: even a retained DOM cannot lend its producer credit.
        use crate::c14n::scratch::Scratch as _;
        use std::sync::Arc;
        use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
        let package = Package::new();
        let document = package.as_document();
        let root = document.create_element("root");
        let child = document.create_element("child");
        root.append_child(child);
        child.append_child(document.create_text("must not be copied"));
        document.root().append_child(root);
        let context = sxd_xpath_no_unsafe::Context::new();
        let evaluation =
            sxd_xpath_no_unsafe::context::Evaluation::new(&context, document.root().into());
        for (bytes, units, expected) in [
            (0, 4096, MemoryError::LimitExceeded),
            (4096, 0, MemoryError::WorkExceeded),
        ] {
            let work = Memory::new(Arc::new(MemoryAccount::new(bytes, units)));
            let failure = Cell::new(None);
            let mut stack = IdTextStack {
                frames: crate::c14n::scratch::Accounted(&work).values(),
                failure: &failure,
            };
            let result = nodeset::Node::Root(document.root()).visit_string_value_with_stack(
                &evaluation,
                &mut stack,
                |_| panic!("the stack must be funded before visiting text"),
            );
            assert!(matches!(result, Err(function::Error::ProcessingStopped)));
            assert_eq!(failure.get(), Some(expected));
            drop(stack);
            assert_eq!(work.used(), 0);
        }
    }

    #[test]
    fn current_id_number_format_uses_shared_xpath_lexical_rules() {
        // Scalar ID arguments must not allocate a native conversion buffer,
        // nor use a different spelling for signed zero, NaN or infinity.
        use std::sync::Arc;
        use structured_asn1::memory::{Memory, MemoryAccount};
        let memory = Memory::new(Arc::new(MemoryAccount::new(4096, 65536)));
        for number in [
            0.0,
            -0.0,
            1.5,
            -42.0,
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::MAX,
            f64::MIN_POSITIVE,
            f64::from_bits(1),
        ] {
            let text = crate::c14n::scratch::Accounted(&memory)
                .formatted(format_args!("{}", NumberLexical(number)))
                .expect("funded number formatting");
            assert_eq!(&*text, Value::Number(number).string());
            assert!(memory.used() >= text.len());
            drop(text);
            assert_eq!(memory.used(), 0);
        }
    }

    #[test]
    fn here_path_owns_current_capacity_and_admits_source_scan() {
        // The cached path is a real current-query vector. Neither zero memory
        // nor exhausted current work may fall back to an ordinary Vec.
        use std::sync::Arc;
        use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
        let document = Document::parse("<root><parent><here/></parent></root>").unwrap();
        let here = document
            .descendants()
            .find(|node| node.tag_name().name() == "here")
            .unwrap()
            .id();
        for (bytes, units, expected) in [
            (0, 4096, MemoryError::LimitExceeded),
            (4096, 0, MemoryError::WorkExceeded),
        ] {
            let memory = Memory::new(Arc::new(MemoryAccount::new(bytes, units)));
            let result = here_path(
                &document,
                Some(here),
                &crate::c14n::scratch::Accounted(&memory),
            );
            assert!(
                matches!(result, Err(TransformError::C14n(crate::c14n::C14nError::SharedExecution(cause))) if cause == expected)
            );
            assert_eq!(memory.used(), 0);
        }
        let memory = Memory::new(Arc::new(MemoryAccount::new(4096, 4096)));
        let path = here_path(
            &document,
            Some(here),
            &crate::c14n::scratch::Accounted(&memory),
        )
        .unwrap()
        .unwrap();
        assert_eq!(&*path, &[0, 0, 0]);
        assert_eq!(
            memory.used(),
            path.capacity() * std::mem::size_of::<usize>()
        );
        drop(path);
        assert_eq!(memory.used(), 0);
    }

    #[test]
    fn current_xpath_diagnostic_retains_its_actual_allocation() {
        // A malformed expression releases its partial arena, then constructs
        // its diagnostic under the same query. Keeping the error keeps only
        // the admitted diagnostic capacity alive.
        use std::sync::Arc;
        use structured_asn1::memory::{Memory, MemoryAccount};
        let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 20)));
        let storage = crate::c14n::scratch::Accounted(&memory);
        let error = storage.compile("f(1,)").err().unwrap();
        let TransformError::AccountedXPath(message) = &error else {
            panic!("{error}")
        };
        assert_eq!(message.as_str(), "function argument is missing");
        assert_eq!(memory.used(), message.capacity());
        drop(error);
        assert_eq!(memory.used(), 0);
    }

    #[test]
    fn current_xpath_refusal_does_not_allocate_a_diagnostic() {
        // Resource refusal remains the original typed terminal cause, even
        // when the malformed source would later require an error message.
        use std::sync::Arc;
        use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
        let memory = Memory::new(Arc::new(MemoryAccount::new(0, 1 << 20)));
        let error = crate::c14n::scratch::Accounted(&memory)
            .compile("f(1,)")
            .err()
            .unwrap();
        assert!(matches!(
            error,
            TransformError::C14n(crate::c14n::C14nError::SharedExecution(
                MemoryError::LimitExceeded
            ))
        ));
        assert_eq!(memory.used(), 0);
    }

    fn canonicalize(nodes: &NodeSet<'_>) -> String {
        let mut output = Vec::new();
        canonicalize_with_visibility(
            nodes.document(),
            Some(nodes),
            &C14nAlgorithm::new(C14nMode::Inclusive1_0, false),
            &mut output,
        )
        .unwrap();
        String::from_utf8(output).unwrap()
    }

    fn assert_resource_limit(error: &TransformError, expected_resource: &'static str) {
        assert!(
            matches!(
                error,
                TransformError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                    resource,
                    maximum,
                    actual,
                }) if *resource == expected_resource && actual > maximum
            ),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn xpath_filters_attributes_as_independent_nodes() {
        // The element remains visible while one attribute is removed from its
        // canonical form; expanding every selected element would regress this.
        let doc = Document::parse(r#"<root keep="yes" drop="no">text</root>"#).unwrap();
        let input = NodeSet::entire_document_with_comments(&doc).unwrap();
        let result = apply_xpath_filter(input, &XPathExpression::new("name() != 'drop'")).unwrap();

        assert_eq!(canonicalize(&result), r#"<root keep="yes">text</root>"#);
    }

    #[test]
    fn xpath_filters_namespace_nodes_independently() {
        // Namespace nodes have their own XPath identity and may be excluded
        // without hiding their owner element or ordinary attributes.
        let doc = Document::parse(
            r#"<root xmlns:keep="urn:keep" xmlns:drop="urn:drop" keep:value="1"/>"#,
        )
        .unwrap();
        let input = NodeSet::entire_document_with_comments(&doc).unwrap();
        let result = apply_xpath_filter(input, &XPathExpression::new("name() != 'drop'")).unwrap();

        let output = canonicalize(&result);
        assert!(output.contains(r#"xmlns:keep="urn:keep""#));
        assert!(!output.contains(r#"xmlns:drop="urn:drop""#));
    }

    #[test]
    fn xpath_filter_sets_position_and_size_to_one_for_each_node() {
        // XMLDSig visits every input node independently with both context
        // position and context size set to one.
        let doc = Document::parse("<root><first/><second/></root>").unwrap();
        let input = NodeSet::entire_document_without_comments(&doc).unwrap();
        let result = apply_xpath_filter(
            input,
            &XPathExpression::new("position() = 1 and last() = 1"),
        )
        .unwrap();

        assert!(result.contains(doc.root_element()));
        assert!(result.contains(doc.root_element().first_element_child().unwrap()));
        assert!(result.contains(doc.root_element().last_element_child().unwrap()));
    }

    #[test]
    fn xpath_filter_rejects_oversized_per_node_evaluation() {
        // XMLDSig re-evaluates ordinary XPath for every node, so allowing an
        // expression that scans a larger document would permit quadratic work.
        let xml = format!(
            "<root>{}</root>",
            "<item/>".repeat(MAX_XPATH_CONTEXT_EVALUATIONS + 1)
        );
        let doc = Document::parse(&xml).unwrap();
        let error = apply_xpath_filter(
            NodeSet::entire_document_without_comments(&doc).unwrap(),
            &XPathExpression::new("count(//*) >= 0"),
        )
        .err()
        .expect("oversized per-node XPath evaluation must fail before execution");

        assert_resource_limit(&error, "XPath context evaluations");
    }

    #[test]
    fn xpath_filter_caps_only_input_node_set_contexts() {
        // Same-document references may select a small ID subtree inside a much
        // larger document. Nodes outside that input are not XPath contexts.
        let xml = format!(
            "<root><target Id=\"selected\"><child/></target>{}</root>",
            "<outside/>".repeat(MAX_XPATH_CONTEXT_EVALUATIONS + 1)
        );
        let doc = Document::parse(&xml).unwrap();
        let target = doc
            .descendants()
            .find(|node| node.attribute("Id") == Some("selected"))
            .unwrap();
        let input = NodeSet::subtree(target).unwrap();
        let result = apply_xpath_filter(input, &XPathExpression::new("true()"))
            .expect("small input subtree must not inherit the document context count");

        assert!(result.contains(target));
        assert!(result.contains(target.first_element_child().unwrap()));
    }

    #[test]
    fn xpath_rejects_oversized_source_before_building_mirror() {
        // A small same-document reference must not permit XPath to duplicate an
        // unrelated source document that exceeds the selected node-set budget.
        let xml = format!(
            "<root><target Id=\"selected\"><child/></target>{}</root>",
            "<outside/>".repeat(129)
        );
        let document = Document::parse(&xml).expect("fixed oversized fixture must parse");
        let target = document
            .descendants()
            .find(|node| node.attribute("Id") == Some("selected"))
            .expect("fixed fixture contains selected subtree");

        let materialization_budget = NodeSetMaterializationBudget::with_limits(128, 1_024, 1_024);
        let error = apply_xpath_filter_with_semantics_and_budget(
            NodeSet::subtree(target).expect("selected subtree fits the node-set budget"),
            &XPathExpression::new("true()"),
            XPathHereSemantics::default(),
            XPathDocumentRelation::SameDocument,
            &XPathWorkBudget::default(),
            &NodeFilterWorkBudget::default(),
            &materialization_budget,
        )
        .err()
        .expect("XPath must reject the source before allocating an oversized mirror");

        assert!(matches!(
            error,
            TransformError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::NODE_SET_ENTRIES,
                ..
            })
        ));
    }

    #[test]
    fn xpath_rejects_oversized_source_values_before_building_mirror() {
        // A same-document ID reference can select only a tiny subtree while
        // XPath still mirrors the complete source. Both text and attribute
        // values must be rejected before SXD copies their untrusted bytes.
        let oversized_value = "x".repeat(8 * 1024 * 1024 + 1);
        let fixtures = [
            format!("<root><target Id=\"selected\"/><outside>{oversized_value}</outside></root>"),
            format!("<root><target Id=\"selected\"/><outside value=\"{oversized_value}\"/></root>"),
        ];

        for xml in fixtures {
            let document = Document::parse(&xml).expect("fixed oversized fixture must parse");
            let target = document
                .descendants()
                .find(|node| node.attribute("Id") == Some("selected"))
                .expect("fixed fixture contains the selected subtree");

            let error = apply_xpath_filter(
                NodeSet::subtree(target).expect("selected subtree fits the node-set budget"),
                &XPathExpression::new("true()"),
            )
            .err()
            .expect("XPath must reject source values before building the mirror");

            assert!(matches!(
                error,
                TransformError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XPATH_MIRROR_STRING_BYTES,
                    ..
                })
            ));
        }
    }

    #[test]
    fn xpath_rejects_invalid_expression_before_mirror_preflight() {
        // Programmatic expressions must fail their cheap policy gate before
        // document mirroring can consume or reject the operation's work budget.
        let document = Document::parse("<root/>").unwrap();
        let input = NodeSet::entire_document_without_comments(&document).unwrap();
        let resources = crate::policy::ResourcePolicy {
            max_xpath_expression_bytes: 1,
            max_xpath_mirror_string_bytes: 0,
            ..crate::policy::ResourcePolicy::default()
        };
        let budget = XPathWorkBudget::with_limits(&resources);

        let error = apply_xpath_filter_with_semantics(
            input,
            &XPathExpression::new("true()"),
            XPathHereSemantics::default(),
            XPathDocumentRelation::SameDocument,
            &budget,
        )
        .err()
        .expect("expression policy must reject before mirror preflight");

        assert_resource_limit(&error, "XPath expression bytes");
    }

    #[test]
    fn xpath_preflights_policy_node_set_limits_before_mirror_allocation() {
        // A low compiled node-set limit must win before the mirror string
        // budget, proving that policy-aware preflight runs before SXD allocates.
        let fixtures = [
            (
                "<root><child/></root>",
                1,
                usize::MAX,
                crate::policy::resource_name::NODE_SET_ENTRIES,
            ),
            (
                "<root attribute=\"value\"/>",
                usize::MAX,
                0,
                crate::policy::resource_name::NODE_SET_OWNED_STRING_BYTES,
            ),
        ];

        for (xml, max_entries, max_owned_bytes, expected_resource) in fixtures {
            let document = Document::parse(xml).expect("fixed XPath fixture must parse");
            let input = NodeSet::entire_document_without_comments(&document)
                .expect("fixture fits the default node-set ceiling");
            let resources = crate::policy::ResourcePolicy {
                max_xpath_mirror_string_bytes: 0,
                ..crate::policy::ResourcePolicy::default()
            };
            let work_budget = XPathWorkBudget::with_limits(&resources);
            let materialization_budget =
                NodeSetMaterializationBudget::with_limits(max_entries, max_owned_bytes, usize::MAX);

            let error = match evaluate_expression(
                &input.projection,
                &XPathExpression::new("true()"),
                XPathEvaluationMode::Filter2NodeSetSelection,
                XPathHereSemantics::default(),
                XPathDocumentRelation::SameDocument,
                &work_budget,
                &materialization_budget,
            ) {
                Ok(_) => panic!("node-set policy must reject the source before mirror allocation"),
                Err(error) => error,
            };

            assert!(matches!(
                error,
                TransformError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                    resource,
                    ..
                }) if resource == expected_resource
            ));
        }
    }

    fn built_mirror_string_bytes(mirror: &Mirror<'_, '_>) -> usize {
        let mut bytes = 0_usize;
        let mut pending = vec![nodeset::Node::Root(mirror.target.root())];
        while let Some(node) = pending.pop() {
            pending.extend(node.children());
            let element = match node {
                nodeset::Node::Element(element) => element,
                nodeset::Node::Text(text) => {
                    bytes += text.text().len();
                    continue;
                }
                nodeset::Node::Comment(comment) => {
                    bytes += comment.text().len();
                    continue;
                }
                nodeset::Node::ProcessingInstruction(pi) => {
                    bytes += pi.target().len() + pi.value().map_or(0, |value| value.len());
                    continue;
                }
                _ => continue,
            };
            let stored_name = element.name();
            let name = stored_name.get();
            bytes += name.namespace_uri().map_or(0, str::len) + name.local_part().len();
            bytes += element.preferred_prefix().map_or(0, |prefix| prefix.len());
            bytes += element
                .default_namespace_uri()
                .map_or(0, |namespace| namespace.len());
            bytes += element
                .namespaces_in_scope()
                .into_iter()
                .filter(|namespace| !(namespace.prefix() == "xml" && namespace.uri() == XML_NS))
                .map(|namespace| namespace.prefix().len() + namespace.uri().len())
                .sum::<usize>();

            for attribute in element.attributes() {
                let stored_name = attribute.name();
                let name = stored_name.get();
                bytes += name.namespace_uri().map_or(0, str::len) + name.local_part().len();
                bytes += attribute.value().len();
                bytes += attribute
                    .preferred_prefix()
                    .map_or(0, |prefix| prefix.len());
            }
        }
        bytes
    }

    #[test]
    fn xpath_mirror_projection_counts_every_copied_string() {
        // This fixture exercises every string-bearing SXD constructor and
        // mutator used by Mirror::build. The default namespace is counted
        // twice because SXD stores both its default URI and namespace-axis
        // registration.
        let document = Document::parse(
            r#"<p:root xmlns:p="urn:p" xmlns="urn:d" p:a="value">text<!--comment--><?pi data?></p:root>"#,
        )
        .expect("fixed mirror projection fixture must parse");

        let projected_bytes = Mirror::<NativeKeys>::projected_string_bytes(&document)
            .expect("complete fixed fixture fits the mirror string budget");
        let package = Package::new();
        let mirror = Mirror::build(&document, package.as_document());

        assert_eq!(projected_bytes, 55);
        assert_eq!(projected_bytes, built_mirror_string_bytes(&mirror));
    }

    #[test]
    fn xpath_filter_rejects_excessive_cumulative_evaluation_work() {
        // This document stays below the per-node call-count cap, but repeated
        // evaluation over its full context would still exceed the aggregate
        // work budget. The check must therefore be independent of node count.
        let xml = format!("<root>{}</root>", "<item/>".repeat(2_500));
        let doc = Document::parse(&xml).unwrap();
        let error = apply_xpath_filter(
            NodeSet::entire_document_without_comments(&doc).unwrap(),
            &XPathExpression::new("true()"),
        )
        .err()
        .expect("excessive cumulative XPath evaluation work must fail closed");

        assert_resource_limit(&error, "XPath evaluation work");
    }

    #[test]
    fn xpath_filter_rejects_excessive_cumulative_string_work() {
        // A non-interruptible XPath string function can rescan a large text node
        // for every context node even when the document's node count is small.
        let xml = format!(
            "<root><blob>{}</blob>{}</root>",
            "x".repeat(1024 * 1024),
            "<item/>".repeat(300)
        );
        let document = Document::parse(&xml).unwrap();
        let error = apply_xpath_filter(
            NodeSet::entire_document_without_comments(&document).unwrap(),
            &XPathExpression::new("contains(string(/root/blob), 'missing')"),
        )
        .err()
        .expect("repeated XPath string scans must exhaust the shared work budget");

        assert_resource_limit(&error, "XPath string-processing work bytes");
    }

    #[test]
    fn xpath_filter_charges_each_repeated_string_scan() {
        // One full-source scan fits exactly; repeating the same linear string
        // function in one evaluation must consume another full-source charge.
        let document = Document::parse("<root><blob>payload</blob><item/></root>").unwrap();
        let single_scan_budget = XPathWorkBudget::default();
        let initial_remaining = single_scan_budget.string_work_bytes_remaining.get();
        apply_xpath_filter_with_semantics(
            NodeSet::entire_document_without_comments(&document).unwrap(),
            &XPathExpression::new("contains(/root/blob, 'missing')"),
            XPathHereSemantics::default(),
            XPathDocumentRelation::SameDocument,
            &single_scan_budget,
        )
        .expect("one bounded string scan should fit");
        let one_scan_work =
            initial_remaining - single_scan_budget.string_work_bytes_remaining.get();
        let repeated_scan_budget = XPathWorkBudget {
            remaining: Cell::new(MAX_XPATH_CUMULATIVE_EVALUATION_WORK),
            evaluation_limit_exceeded: Cell::new(false),
            mirror_bytes_remaining: Cell::new(MAX_XPATH_MIRROR_STRING_BYTES),
            string_work_bytes_remaining: Cell::new(one_scan_work),
            limits: XPathWorkBudget::default().limits,
        };

        let error = apply_xpath_filter_with_semantics(
            NodeSet::entire_document_without_comments(&document).unwrap(),
            &XPathExpression::new(
                "contains(/root/blob, 'missing') or contains(/root/blob, 'absent')",
            ),
            XPathHereSemantics::default(),
            XPathDocumentRelation::SameDocument,
            &repeated_scan_budget,
        )
        .err()
        .expect("two string scans must exceed a one-scan budget");

        assert_resource_limit(&error, "XPath string-processing work bytes");
    }

    #[test]
    fn xpath_filter_charges_each_repeated_numeric_conversion() {
        // SXD converts a node-set through its first node's complete string
        // value on every number() call. Repeating that conversion must not fit
        // inside the budget measured for one call.
        let document = Document::parse("<root><blob> 123 </blob><item/></root>").unwrap();
        let single_scan_budget = XPathWorkBudget::default();
        let initial_remaining = single_scan_budget.string_work_bytes_remaining.get();
        apply_xpath_filter_with_semantics(
            NodeSet::entire_document_without_comments(&document).unwrap(),
            &XPathExpression::new("number(/root/blob) = 123"),
            XPathHereSemantics::default(),
            XPathDocumentRelation::SameDocument,
            &single_scan_budget,
        )
        .expect("one bounded numeric conversion should fit");
        let one_scan_work =
            initial_remaining - single_scan_budget.string_work_bytes_remaining.get();
        let repeated_scan_budget = XPathWorkBudget {
            remaining: Cell::new(MAX_XPATH_CUMULATIVE_EVALUATION_WORK),
            evaluation_limit_exceeded: Cell::new(false),
            mirror_bytes_remaining: Cell::new(MAX_XPATH_MIRROR_STRING_BYTES),
            string_work_bytes_remaining: Cell::new(one_scan_work),
            limits: XPathWorkBudget::default().limits,
        };

        let error = apply_xpath_filter_with_semantics(
            NodeSet::entire_document_without_comments(&document).unwrap(),
            &XPathExpression::new("number(/root/blob) + number(/root/blob) = 246"),
            XPathHereSemantics::default(),
            XPathDocumentRelation::SameDocument,
            &repeated_scan_budget,
        )
        .err()
        .expect("repeated numeric conversions must exceed a one-conversion budget");

        assert_resource_limit(&error, "XPath string-processing work bytes");
    }

    #[test]
    fn xpath_filter_charges_each_repeated_id_conversion() {
        // The custom id() implementation converts its node-set argument to
        // complete string values before tokenizing IDs. Repeating that
        // conversion must not fit inside the budget measured for one call.
        let document =
            Document::parse("<root><ids>target</ids><item Id=\"target\"/><context/></root>")
                .unwrap();
        let single_scan_budget = XPathWorkBudget::default();
        let initial_remaining = single_scan_budget.string_work_bytes_remaining.get();
        apply_xpath_filter_with_semantics(
            NodeSet::entire_document_without_comments(&document).unwrap(),
            &XPathExpression::new("id(/root/ids)"),
            XPathHereSemantics::default(),
            XPathDocumentRelation::SameDocument,
            &single_scan_budget,
        )
        .expect("one bounded id conversion should fit");
        let one_scan_work =
            initial_remaining - single_scan_budget.string_work_bytes_remaining.get();
        let repeated_scan_budget = XPathWorkBudget {
            remaining: Cell::new(MAX_XPATH_CUMULATIVE_EVALUATION_WORK),
            evaluation_limit_exceeded: Cell::new(false),
            mirror_bytes_remaining: Cell::new(MAX_XPATH_MIRROR_STRING_BYTES),
            string_work_bytes_remaining: Cell::new(one_scan_work),
            limits: XPathWorkBudget::default().limits,
        };

        let error = apply_xpath_filter_with_semantics(
            NodeSet::entire_document_without_comments(&document).unwrap(),
            &XPathExpression::new("id(/root/ids) or id(/root/ids)"),
            XPathHereSemantics::default(),
            XPathDocumentRelation::SameDocument,
            &repeated_scan_budget,
        )
        .err()
        .expect("repeated id conversions must exceed a one-conversion budget");

        assert_resource_limit(&error, "XPath string-processing work bytes");
    }

    #[test]
    fn xpath_filter_charges_each_repeated_comparison_scan() {
        // XPath 1.0 compares a node-set through each candidate node's string
        // value. Two comparisons must therefore consume two complete source scans.
        let document = Document::parse("<root><blob>payload</blob><item/></root>").unwrap();
        let single_scan_budget = XPathWorkBudget::default();
        let initial_remaining = single_scan_budget.string_work_bytes_remaining.get();
        apply_xpath_filter_with_semantics(
            NodeSet::entire_document_without_comments(&document).unwrap(),
            &XPathExpression::new("/root/blob = 'missing'"),
            XPathHereSemantics::default(),
            XPathDocumentRelation::SameDocument,
            &single_scan_budget,
        )
        .expect("one bounded comparison scan should fit");
        let one_scan_work =
            initial_remaining - single_scan_budget.string_work_bytes_remaining.get();
        let repeated_scan_budget = XPathWorkBudget {
            remaining: Cell::new(MAX_XPATH_CUMULATIVE_EVALUATION_WORK),
            evaluation_limit_exceeded: Cell::new(false),
            mirror_bytes_remaining: Cell::new(MAX_XPATH_MIRROR_STRING_BYTES),
            string_work_bytes_remaining: Cell::new(one_scan_work),
            limits: XPathWorkBudget::default().limits,
        };

        let error = apply_xpath_filter_with_semantics(
            NodeSet::entire_document_without_comments(&document).unwrap(),
            &XPathExpression::new("/root/blob = 'missing' or /root/blob = 'absent'"),
            XPathHereSemantics::default(),
            XPathDocumentRelation::SameDocument,
            &repeated_scan_budget,
        )
        .err()
        .expect("two comparison scans must exceed a one-scan budget");

        assert_resource_limit(&error, "XPath string-processing work bytes");
    }

    #[test]
    fn xpath_filter2_rejects_cumulative_mirror_bytes() {
        // Each expression may mirror less than the per-document byte ceiling,
        // but repeated filters must not multiply signature-wide copying.
        let xml = format!("<root value=\"{}\"/>", "x".repeat(5 * 1024 * 1024));
        let document = Document::parse(&xml).unwrap();
        let input = NodeSet::entire_document_without_comments(&document).unwrap();
        let filters = [
            XPathFilter::new(XPathFilterOperation::Intersect, XPathExpression::new(".")),
            XPathFilter::new(XPathFilterOperation::Intersect, XPathExpression::new(".")),
        ];

        let error = match apply_xpath_filter2(input, &filters) {
            Ok(_) => panic!("repeated SXD mirrors must exhaust the cumulative byte budget"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            TransformError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XPATH_MIRROR_STRING_BYTES,
                ..
            })
        ));
    }

    #[test]
    fn xpath_filter_charges_nested_document_scans() {
        // A nested descendant scan runs once for every node visited by the
        // outer scan, and ordinary XMLDSig XPath repeats that work for every
        // input context node. Flat document-size accounting misses this cubic
        // case even though the expression and document are both small.
        let xml = format!("<root>{}</root>", "<item/>".repeat(20));
        let document = Document::parse(&xml).unwrap();
        let budget = XPathWorkBudget::with_limit(1_000);
        let error = apply_xpath_filter_with_semantics(
            NodeSet::entire_document_without_comments(&document).unwrap(),
            &XPathExpression::new("//*[count(//*) > 0]"),
            XPathHereSemantics::default(),
            XPathDocumentRelation::SameDocument,
            &budget,
        )
        .err()
        .expect("nested document scans must exhaust the shared XPath budget");

        assert_resource_limit(&error, "XPath evaluation work");
    }

    #[test]
    fn xpath_filter2_charges_each_parent_axis_step() {
        // A descendant selection followed by repeated parent steps traverses
        // those steps for every selected node inside the non-interruptible engine.
        let xml = format!("<root><outer>{}</outer></root>", "<item/>".repeat(20));
        let document = Document::parse(&xml).unwrap();
        let budget = XPathWorkBudget::with_limit(70);
        let error = apply_xpath_filter2_with_semantics(
            NodeSet::entire_document_without_comments(&document).unwrap(),
            &[XPathFilter::new(
                XPathFilterOperation::Intersect,
                XPathExpression::new("//*[../../..]"),
            )],
            XPathHereSemantics::default(),
            XPathDocumentRelation::SameDocument,
            &budget,
        )
        .err()
        .expect("repeated parent-axis steps must exhaust the shared XPath budget");

        assert_resource_limit(&error, "XPath evaluation work");
    }

    #[test]
    fn xpath_filter_charges_top_level_composed_document_scans() {
        // The descendant axis is evaluated for every node selected by the
        // leading descendant scan. Ordinary XMLDSig XPath then repeats that
        // quadratic evaluation for every input context node.
        let xml = format!("<root>{}</root>", "<item/>".repeat(20));
        let document = Document::parse(&xml).unwrap();
        let budget = XPathWorkBudget::with_limit(1_000);
        let error = apply_xpath_filter_with_semantics(
            NodeSet::entire_document_without_comments(&document).unwrap(),
            &XPathExpression::new("//*/descendant::*"),
            XPathHereSemantics::default(),
            XPathDocumentRelation::SameDocument,
            &budget,
        )
        .err()
        .expect("composed top-level scans must exhaust the shared XPath budget");

        assert_resource_limit(&error, "XPath evaluation work");
    }

    #[test]
    fn xpath_filter_charges_repeated_child_axis_branches() {
        // Independent child-axis union branches each rescan the same children.
        // Counting only descendant axes lets a short expression multiply SXD
        // work beyond the shared budget before signature verification begins.
        let xml = format!("<root>{}</root>", "<item/>".repeat(20));
        let document = Document::parse(&xml).unwrap();
        let repeated_branches = std::iter::repeat_n("/root/*", 30)
            .collect::<Vec<_>>()
            .join(" | ");
        let budget = XPathWorkBudget::with_limit(5_000);
        let error = apply_xpath_filter_with_semantics(
            NodeSet::entire_document_without_comments(&document).unwrap(),
            &XPathExpression::new(repeated_branches),
            XPathHereSemantics::default(),
            XPathDocumentRelation::SameDocument,
            &budget,
        )
        .err()
        .expect("repeated child-axis branches must exhaust the shared XPath budget");

        assert_resource_limit(&error, "XPath evaluation work");
    }

    #[test]
    fn xpath_work_profile_tracks_nested_paths_but_ignores_literals() {
        // The preflight meter must recognize both abbreviated paths and named
        // axes without treating XPath punctuation inside quoted data as work.
        fn xpath_evaluation_work(source: &str, size: usize, mode: XPathEvaluationMode) -> usize {
            super::xpath_evaluation_work(source, size, mode, &crate::c14n::scratch::Native)
                .expect("native estimate state is infallible")
        }
        let filter2 = XPathEvaluationMode::Filter2NodeSetSelection;
        assert_eq!(
            xpath_evaluation_work("//*[count(//*) > 0]", 10, filter2),
            110
        );
        assert_eq!(xpath_evaluation_work("//*[ancestor::*]", 10, filter2), 110);
        assert_eq!(xpath_evaluation_work("//a | //b", 10, filter2), 20);
        assert_eq!(xpath_evaluation_work("//a and //b", 10, filter2), 20);
        assert_eq!(xpath_evaluation_work("/root/*", 10, filter2), 10);
        assert_eq!(xpath_evaluation_work("/root/* | /root/*", 10, filter2), 20);
        assert_eq!(xpath_evaluation_work("/root/* | //item", 10, filter2), 20);
        assert_eq!(
            xpath_evaluation_work("child::root | child::root", 10, filter2),
            20
        );
        assert_eq!(
            xpath_evaluation_work("//brand/descendant::*", 10, filter2),
            110
        );
        assert_eq!(xpath_evaluation_work("//*/descendant::*", 10, filter2), 110);
        assert_eq!(
            xpath_evaluation_work("//*[.//*/descendant::*]", 10, filter2),
            1_110
        );
        assert_eq!(xpath_evaluation_work("//*[../../..]", 10, filter2), 40);
        assert_eq!(
            xpath_evaluation_work("//*[parent::*/parent::*]", 10, filter2),
            30
        );
        assert_eq!(
            xpath_evaluation_work(
                "//*[../../..]",
                10,
                XPathEvaluationMode::XmlDsigPerNodeFilter,
            ),
            13
        );
        assert_eq!(
            xpath_evaluation_work("//*[contains(., '//ancestor::*')]", 10, filter2),
            10
        );
    }

    #[test]
    fn xpath_string_profile_counts_only_linear_builtin_calls() {
        // Function-like text in literals and namespaced extension names does
        // not count, while each argument boundary remains a conservative pass.
        assert_eq!(
            xpath_string_scan_count("contains(/root/a, 'x') or starts-with(/root/b, 'y')"),
            4
        );
        assert_eq!(
            xpath_string_scan_count("string(translate(/root/a, 'x', 'y'))"),
            4
        );
        assert_eq!(
            xpath_string_scan_count("contains ('contains(/ignored)', 'x')"),
            2
        );
        assert_eq!(xpath_string_scan_count("ext:contains(/root/a, 'x')"), 1);
        assert_eq!(
            xpath_string_scan_count("/root/blob = 'missing' or /root/blob = 'absent'"),
            2
        );
        assert_eq!(xpath_string_scan_count("/root/blob = 'literal < > ='"), 1);
    }

    #[test]
    fn xpath_dependency_profile_distinguishes_counts_from_value_coercion() {
        // count() observes only node-set cardinality, while direct comparison
        // and string() can read mutable DigestValue text that controls output.
        assert!(!xpath_may_read_node_values("count(. | here()) = 1"));
        assert!(!xpath_may_read_node_values("1 != count(//item)"));
        assert!(xpath_may_read_node_values("//ds:DigestValue = ''"));
        assert!(xpath_may_read_node_values("string(//ds:DigestValue) = ''"));
    }

    #[test]
    fn xpath_dependency_profile_excludes_attribute_scalar_comparisons() {
        // Signing never mutates attributes, so comparing one to a literal does
        // not make disjoint DigestValue or SignatureValue text a dependency.
        assert!(!xpath_may_read_mutable_character_data("@kind = 'include'"));
        assert!(!xpath_may_read_mutable_character_data("'include' = @kind"));
        assert!(xpath_may_read_mutable_character_data(
            "//ds:DigestValue = ''"
        ));
        assert!(xpath_may_read_mutable_character_data(
            "@kind = //ds:DigestValue"
        ));
        assert!(xpath_may_read_mutable_character_data(
            "@kind = 'include' and string(//ds:DigestValue)"
        ));
    }

    #[test]
    fn xpath_string_profile_counts_numeric_coercion_sites() {
        // Numeric built-ins and arithmetic call SXD's Value::number(), while
        // wildcard name tests do not coerce strings and must remain free.
        assert_eq!(xpath_string_scan_count("number(/root/blob)"), 1);
        assert_eq!(xpath_string_scan_count("sum(/root/item)"), 1);
        assert_eq!(xpath_string_scan_count("floor(number(/root/blob))"), 2);
        assert_eq!(xpath_string_scan_count("/root/a + /root/b - /root/c"), 2);
        assert_eq!(
            xpath_string_scan_count("/root/a * /root/b div /root/c mod /root/d"),
            3
        );
        assert_eq!(xpath_string_scan_count("-/root/a"), 1);
        assert_eq!(xpath_string_scan_count("/root/* | child::* | //@*"), 0);
    }

    #[test]
    fn xpath_string_profile_counts_custom_string_coercions() {
        // Both registered custom functions eagerly coerce their argument to a
        // string, while unrelated namespace-qualified extensions do not.
        assert_eq!(xpath_string_scan_count("id(/root/ids)"), 1);
        assert_eq!(xpath_string_scan_count("lang(/root/language)"), 1);
        assert_eq!(xpath_string_scan_count("ext:id(/root/ids)"), 0);
    }

    #[test]
    fn xpath_string_profile_matches_pinned_nodeset_comparison_contract() {
        // xml-sec-sxd-xpath 0.1.0 hashes each node-set's string values before
        // testing equality, so one comparison is two linear operand scans, not
        // a Cartesian product. The conservative full-source charge is one pass.
        assert_eq!(
            xpath_string_scan_count("/root/left/item = /root/right/item"),
            1
        );

        let document = Document::parse(
            "<root><left><item>a</item><item>b</item></left><right><item>c</item><item>b</item></right></root>",
        )
        .unwrap();
        let result = apply_xpath_filter(
            NodeSet::entire_document_without_comments(&document).unwrap(),
            &XPathExpression::new("/root/left/item = /root/right/item"),
        )
        .expect("the pinned evaluator must support node-set equality");

        assert!(result.contains(document.root_element()));
    }

    #[test]
    fn xpath_id_scans_consume_the_shared_work_budget() {
        // Each custom id() call scans the mirrored document in addition to the
        // XPath engine's own traversal and must therefore consume shared work.
        let document = Document::parse("<root><item Id=\"selected\"/></root>").unwrap();
        let input = NodeSet::entire_document_without_comments(&document).unwrap();
        let budget = XPathWorkBudget::with_limit(15);
        let error = apply_xpath_filter2_with_semantics(
            input,
            &[XPathFilter::new(
                XPathFilterOperation::Intersect,
                XPathExpression::new("id('selected') | id('selected')"),
            )],
            XPathHereSemantics::default(),
            XPathDocumentRelation::SameDocument,
            &budget,
        )
        .err()
        .expect("repeated id() scans must exhaust the shared XPath budget");

        assert_resource_limit(&error, "XPath evaluation work");
    }

    #[test]
    fn xpath_filter_rejects_excessive_expression_complexity() {
        // A short document does not consume the context budget, but repeating
        // a document-scanning subexpression can still multiply evaluator work.
        let repeated_scan = "count(//*) >= 0 and ".repeat(300);
        let expression = XPathExpression::new(format!("{repeated_scan}true()"));
        let doc = Document::parse("<root><item/></root>").unwrap();
        let error = apply_xpath_filter(
            NodeSet::entire_document_without_comments(&doc).unwrap(),
            &expression,
        )
        .err()
        .expect("excessive XPath expression complexity must fail closed");

        assert_resource_limit(&error, "XPath expression complexity");
    }

    #[test]
    fn filter2_expands_selected_elements_to_subtrees() {
        // Filter 2.0 selection of an element includes all descendants,
        // attributes, and in-scope namespace nodes before set operations.
        let doc = Document::parse(
            r#"<root><keep a="1"><child>yes</child></keep><outside>no</outside></root>"#,
        )
        .unwrap();
        let input = NodeSet::entire_document_with_comments(&doc).unwrap();
        let filters = [XPathFilter::new(
            XPathFilterOperation::Intersect,
            XPathExpression::new("/root/keep"),
        )];
        let result = apply_xpath_filter2(input, &filters).unwrap();

        assert_eq!(
            canonicalize(&result),
            r#"<keep a="1"><child>yes</child></keep>"#
        );
    }

    #[test]
    fn retained_mirror_index_reads_use_the_current_query_not_the_producer() {
        // Retained identity maps keep their original capacity account. Reading
        // them from a new query must not spend an exhausted producer's work.
        use super::super::types::projection::PaidKeys;
        use std::sync::Arc;
        use structured_asn1::memory::{Memory, MemoryAccount};

        let document = Document::parse("<root/>").expect("fixed mirror fixture");
        let producer = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 20)));
        let package = Package::try_current(&producer).expect("funded mirror arena");
        let target = package.as_document();
        let mirror = Mirror::<PaidKeys<'_, Memory>>::build_in(&document, target, &producer)
            .expect("producer indexes fit");
        producer
            .charge_work(producer.work_remaining() as u64)
            .expect("exhaust producer");
        let query = Memory::new(Arc::new(MemoryAccount::new(0, 1 << 20)));
        let input = Projection::empty(&document, PaidKeys::new(&query));
        let element = target
            .root()
            .child_at(0)
            .expect("root slot")
            .element()
            .expect("mirrored root");
        assert!(
            !mirror
                .input_contains(&document, &input, &nodeset::Node::Element(element))
                .expect("current query reads retained index")
        );
        assert!(query.work_used() > 0);
        assert_eq!(
            query.used(),
            0,
            "read-only query allocates no index storage"
        );
        assert!(producer.charge_work(1).is_err());
    }

    #[test]
    fn mirror_indexes_retain_actual_capacity_and_refuse_zero_capacity() {
        // Both the identity indexes and the actual SXD allocation remain
        // charged independently until their respective owners are destroyed.
        use super::super::types::projection::PaidKeys;
        use std::sync::Arc;
        use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};

        let document = Document::parse("<root a='v'>text<!--c--><?pi v?></root>")
            .expect("fixed mirror fixture");
        let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 24)));
        let package = Package::try_current(&memory).expect("funded mirror arena");
        let mirror =
            Mirror::<PaidKeys<'_, Memory>>::build_in(&document, package.as_document(), &memory)
                .expect("indexes fit current capacity");
        assert!(memory.used() > 0, "index allocations retain their charge");
        let with_indexes = memory.used();
        drop(mirror);
        assert!(memory.used() > 0, "the arena still owns its actual storage");
        assert!(
            memory.used() < with_indexes,
            "dropping indexes releases their storage"
        );
        drop(package);
        assert_eq!(memory.used(), 0, "all actual owners have been destroyed");

        let refused = Memory::new(Arc::new(MemoryAccount::new(0, 1 << 24)));
        assert!(matches!(
            Package::try_current(&refused),
            Err(MemoryError::LimitExceeded)
        ));
        assert_eq!(refused.used(), 0);
    }

    #[test]
    fn callback_resource_cause_does_not_format_an_evaluator_diagnostic() {
        // Refusal must return the original typed cause without allocating a
        // diagnostic when the embedding resource domain is already exhausted.
        struct MustNotFormat;
        impl std::fmt::Display for MustNotFormat {
            fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                panic!("a retained resource cause must not format secondary errors")
            }
        }
        let failure = Cell::new(Some(structured_asn1::memory::MemoryError::OutOfMemory));
        let error = XPathWorkBudget::default().map_evaluation_error(
            MustNotFormat,
            &failure,
            &crate::c14n::scratch::Native,
        );
        assert!(matches!(
            error,
            TransformError::C14n(crate::c14n::C14nError::SharedExecution(
                structured_asn1::memory::MemoryError::OutOfMemory
            ))
        ));
    }

    #[test]
    fn current_evaluator_diagnostic_owns_capacity_or_returns_original_refusal() {
        // The final error is retained outside the evaluator. Its actual text
        // capacity must remain charged, and a refusal must not retry natively.
        use std::sync::Arc;
        use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
        let memory = Memory::new(Arc::new(MemoryAccount::new(4096, 4096)));
        let budget = XPathWorkBudget::default();
        let failure = Cell::new(None);
        let error = budget.map_evaluation_error(
            "unknown function",
            &failure,
            &crate::c14n::scratch::Accounted(&memory),
        );
        assert!(
            matches!(&error, TransformError::AccountedXPath(text) if &**text == "unknown function")
        );
        assert!(memory.used() > 0);
        drop(error);
        assert_eq!(memory.used(), 0);

        let refused = Memory::new(Arc::new(MemoryAccount::new(0, 4096)));
        let error = budget.map_evaluation_error(
            "unknown function",
            &failure,
            &crate::c14n::scratch::Accounted(&refused),
        );
        assert!(matches!(
            error,
            TransformError::C14n(crate::c14n::C14nError::SharedExecution(
                MemoryError::LimitExceeded
            ))
        ));
        assert_eq!(refused.used(), 0);
        assert!(matches!(
            XPathWorkBudget::with_limit(0).charge_function(1),
            Err(function::Error::ProcessingStopped)
        ));
    }

    #[test]
    fn current_evaluation_estimate_pays_its_scan_and_predicate_state() {
        // The estimate runs before the non-interruptible evaluator; a query
        // must pay its full source scan and own the per-predicate stacks.
        use std::sync::Arc;
        use structured_asn1::memory::{Memory, MemoryAccount, MemoryError};
        let mode = XPathEvaluationMode::XmlDsigPerNodeFilter;
        let source = format!("{}self::node()", " ".repeat(4096));
        let memory = Memory::new(Arc::new(MemoryAccount::new(4096, 1 << 20)));
        xpath_evaluation_work(&source, 10, mode, &crate::c14n::scratch::Accounted(&memory))
            .unwrap();
        assert!(memory.work_used() >= source.len());
        assert_eq!(memory.used(), 0);

        let nested = format!("{}self::node(){}", "a[".repeat(64), "]".repeat(64));
        let refused = Memory::new(Arc::new(MemoryAccount::new(0, 1 << 20)));
        assert!(matches!(
            xpath_evaluation_work(
                &nested,
                10,
                mode,
                &crate::c14n::scratch::Accounted(&refused)
            ),
            Err(crate::c14n::C14nError::SharedExecution(
                MemoryError::LimitExceeded
            ))
        ));
        assert_eq!(refused.used(), 0);
    }

    #[test]
    fn filter2_expansion_admits_source_walk_before_result_growth() {
        // Selecting the root requires one complete source walk even for a
        // sparse input projection. Refuse that walk with the current query
        // before allocating or partially constructing the result.
        use super::super::types::projection::PaidKeys;
        use std::sync::Arc;
        use structured_asn1::memory::{Memory, MemoryAccount};
        use structured_asn1::{Encoding, Limits, Parser};

        let document = Document::parse("<root><a/><b/><c/><d/><e/><f/></root>")
            .expect("fixed expansion fixture");
        let memory = Memory::new(Arc::new(MemoryAccount::new(1 << 20, 1 << 20)));
        let query = Parser::new(
            Encoding::Der,
            Limits {
                max_work: 1 << 20,
                ..Default::default()
            },
            memory.clone(),
        );
        let reader = query.read(&[], 0).expect("empty query carrier");
        let work = reader.execution();
        let package = Package::try_current(&work).expect("funded mirror arena");
        let target = package.as_document();
        let mut selected = nodeset::Nodeset::new();
        selected.add(target.root());
        let mirror = Mirror::<PaidKeys<'_, _>>::build_in(&document, target, &work)
            .expect("current indexes fit before exhausting traversal work");
        let allowed = document.descendants().len() - 1;
        let before_probe = memory.work_used();
        drop(
            selected
                .iter_current(&work)
                .expect("admit selected-table metadata"),
        );
        let selected_scan = memory.work_used() - before_probe;
        use structured_asn1::memory::Work as _;
        work.charge_work(((1 << 20) - memory.work_used() - allowed - selected_scan) as u64)
            .expect("fund selected metadata but leave one-less than the source walk");
        let before_work = memory.work_used();
        let before_storage = memory.used();
        assert!(
            before_storage > 0,
            "the current mirror indexes are accounted"
        );
        let input = Projection::empty(&document, PaidKeys::new(&work));
        let error = mirror
            .project_expanded(
                &document,
                &input,
                selected,
                &NodeSetMaterializationBudget::default(),
            )
            .err()
            .expect("whole expansion walk does not fit the current query");
        assert!(matches!(
            error,
            TransformError::C14n(crate::c14n::C14nError::SharedExecution(
                structured_asn1::memory::MemoryError::WorkExceeded
            ))
        ));
        assert_eq!(
            memory.work_used(),
            before_work + selected_scan,
            "only the admitted selected-table read precedes source-walk refusal"
        );
        assert_eq!(
            memory.used(),
            before_storage,
            "no result storage before admission"
        );
    }

    #[test]
    fn filter2_expands_nested_selected_roots_in_one_document_walk() {
        // A descendant selection returns every nested ancestor. Projection must
        // not rewalk the same descendants once for every selected root.
        let depth = 32;
        let xml = format!("{}text{}", "<n>".repeat(depth), "</n>".repeat(depth));
        let document = Document::parse(&xml).unwrap();
        let input = NodeSet::entire_document_without_comments(&document).unwrap();
        let filters = [XPathFilter::new(
            XPathFilterOperation::Intersect,
            XPathExpression::new("//*"),
        )];

        FILTER2_PROJECTION_NODE_VISITS.with(|visits| visits.set(0));
        apply_xpath_filter2(input, &filters).unwrap();
        let visits = FILTER2_PROJECTION_NODE_VISITS.with(Cell::get);

        assert!(
            visits <= document.descendants().count(),
            "projection revisited {visits} nodes"
        );
    }

    #[test]
    fn filter2_lang_ancestor_walks_consume_the_shared_budget() {
        // lang() searches ancestors for xml:lang. On a deep tree without that
        // attribute, evaluating it for every descendant must not evade metering.
        let depth = 32;
        let xml = format!("{}text{}", "<n>".repeat(depth), "</n>".repeat(depth));
        let document = Document::parse(&xml).unwrap();
        let input = NodeSet::entire_document_without_comments(&document).unwrap();
        let document_size = document.descendants().count();
        let filters = [XPathFilter::new(
            XPathFilterOperation::Intersect,
            XPathExpression::new("//*[lang('missing')]"),
        )];

        let error = apply_xpath_filter2_with_semantics(
            input,
            &filters,
            XPathHereSemantics::default(),
            XPathDocumentRelation::SameDocument,
            &XPathWorkBudget::with_limit(document_size * 3),
        )
        .err()
        .expect("ancestor walks must exhaust the shared XPath budget");

        assert_resource_limit(&error, "XPath evaluation work");
    }

    #[test]
    fn xpath_coalesces_text_split_only_by_cdata_boundaries() {
        // XPath 1.0 exposes adjacent character data as one logical text node,
        // while canonicalization must still retain every source fragment.
        let document = Document::parse("<root>A<![CDATA[B]]></root>").unwrap();
        let source_text = document
            .descendants()
            .filter(|node| node.is_text())
            .collect::<Vec<_>>();
        assert_eq!(source_text.len(), 1);
        assert_eq!(source_text[0].text(), Some("AB"));
        let input = NodeSet::entire_document_without_comments(&document).unwrap();

        let result = apply_xpath_filter(
            input,
            &XPathExpression::new("not(self::text()) or . = 'AB'"),
        )
        .unwrap();

        assert_eq!(canonicalize(&result), "<root>AB</root>");
    }

    #[test]
    fn filter2_expands_document_root_to_the_whole_document() {
        // Filter 2.0 defines a selected root as the root plus every node that
        // has it as an ancestor, so intersecting with `/` is an identity.
        let doc = Document::parse("<root><child>covered</child></root>").unwrap();
        let input = NodeSet::entire_document_without_comments(&doc).unwrap();
        let filters = [XPathFilter::new(
            XPathFilterOperation::Intersect,
            XPathExpression::new("/"),
        )];
        let result = apply_xpath_filter2(input, &filters).unwrap();

        assert_eq!(canonicalize(&result), "<root><child>covered</child></root>");
    }

    #[test]
    fn filter2_applies_intersect_subtract_and_union_in_order() {
        // Ordered set algebra must permit a later union to restore a subtree
        // removed by an earlier subtraction.
        let doc = Document::parse(
            r#"<root><scope><keep/><drop><restore/></drop></scope><other/></root>"#,
        )
        .unwrap();
        let input = NodeSet::entire_document_with_comments(&doc).unwrap();
        let filters = [
            XPathFilter::new(
                XPathFilterOperation::Intersect,
                XPathExpression::new("/root/scope"),
            ),
            XPathFilter::new(
                XPathFilterOperation::Subtract,
                XPathExpression::new("/root/scope/drop"),
            ),
            XPathFilter::new(
                XPathFilterOperation::Union,
                XPathExpression::new("/root/scope/drop/restore"),
            ),
        ];
        let result = apply_xpath_filter2(input, &filters).unwrap();

        assert_eq!(
            canonicalize(&result),
            "<scope><keep></keep><restore></restore></scope>"
        );
    }

    #[test]
    fn xpath_id_function_uses_projected_dtd_type() {
        // XPath 1.0 section 4.1 determines IDs from the XML data model;
        // projecting into SXD must not erase DTD type assignment.
        let doc = Document::parse_with_options(
            "<!DOCTYPE root [<!ATTLIST item Token ID #IMPLIED>]><root><item Token='  target  '>yes</item></root>",
            crate::ParsingOptions { allow_dtd: true, ..Default::default() },
        ).unwrap();
        let result = apply_xpath_filter2(
            NodeSet::entire_document_with_comments(&doc).unwrap(),
            &[XPathFilter::new(
                XPathFilterOperation::Intersect,
                XPathExpression::new("id('target')"),
            )],
        )
        .unwrap();
        assert_eq!(canonicalize(&result), "<item Token=\"target\">yes</item>");
    }

    #[test]
    fn xpath_id_registration_is_namespace_scoped() {
        // Filter 2.0 consumes the same request registration as ordinary XPath;
        // foreign attributes must not create a collision, but broad ones must.
        let doc = Document::parse(r#"<root xmlns:t="urn:trusted" xmlns:f="urn:foreign"><item t:Token="target">yes</item><other f:Token="target"/></root>"#).unwrap();
        let filters = [XPathFilter::new(
            XPathFilterOperation::Intersect,
            XPathExpression::new("id('target')"),
        )];
        let registrations = [crate::xml::IdAttributeRegistration::global("Token")
            .with_attribute_namespace(Some("urn:trusted"))];
        let result = apply_xpath_filter2_with_semantics_and_budget(
            NodeSet::entire_document_with_comments(&doc).unwrap(),
            &filters,
            XPathRequestContext::new(XPathHereSemantics::default(), &registrations),
            XPathDocumentRelation::SameDocument,
            &XPathWorkBudget::default(),
            &NodeFilterWorkBudget::default(),
            &NodeSetMaterializationBudget::default(),
        )
        .unwrap();
        let target = doc
            .descendants()
            .find(|node| node.has_tag_name("item"))
            .unwrap();
        let other = doc
            .descendants()
            .find(|node| node.has_tag_name("other"))
            .unwrap();
        assert!(result.contains(target));
        assert!(!result.contains(other));
        let broad = [crate::xml::IdAttributeRegistration::global("Token")];
        assert!(
            apply_xpath_filter2_with_semantics_and_budget(
                NodeSet::entire_document_with_comments(&doc).unwrap(),
                &filters,
                XPathRequestContext::new(XPathHereSemantics::default(), &broad),
                XPathDocumentRelation::SameDocument,
                &XPathWorkBudget::default(),
                &NodeFilterWorkBudget::default(),
                &NodeSetMaterializationBudget::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn xpath_id_function_selects_same_document_id() {
        // XMLDSig ID resolution accepts the common unqualified Id spelling
        // even without a validating DTD declaring the attribute type ID.
        let doc =
            Document::parse(r#"<root><item Id="target">yes</item><item>no</item></root>"#).unwrap();
        let input = NodeSet::entire_document_with_comments(&doc).unwrap();
        let filters = [XPathFilter::new(
            XPathFilterOperation::Intersect,
            XPathExpression::new("id('target')"),
        )];
        let result = apply_xpath_filter2(input, &filters).unwrap();

        assert_eq!(canonicalize(&result), r#"<item Id="target">yes</item>"#);
    }

    #[test]
    fn xpath_id_function_selects_namespaced_id_by_local_name() {
        // Same-document URI resolution and XPath id() must agree on common
        // WS-Security identifiers even when the Id attribute is namespaced.
        let doc = Document::parse(
            r#"<root xmlns:wsu="urn:ws-security"><item wsu:Id="target">yes</item><item>no</item></root>"#,
        )
        .unwrap();
        let filters = [XPathFilter::new(
            XPathFilterOperation::Intersect,
            XPathExpression::new("id('target')"),
        )];
        let result = apply_xpath_filter2(
            NodeSet::entire_document_with_comments(&doc).unwrap(),
            &filters,
        )
        .unwrap();

        assert_eq!(
            canonicalize(&result),
            r#"<item xmlns:wsu="urn:ws-security" wsu:Id="target">yes</item>"#
        );
    }

    #[test]
    fn xpath_id_function_unions_identifiers_from_node_set_argument() {
        // XPath 1.0 expands every string-value in a node-set argument to id(),
        // rather than coercing only its first node to a string.
        let doc = Document::parse(
            r#"<root><ids><id>one</id><id>two</id></ids><item Id="one"/><item Id="two"/></root>"#,
        )
        .unwrap();
        let filters = [XPathFilter::new(
            XPathFilterOperation::Intersect,
            XPathExpression::new("id(/root/ids/id)"),
        )];
        let result = apply_xpath_filter2(
            NodeSet::entire_document_with_comments(&doc).unwrap(),
            &filters,
        )
        .unwrap();

        assert_eq!(
            canonicalize(&result),
            r#"<item Id="one"></item><item Id="two"></item>"#
        );
    }

    #[test]
    fn xpath_id_function_rejects_duplicate_identifiers() {
        // Ambiguous IDs must fail closed instead of selecting every matching
        // element, which could let a verifier and application bind different
        // content to the same identifier.
        let doc =
            Document::parse(r#"<root><first Id="duplicate"/><second Id="duplicate"/></root>"#)
                .unwrap();
        let filters = [XPathFilter::new(
            XPathFilterOperation::Intersect,
            XPathExpression::new("id('duplicate')"),
        )];

        let error = apply_xpath_filter2(
            NodeSet::entire_document_with_comments(&doc).unwrap(),
            &filters,
        )
        .err()
        .expect("duplicate IDs must make XPath evaluation fail closed");

        assert!(matches!(error, TransformError::XPath(_)));
    }

    #[test]
    fn xpath_lang_function_uses_nearest_xml_lang_ancestor() {
        // lang() is case-insensitive, accepts a language subtag suffix, and
        // stops at the nearest xml:lang declaration.
        let doc = Document::parse(
            r#"<root xml:lang="en-US"><english>yes</english><french xml:lang="fr">no</french></root>"#,
        )
        .unwrap();
        let result = apply_xpath_filter(
            NodeSet::entire_document_with_comments(&doc).unwrap(),
            &XPathExpression::new("lang('EN')"),
        )
        .unwrap();
        let output = canonicalize(&result);

        assert!(output.contains("<english>yes</english>"));
        assert!(!output.contains("<french"));
        assert!(!output.contains(">no<"));
    }

    #[test]
    fn function_spacing_normalization_preserves_string_literals() {
        // The SXD compatibility normalization removes only a QName-to-call
        // token gap and must never rewrite matching text inside a literal.
        assert_eq!(
            normalize_function_spacing("not (contains('not (', 'x'))"),
            "not(contains('not (', 'x'))"
        );
    }

    #[test]
    fn function_spacing_normalization_preserves_word_operators() {
        // XPath word operators require a token boundary. Treating their
        // following parenthesis like a function call changes valid syntax.
        let source = "true() and (false()) or (6 div (2) = 3 and 7 mod (4) = 3)";

        assert_eq!(normalize_function_spacing(source), source);
    }

    #[test]
    fn function_spacing_normalization_uses_xpath_whitespace() {
        // XPath 1.0 S contains only space, tab, CR, and LF. Rust's broader
        // Unicode whitespace class must not turn malformed source into a
        // conforming function call that another XPath implementation rejects.
        for whitespace in [' ', '\t', '\r', '\n'] {
            let source = format!("true{whitespace}()");
            assert_eq!(normalize_function_spacing(&source), "true()");
            assert!(compile_xpath(&source).is_ok());
        }

        let non_xpath_whitespace = "true\u{00a0}()";
        assert_eq!(
            normalize_function_spacing(non_xpath_whitespace),
            non_xpath_whitespace
        );
        assert!(compile_xpath(non_xpath_whitespace).is_err());
    }

    #[test]
    fn xpath_here_function_uses_xpath_element() {
        // XMLDSig defines here() as the parent of the text node that directly
        // bears the expression, which is the XPath parameter element.
        let xml = r#"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><data/><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>count(. | here()) = 1 and count(here()/self::*) = 1 and count(here()/self::text()) = 0</ds:XPath></ds:Transform></root>"#;
        let doc = Document::parse(xml).unwrap();
        let transform_node = doc
            .descendants()
            .find(|node| node.has_tag_name((super::super::parse::XMLDSIG_NS, "Transform")))
            .unwrap();
        let transform = super::super::transforms::parse_xpath_transform(transform_node).unwrap();
        let input = TransformData::NodeSet(NodeSet::entire_document_with_comments(&doc).unwrap());
        let result =
            super::super::transforms::apply_transform(doc.root_element(), &transform, input)
                .unwrap()
                .into_node_set()
                .unwrap();

        let xpath_node = doc
            .descendants()
            .find(|node| node.has_tag_name((super::super::parse::XMLDSIG_NS, "XPath")))
            .unwrap();
        assert!(result.contains(xpath_node));
        assert!(!result.contains(doc.root_element()));
    }

    #[test]
    fn parsed_xpath_uses_implicit_xml_namespace_binding() {
        // Namespaces in XML binds `xml` without requiring an xmlns:xml
        // declaration, so parsed signatures must expose it to XPath too.
        let xml = r#"<root xml:id="target" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>self::*[@xml:id='target']</ds:XPath></ds:Transform></root>"#;
        let doc = Document::parse(xml).unwrap();
        let transform_node = doc
            .descendants()
            .find(|node| node.has_tag_name((super::super::parse::XMLDSIG_NS, "Transform")))
            .unwrap();
        let transform = super::super::transforms::parse_xpath_transform(transform_node).unwrap();
        let input = TransformData::NodeSet(NodeSet::entire_document_with_comments(&doc).unwrap());

        let result =
            super::super::transforms::apply_transform(doc.root_element(), &transform, input)
                .unwrap()
                .into_node_set()
                .unwrap();

        assert!(result.contains(doc.root_element()));
    }

    #[test]
    fn xpath_here_function_ignores_document_level_whitespace() {
        // XPath's root node does not expose whitespace outside the document
        // element, so it must not shift the child-index path used by here().
        let xml = r#"
<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><data/><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>count(. | here()) = 1</ds:XPath></ds:Transform></root>"#;
        let doc = Document::parse(xml).unwrap();
        let transform_node = doc
            .descendants()
            .find(|node| node.has_tag_name((super::super::parse::XMLDSIG_NS, "Transform")))
            .unwrap();
        let transform = super::super::transforms::parse_xpath_transform(transform_node).unwrap();
        let input = TransformData::NodeSet(NodeSet::entire_document_with_comments(&doc).unwrap());
        let result =
            super::super::transforms::apply_transform(doc.root_element(), &transform, input)
                .unwrap()
                .into_node_set()
                .unwrap();

        let xpath_node = doc
            .descendants()
            .find(|node| node.has_tag_name((super::super::parse::XMLDSIG_NS, "XPath")))
            .unwrap();
        assert!(result.contains(xpath_node));
        assert!(!result.contains(doc.root_element()));
    }

    #[test]
    fn xpath_here_function_supports_xmlsec_legacy_transform_element() {
        // libxmlsec1 binds here() to Transform rather than the XPath parameter;
        // compatibility must be explicit because this changes the selected set.
        let xml = r#"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><data/><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>count(. | here()) = 1</ds:XPath></ds:Transform></root>"#;
        let doc = Document::parse(xml).unwrap();
        let transform_node = doc
            .descendants()
            .find(|node| node.has_tag_name((super::super::parse::XMLDSIG_NS, "Transform")))
            .unwrap();
        let transform = super::super::transforms::parse_xpath_transform(transform_node).unwrap();
        let input = TransformData::NodeSet(NodeSet::entire_document_with_comments(&doc).unwrap());
        let options = super::super::transforms::TransformOptions::default()
            .xpath_here_semantics(XPathHereSemantics::XmlSecLegacy);
        let budget = super::super::transforms::TransformExecutionBudget::default();
        let result = super::super::transforms::apply_transform_with_options(
            doc.root_element(),
            &transform,
            input,
            options,
            &budget,
        )
        .unwrap()
        .into_node_set()
        .unwrap();

        assert!(result.contains(transform_node));
        assert!(!result.contains(doc.root_element()));
    }

    #[test]
    fn filter2_rejects_scalar_expression_results() {
        // Filter 2.0 requires a node-set; silently converting booleans would
        // change the signed node set and diverge from the W3C processing model.
        let doc = Document::parse("<root/>").unwrap();
        let filters = [XPathFilter::new(
            XPathFilterOperation::Intersect,
            XPathExpression::new("true()"),
        )];
        let error = apply_xpath_filter2(NodeSet::try_entire_document(&doc).unwrap(), &filters)
            .err()
            .unwrap();

        assert!(matches!(error, TransformError::XPath(_)));
    }

    #[test]
    fn xpath_rejects_unbound_variables() {
        // XMLDSig supplies no variable bindings, so a variable reference must
        // fail closed rather than inheriting application state.
        let doc = Document::parse("<root/>").unwrap();
        let error = apply_xpath_filter(
            NodeSet::try_entire_document(&doc).unwrap(),
            &XPathExpression::new("$external"),
        )
        .err()
        .unwrap();

        assert!(matches!(error, TransformError::XPath(_)));
    }

    #[test]
    fn filter2_rejects_empty_filter_sequence() {
        // A parameterless Filter 2.0 transform is malformed and must not act
        // as an accidental identity transform.
        let doc = Document::parse("<root/>").unwrap();
        let error = apply_xpath_filter2(NodeSet::try_entire_document(&doc).unwrap(), &[])
            .err()
            .unwrap();

        assert!(matches!(error, TransformError::XPath(_)));
    }
}
