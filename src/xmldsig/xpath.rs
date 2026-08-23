//! XPath 1.0 evaluation for XMLDSig transform node sets.
//!
//! `roxmltree` intentionally has no XPath engine, so transforms are evaluated
//! against an equivalent, short-lived SXD document. The mirror keeps a
//! bidirectional node map so the result can be projected back onto the
//! original document without serializing and reparsing signed input.

use std::cell::Cell;
use std::collections::{HashMap, HashSet, hash_map::Entry};
use std::rc::Rc;

use roxmltree::{Document, NodeId};
use sxd_document_no_unsafe::{Package, QName, dom};
use sxd_xpath_no_unsafe::{Context, Factory, Value, function, nodeset};

use super::transforms::{
    MAX_XPATH_EXPRESSION_BYTES, MAX_XPATH_FILTERS, NodeFilterWorkBudget, XPathExpression,
    XPathFilter, XPathFilterOperation, XPathHereSemantics,
};
use super::types::{
    NodeSet, NodeSetMaterializationBudget, TransformError, transform_resource_limit,
};
use crate::c14n::NodeVisibility;
use crate::c14n::prefix::{attribute_prefix, element_prefix};

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

#[derive(Clone)]
pub(super) struct XPathWorkBudget {
    remaining: Rc<Cell<usize>>,
    evaluation_limit_exceeded: Rc<Cell<bool>>,
    mirror_bytes_remaining: Rc<Cell<usize>>,
    string_work_bytes_remaining: Rc<Cell<usize>>,
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
            remaining: Rc::new(Cell::new(MAX_XPATH_CUMULATIVE_EVALUATION_WORK)),
            evaluation_limit_exceeded: Rc::new(Cell::new(false)),
            mirror_bytes_remaining: Rc::new(Cell::new(MAX_XPATH_MIRROR_STRING_BYTES)),
            string_work_bytes_remaining: Rc::new(Cell::new(MAX_XPATH_CUMULATIVE_STRING_WORK_BYTES)),
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
            remaining: Rc::new(Cell::new(limit)),
            evaluation_limit_exceeded: Rc::new(Cell::new(false)),
            mirror_bytes_remaining: Rc::new(Cell::new(MAX_XPATH_MIRROR_STRING_BYTES)),
            string_work_bytes_remaining: Rc::new(Cell::new(MAX_XPATH_CUMULATIVE_STRING_WORK_BYTES)),
            limits: Self::default().limits,
        }
    }

    pub(super) fn with_limits(resources: &crate::policy::ResourcePolicy) -> Self {
        Self {
            remaining: Rc::new(Cell::new(resources.max_xpath_evaluation_work)),
            evaluation_limit_exceeded: Rc::new(Cell::new(false)),
            mirror_bytes_remaining: Rc::new(Cell::new(resources.max_xpath_mirror_string_bytes)),
            string_work_bytes_remaining: Rc::new(Cell::new(resources.max_xpath_string_work_bytes)),
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
        self.charge(work).map_err(|error| function::Error::Other {
            what: error.to_string(),
        })
    }

    fn map_evaluation_error(&self, error: impl ToString) -> TransformError {
        if self.evaluation_limit_exceeded.get() {
            transform_resource_limit(
                crate::policy::resource_name::XPATH_EVALUATION_WORK,
                self.limits.evaluation_work,
                self.limits.evaluation_work.saturating_add(1),
            )
        } else {
            TransformError::XPath(error.to_string())
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

pub(super) fn normalize_function_spacing(source: &str) -> String {
    let chars = source.chars().collect::<Vec<_>>();
    let mut output = String::with_capacity(source.len());
    let mut index = 0;
    let mut quote = None;
    while index < chars.len() {
        let character = chars[index];
        if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            }
            output.push(character);
            index += 1;
            continue;
        }
        if quote.is_none() && is_xpath_whitespace(character) {
            let whitespace_start = index;
            while index < chars.len() && is_xpath_whitespace(chars[index]) {
                index += 1;
            }
            let previous_is_name = output
                .chars()
                .next_back()
                .is_some_and(|ch| ch.is_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':'));
            let previous_name = output
                .rsplit(|ch: char| !(ch.is_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':')))
                .next()
                .unwrap_or_default();
            let previous_is_word_operator = matches!(previous_name, "and" | "or" | "div" | "mod");
            if previous_is_name && !previous_is_word_operator && chars.get(index) == Some(&'(') {
                continue;
            }
            output.extend(chars[whitespace_start..index].iter());
            continue;
        }
        output.push(character);
        index += 1;
    }
    output
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
    if source.is_empty() || source.len() > max_expression_bytes {
        return Err(format!(
            "XPath expression length must be between 1 and {max_expression_bytes} bytes"
        ));
    }
    if xpath_expression_complexity(source) > max_expression_complexity {
        return Err(format!(
            "XPath expression complexity exceeds {max_expression_complexity} tokens"
        ));
    }
    Factory::new()
        .build(&normalize_function_spacing(source))
        .map_err(|error| error.to_string())
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
                    // This charge matches sxd-xpath-no-unsafe 0.5.1 rather than
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
/// deliberately turns arithmetic overflow into a budget rejection.
fn xpath_evaluation_work(source: &str, document_size: usize, mode: XPathEvaluationMode) -> usize {
    let bytes = source.as_bytes();
    let mut work = document_size;
    let mut predicate_depth = 0_usize;
    let mut top_level_path_scans = 0_usize;
    let mut top_level_path_started = false;
    let mut top_level_path_branches = 0_usize;
    let mut predicate_path_scans = Vec::new();
    let mut predicate_path_started = Vec::new();
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
                predicate_path_scans.push(0);
                predicate_path_started.push(false);
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

    work
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

struct Mirror<'d> {
    elements: HashMap<dom::Element<'d>, NodeId>,
    texts: HashMap<dom::Text<'d>, NodeId>,
    comments: HashMap<dom::Comment<'d>, NodeId>,
    processing_instructions: HashMap<dom::ProcessingInstruction<'d>, NodeId>,
}

#[derive(Clone, Copy)]
enum ProjectionMode {
    ExactNodes,
    ExpandToSubtrees,
}

impl<'d> Mirror<'d> {
    /// Measures exactly the source strings passed to SXD by [`Self::build`].
    ///
    /// Keep this traversal structurally aligned with `build`: unlike the
    /// node-set budget, it includes character data and attribute values, and
    /// charges repeated namespace registrations separately.
    fn projected_string_bytes(source: &Document<'_>) -> Result<usize, TransformError> {
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
                        attribute_prefix(node, &attribute).len(),
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

    fn build(source: &Document<'_>, target: dom::Document<'d>) -> Self {
        let mut mirror = Self {
            elements: HashMap::new(),
            texts: HashMap::new(),
            comments: HashMap::new(),
            processing_instructions: HashMap::new(),
        };
        let mut parents: HashMap<NodeId, dom::Element<'d>> = HashMap::new();

        // Descendants are yielded in document order, so every element parent
        // has already been mirrored when one of its children is encountered.
        for source_node in source.descendants().filter(|node| !node.is_root()) {
            let source_parent = source_node.parent();
            let target_parent = source_parent.and_then(|node| parents.get(&node.id()).copied());

            if source_node.is_element() {
                let name = QName::with_namespace_uri(
                    source_node.tag_name().namespace(),
                    source_node.tag_name().name(),
                );
                let element = target.create_element(name);

                // SXD's namespaces_in_scope() always injects the predefined
                // xml binding, even when no prefix was registered explicitly.
                for namespace in source_node.namespaces() {
                    match namespace.name() {
                        Some(prefix) => element.register_prefix(prefix, namespace.uri()),
                        None => {
                            // XPath 1.0's namespace axis does not expose an
                            // `xmlns=""` undeclaration as a namespace node.
                            // Registering it in SXD changes canonicalized
                            // node-sets compared with libxml2/xmlsec.
                            if namespace.uri().is_empty() {
                                element.set_default_namespace_uri(None);
                                continue;
                            }
                            element.set_default_namespace_uri(Some(namespace.uri()));
                            // SXD's namespace axis enumerates only registered
                            // prefixes and otherwise omits the default binding.
                            element.register_prefix("", namespace.uri());
                        }
                    }
                }
                let prefix = element_prefix(source_node);
                element.set_preferred_prefix((!prefix.is_empty()).then_some(prefix));

                for attribute in source_node.attributes() {
                    let name = QName::with_namespace_uri(attribute.namespace(), attribute.name());
                    let target_attribute = element.set_attribute_value(name, attribute.value());
                    let prefix = attribute_prefix(source_node, &attribute);
                    target_attribute.set_preferred_prefix((!prefix.is_empty()).then_some(prefix));
                }

                match target_parent {
                    Some(parent) => parent.append_child(element),
                    None => target.root().append_child(element),
                }
                parents.insert(source_node.id(), element);
                mirror.elements.insert(element, source_node.id());
            } else if source_node.is_text() {
                // roxmltree already coalesces adjacent character data across
                // CDATA boundaries into the single text node required by the
                // XPath 1.0 data model. It also omits whitespace outside the
                // document element, so every mirrored text has an element parent.
                if let Some(parent) = target_parent {
                    let text = target.create_text(source_node.text().unwrap_or_default());
                    parent.append_child(text);
                    mirror.texts.insert(text, source_node.id());
                }
            } else if source_node.is_comment() {
                let comment = target.create_comment(source_node.text().unwrap_or_default());
                match target_parent {
                    Some(parent) => parent.append_child(comment),
                    None => target.root().append_child(comment),
                }
                mirror.comments.insert(comment, source_node.id());
            } else if source_node.is_pi()
                && let Some(pi) = source_node.pi()
            {
                let processing_instruction =
                    target.create_processing_instruction(pi.target, pi.value);
                match target_parent {
                    Some(parent) => parent.append_child(processing_instruction),
                    None => target.root().append_child(processing_instruction),
                }
                mirror
                    .processing_instructions
                    .insert(processing_instruction, source_node.id());
            }
        }

        mirror
    }

    fn project<'a>(
        &self,
        source: &'a Document<'a>,
        selected: nodeset::Nodeset<'d>,
        mode: ProjectionMode,
        materialization_budget: &NodeSetMaterializationBudget,
    ) -> Result<NodeSet<'a>, TransformError> {
        if matches!(mode, ProjectionMode::ExpandToSubtrees) {
            return self.project_expanded(source, selected, materialization_budget);
        }

        let mut result = NodeSet::empty(source);
        for node in selected.document_order() {
            match node {
                nodeset::Node::Root(_) => {
                    result.insert_node(source.root());
                }
                nodeset::Node::Element(element) => {
                    if let Some(source_node) = self.source_node(source, self.elements.get(&element))
                    {
                        result.insert_node(source_node);
                    }
                }
                nodeset::Node::Attribute(attribute) => {
                    let Some(parent) = attribute.parent() else {
                        continue;
                    };
                    let Some(source_parent) = self.source_node(source, self.elements.get(&parent))
                    else {
                        continue;
                    };
                    let stored_name = attribute.name();
                    let name = sxd_document_no_unsafe::as_qname!(stored_name);
                    result.insert_attribute_with_budget(
                        source_parent,
                        name.namespace_uri(),
                        name.local_part(),
                        materialization_budget,
                    )?;
                }
                nodeset::Node::Text(text) => {
                    if let Some(source_node) = self.source_node(source, self.texts.get(&text)) {
                        result.insert_node(source_node);
                    }
                }
                nodeset::Node::Comment(comment) => {
                    if let Some(source_node) = self.source_node(source, self.comments.get(&comment))
                    {
                        result.insert_node(source_node);
                    }
                }
                nodeset::Node::Namespace(namespace) => {
                    if let Some(source_parent) =
                        self.source_node(source, self.elements.get(&namespace.parent()))
                    {
                        result.insert_namespace_with_budget(
                            source_parent,
                            namespace.prefix(),
                            namespace.uri(),
                            materialization_budget,
                        )?;
                    }
                }
                nodeset::Node::ProcessingInstruction(pi) => {
                    if let Some(source_node) =
                        self.source_node(source, self.processing_instructions.get(&pi))
                    {
                        result.insert_node(source_node);
                    }
                }
            }
        }
        Ok(result)
    }

    fn project_expanded<'a>(
        &self,
        source: &'a Document<'a>,
        selected: nodeset::Nodeset<'d>,
        materialization_budget: &NodeSetMaterializationBudget,
    ) -> Result<NodeSet<'a>, TransformError> {
        let mut result = NodeSet::empty(source);
        let mut selected_elements = HashSet::new();
        let mut root_selected = false;

        // Non-container XPath nodes have no descendants and are projected
        // exactly. Element/root selections are expanded together below.
        for node in selected.document_order() {
            match node {
                nodeset::Node::Root(_) => root_selected = true,
                nodeset::Node::Element(element) => {
                    if let Some(source_node) = self.source_node(source, self.elements.get(&element))
                    {
                        selected_elements.insert(source_node.id());
                    }
                }
                nodeset::Node::Attribute(attribute) => {
                    let Some(parent) = attribute.parent() else {
                        continue;
                    };
                    let Some(source_parent) = self.source_node(source, self.elements.get(&parent))
                    else {
                        continue;
                    };
                    let stored_name = attribute.name();
                    let name = sxd_document_no_unsafe::as_qname!(stored_name);
                    result.insert_attribute_with_budget(
                        source_parent,
                        name.namespace_uri(),
                        name.local_part(),
                        materialization_budget,
                    )?;
                }
                nodeset::Node::Text(text) => {
                    if let Some(source_node) = self.source_node(source, self.texts.get(&text)) {
                        result.insert_node(source_node);
                    }
                }
                nodeset::Node::Comment(comment) => {
                    if let Some(source_node) = self.source_node(source, self.comments.get(&comment))
                    {
                        result.insert_node(source_node);
                    }
                }
                nodeset::Node::Namespace(namespace) => {
                    if let Some(source_parent) =
                        self.source_node(source, self.elements.get(&namespace.parent()))
                    {
                        result.insert_namespace_with_budget(
                            source_parent,
                            namespace.prefix(),
                            namespace.uri(),
                            materialization_budget,
                        )?;
                    }
                }
                nodeset::Node::ProcessingInstruction(pi) => {
                    if let Some(source_node) =
                        self.source_node(source, self.processing_instructions.get(&pi))
                    {
                        result.insert_node(source_node);
                    }
                }
            }
        }

        // Carry one inherited-selection bit through a single source DFS. Nested
        // selected roots therefore never cause repeated descendant insertion.
        if !root_selected && selected_elements.is_empty() {
            return Ok(result);
        }
        let mut stack = vec![(source.root(), root_selected)];
        while let Some((node, inherited_selection)) = stack.pop() {
            #[cfg(test)]
            FILTER2_PROJECTION_NODE_VISITS.with(|visits| visits.set(visits.get() + 1));
            let selected = inherited_selection || selected_elements.contains(&node.id());
            if selected {
                result.insert_node(node);
                if node.is_element() {
                    for attribute in node.attributes() {
                        result.insert_attribute_with_budget(
                            node,
                            attribute.namespace(),
                            attribute.name(),
                            materialization_budget,
                        )?;
                    }
                    for namespace in node.namespaces() {
                        result.insert_namespace_with_budget(
                            node,
                            namespace.name().unwrap_or(""),
                            namespace.uri(),
                            materialization_budget,
                        )?;
                    }
                }
            }
            stack.extend(node.children().rev().map(|child| (child, selected)));
        }

        Ok(result)
    }

    fn source_node<'a>(
        &self,
        source: &'a Document<'a>,
        id: Option<&NodeId>,
    ) -> Option<roxmltree::Node<'a, 'a>> {
        id.and_then(|id| source.get_node(*id))
    }

    fn input_contains<'a>(
        &self,
        source: &'a Document<'a>,
        input: &NodeSet<'a>,
        node: &nodeset::Node<'d>,
    ) -> bool {
        match node {
            nodeset::Node::Root(_) => input.contains(source.root()),
            nodeset::Node::Element(element) => self
                .source_node(source, self.elements.get(element))
                .is_some_and(|node| input.contains(node)),
            nodeset::Node::Attribute(attribute) => {
                let Some(parent) = attribute.parent() else {
                    return false;
                };
                let Some(source_parent) = self.source_node(source, self.elements.get(&parent))
                else {
                    return false;
                };
                let stored_name = attribute.name();
                let name = sxd_document_no_unsafe::as_qname!(stored_name);
                input.contains_attribute(source_parent, name.namespace_uri(), name.local_part())
            }
            nodeset::Node::Text(text) => self
                .source_node(source, self.texts.get(text))
                .is_some_and(|node| input.contains(node)),
            nodeset::Node::Comment(comment) => self
                .source_node(source, self.comments.get(comment))
                .is_some_and(|node| input.contains(node)),
            nodeset::Node::Namespace(namespace) => self
                .source_node(source, self.elements.get(&namespace.parent()))
                .is_some_and(|owner| {
                    input.contains_namespace(owner, namespace.prefix(), namespace.uri())
                }),
            nodeset::Node::ProcessingInstruction(pi) => self
                .source_node(source, self.processing_instructions.get(pi))
                .is_some_and(|node| input.contains(node)),
        }
    }
}

fn charge_xpath_mirror_bytes(current: usize, additional: usize) -> Result<usize, TransformError> {
    let total = current.checked_add(additional).ok_or_else(|| {
        transform_resource_limit(
            crate::policy::resource_name::XPATH_MIRROR_STRING_BYTES,
            MAX_XPATH_MIRROR_STRING_BYTES,
            usize::MAX,
        )
    })?;
    if total > MAX_XPATH_MIRROR_STRING_BYTES {
        return Err(transform_resource_limit(
            crate::policy::resource_name::XPATH_MIRROR_STRING_BYTES,
            MAX_XPATH_MIRROR_STRING_BYTES,
            total,
        ));
    }
    Ok(total)
}

/// Resolves XML Signature's `here()` function to the node selected by the
/// caller's standards/compatibility policy. A child-index path is owned by the
/// function because SXD requires registered functions to be `'static`.
struct HereFunction {
    context: HereContext,
}

enum HereContext {
    Path(Vec<usize>),
    CrossDocument,
    MissingParameterNode,
}

impl function::Function for HereFunction {
    fn evaluate<'c, 'd>(
        &self,
        context: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: Vec<Value<'d>>,
    ) -> Result<Value<'d>, function::Error> {
        function::Args(args).exactly(0)?;
        let path = match &self.context {
            HereContext::Path(path) => path,
            // XMLDSig XPath and Filter 2.0 require an error when the parameter
            // carrying the expression belongs to another XML document.
            HereContext::CrossDocument => {
                return Err(function::Error::Other {
                    what: "here() parameter and evaluation context must appear in the same XML document"
                        .into(),
                });
            }
            HereContext::MissingParameterNode => {
                return Err(function::Error::Other {
                    what: "here() requires an XPath expression parsed from an XML parameter".into(),
                });
            }
        };
        let mut node = nodeset::Node::Root(context.node.document().root());
        for &index in path {
            node =
                node.children()
                    .into_iter()
                    .nth(index)
                    .ok_or_else(|| function::Error::Other {
                        what: "here() context node no longer exists".into(),
                    })?;
        }
        let mut result = nodeset::Nodeset::new();
        result.add(node);
        Ok(Value::Nodeset(result))
    }
}

/// SXD omits XPath's DTD-aware `id()` function. XMLDSig commonly identifies
/// elements through `Id`, `ID`, `id`, or `xml:id`, matching this crate's same-
/// document URI resolver rather than requiring a validating DTD parser.
struct IdFunction {
    work_budget: XPathWorkBudget,
    document_scan_cost: usize,
}

impl function::Function for IdFunction {
    fn evaluate<'c, 'd>(
        &self,
        context: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: Vec<Value<'d>>,
    ) -> Result<Value<'d>, function::Error> {
        let mut args = function::Args(args);
        args.exactly(1)?;
        let argument = args.0.pop().ok_or(function::Error::ArgumentMissing)?;
        let values = match argument {
            Value::Nodeset(nodes) => nodes
                .document_order()
                .into_iter()
                .map(|node| node.string_value())
                .collect::<Vec<_>>(),
            value => vec![value.into_string()],
        };
        let identifiers = values
            .iter()
            .flat_map(|value| value.split_ascii_whitespace())
            .collect::<HashSet<_>>();
        let mut matched = HashMap::new();
        let mut ambiguous = HashSet::new();
        let mut stack = vec![nodeset::Node::Root(context.node.document().root())];

        // The custom id() implementation performs its own full-document scan in
        // addition to the XPath engine's work, so it must consume the same meter.
        self.work_budget.charge_function(self.document_scan_cost)?;

        while let Some(node) = stack.pop() {
            stack.extend(node.children());
            let Some(element) = node.element() else {
                continue;
            };
            for attribute in element.attributes() {
                let stored_name = attribute.name();
                let name = sxd_document_no_unsafe::as_qname!(stored_name);
                // Match the URI resolver's local-name policy: WS-Security's
                // namespaced wsu:Id and XML's xml:id are ID attributes too.
                let recognized = matches!(name.local_part(), "Id" | "ID" | "id");
                let value = sxd_document_no_unsafe::as_str!(attribute.value());
                if !recognized || !identifiers.contains(&value) || ambiguous.contains(value) {
                    continue;
                }
                match matched.entry(value.to_owned()) {
                    Entry::Vacant(entry) => {
                        entry.insert(element);
                    }
                    Entry::Occupied(entry) if *entry.get() == element => {}
                    Entry::Occupied(entry) => {
                        entry.remove();
                        ambiguous.insert(value.to_owned());
                    }
                }
            }
        }

        if !ambiguous.is_empty() {
            return Err(function::Error::Other {
                what: "id() matched a duplicate identifier".into(),
            });
        }
        let mut result = nodeset::Nodeset::new();
        for element in matched.into_values() {
            result.add(element);
        }
        Ok(Value::Nodeset(result))
    }
}

struct LangFunction {
    work_budget: XPathWorkBudget,
}

impl function::Function for LangFunction {
    fn evaluate<'c, 'd>(
        &self,
        context: &sxd_xpath_no_unsafe::context::Evaluation<'c, 'd>,
        args: Vec<Value<'d>>,
    ) -> Result<Value<'d>, function::Error> {
        let mut args = function::Args(args);
        args.exactly(1)?;
        let requested = args.pop_string()?.to_ascii_lowercase();
        let mut node = Some(context.node.clone());
        while let Some(current) = node {
            self.work_budget.charge_function(1)?;
            if let Some(element) = current.element()
                && let Some(language) = element.attributes().into_iter().find_map(|attribute| {
                    let stored_name = attribute.name();
                    let name = sxd_document_no_unsafe::as_qname!(stored_name);
                    (name.local_part() == "lang"
                        && name.namespace_uri() == Some("http://www.w3.org/XML/1998/namespace"))
                    .then(|| sxd_document_no_unsafe::as_str!(attribute.value()).to_owned())
                })
            {
                let language = language.to_ascii_lowercase();
                let matches = language == requested
                    || language
                        .strip_prefix(&requested)
                        .is_some_and(|suffix| suffix.starts_with('-'));
                return Ok(Value::Boolean(matches));
            }
            node = current.parent();
        }
        Ok(Value::Boolean(false))
    }
}

fn here_path(document: &Document<'_>, here_node: Option<NodeId>) -> Option<Vec<usize>> {
    let mut node = here_node.and_then(|id| document.get_node(id))?;
    let mut path = Vec::new();
    while let Some(parent) = node.parent() {
        let index = parent
            .children()
            .position(|child| child == node)
            .unwrap_or(0);
        path.push(index);
        node = parent;
    }
    path.reverse();
    Some(path)
}

#[derive(Clone, Copy)]
pub(super) enum XPathDocumentRelation {
    SameDocument,
    CrossDocument,
}

impl XPathDocumentRelation {
    pub(super) fn between(left: &Document<'_>, right: &Document<'_>) -> Self {
        if std::ptr::eq(left, right) {
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

fn evaluate_expression<'a>(
    input: &NodeSet<'a>,
    expression: &XPathExpression,
    mode: XPathEvaluationMode,
    here_semantics: XPathHereSemantics,
    document_relation: XPathDocumentRelation,
    work_budget: &XPathWorkBudget,
    materialization_budget: &NodeSetMaterializationBudget,
) -> Result<NodeSet<'a>, TransformError> {
    let document = input.document();
    let document_size = NodeSet::ensure_subtree_materialization_fits_with_budget(
        document.root(),
        true,
        materialization_budget,
    )?;
    // The node-set preflight bounds map cardinality and inherited namespace
    // amplification. This separate preflight accounts for every string copied
    // by Mirror::build before allocating the secondary DOM.
    let mirror_bytes = Mirror::projected_string_bytes(document)?;
    work_budget.charge_mirror_bytes(mirror_bytes)?;
    work_budget.charge(document_size)?;
    let package = Package::new();
    let target = package.as_document();
    let mirror = Mirror::build(document, target);
    let mut context = Context::new();
    for (prefix, uri) in expression.namespaces() {
        context.set_namespace(prefix, uri);
    }
    // The XML namespace binding is implicit and roxmltree therefore does not
    // expose it through element namespace declarations. Enforce it at the
    // evaluation boundary for both parsed and programmatic expressions.
    context.set_namespace("xml", XML_NS);
    context.set_function(
        "here",
        HereFunction {
            context: match document_relation {
                XPathDocumentRelation::CrossDocument => HereContext::CrossDocument,
                XPathDocumentRelation::SameDocument => {
                    here_path(document, expression.here_context_node(here_semantics))
                        .map_or(HereContext::MissingParameterNode, HereContext::Path)
                }
            },
        },
    );
    context.set_function(
        "id",
        IdFunction {
            work_budget: work_budget.clone(),
            document_scan_cost: document_size,
        },
    );
    context.set_function(
        "lang",
        LangFunction {
            work_budget: work_budget.clone(),
        },
    );

    let expression_bytes = expression.expression().len();
    if expression_bytes > work_budget.limits.expression_bytes {
        return Err(transform_resource_limit(
            crate::policy::resource_name::XPATH_EXPRESSION_BYTES,
            work_budget.limits.expression_bytes,
            expression_bytes,
        ));
    }
    let expression_complexity = xpath_expression_complexity(expression.expression());
    if expression_complexity > work_budget.limits.expression_complexity {
        return Err(transform_resource_limit(
            crate::policy::resource_name::XPATH_EXPRESSION_COMPLEXITY,
            work_budget.limits.expression_complexity,
            expression_complexity,
        ));
    }
    let xpath = compile_xpath_with_policy_limits(
        expression.expression(),
        work_budget.limits.expression_bytes,
        work_budget.limits.expression_complexity,
    )
    .map_err(TransformError::XPath)?;
    let evaluation_work = xpath_evaluation_work(expression.expression(), document_size, mode);
    let string_scans = xpath_string_scan_count(expression.expression()).max(1);

    if matches!(mode, XPathEvaluationMode::XmlDsigPerNodeFilter) {
        // XMLDSig 1.1 section 6.6.3 requires a fresh context for every input
        // node with position=1 and size=1. Do not evaluate these nodes as one
        // XPath sequence: position() and last() are normatively constant here.
        // https://www.w3.org/TR/xmldsig-core/#sec-XPath
        let all_nodes_xpath = Factory::new()
            .build(ALL_XPATH_NODES)
            .map_err(|error| TransformError::XPath(error.to_string()))?;
        work_budget.charge(document_size)?;
        let all_nodes = all_nodes_xpath
            .evaluate(&context, target.root())
            .map_err(|error| work_budget.map_evaluation_error(error))?;
        let Value::Nodeset(all_nodes) = all_nodes else {
            unreachable!("the fixed all-nodes XPath expression returns a node-set");
        };
        let all_ordered_nodes = all_nodes.document_order();
        let ordered_nodes = all_ordered_nodes
            .into_iter()
            .filter(|node| mirror.input_contains(document, input, node))
            .collect::<Vec<_>>();
        work_budget.validate_context_evaluations(ordered_nodes.len())?;
        // SXD has no interrupt hook and XPath coercions can materialize or scan
        // any mirrored string. Charge the complete source string volume for
        // every context before entering the evaluator; syntax-based discounts
        // would leave alternate coercion paths able to bypass this ceiling.
        work_budget.charge_string_work(mirror_bytes, ordered_nodes.len(), string_scans)?;
        let mut selected = nodeset::Nodeset::new();
        for node in ordered_nodes {
            // SXD exposes no interrupt hook. Charge nested predicate scans
            // before execution so they cannot hide cubic work inside one call.
            work_budget.charge(evaluation_work)?;
            let include = xpath
                .evaluate(&context, node.clone())
                .map_err(|error| work_budget.map_evaluation_error(error))?
                .into_boolean();
            if include {
                selected.add(node);
            }
        }
        return mirror.project(
            document,
            selected,
            ProjectionMode::ExactNodes,
            materialization_budget,
        );
    }

    work_budget.charge(evaluation_work)?;
    work_budget.charge_string_work(mirror_bytes, 1, string_scans)?;
    let value = xpath
        .evaluate(&context, target.root())
        .map_err(|error| work_budget.map_evaluation_error(error))?;
    let Value::Nodeset(selected) = value else {
        return Err(TransformError::XPath(
            "XPath Filter 2.0 expression must return a node-set".into(),
        ));
    };
    mirror.project(
        document,
        selected,
        ProjectionMode::ExpandToSubtrees,
        materialization_budget,
    )
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

pub(super) fn apply_xpath_filter_with_semantics_and_budget<'a>(
    mut input: NodeSet<'a>,
    expression: &XPathExpression,
    here_semantics: XPathHereSemantics,
    document_relation: XPathDocumentRelation,
    work_budget: &XPathWorkBudget,
    node_filter_budget: &NodeFilterWorkBudget,
    materialization_budget: &NodeSetMaterializationBudget,
) -> Result<NodeSet<'a>, TransformError> {
    let selected = evaluate_expression(
        &input,
        expression,
        XPathEvaluationMode::XmlDsigPerNodeFilter,
        here_semantics,
        document_relation,
        work_budget,
        materialization_budget,
    )?;
    node_filter_budget.charge(input.len())?;
    input.intersect_with(&selected);
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

pub(super) fn apply_xpath_filter2_with_semantics_and_budget<'a>(
    input: NodeSet<'a>,
    filters: &[XPathFilter],
    here_semantics: XPathHereSemantics,
    document_relation: XPathDocumentRelation,
    work_budget: &XPathWorkBudget,
    node_filter_budget: &NodeFilterWorkBudget,
    materialization_budget: &NodeSetMaterializationBudget,
) -> Result<NodeSet<'a>, TransformError> {
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
    let mut result =
        NodeSet::try_entire_document_with_budget(input.document(), materialization_budget)?;
    for filter in filters {
        let selected = evaluate_expression(
            &input,
            filter.xpath(),
            XPathEvaluationMode::Filter2NodeSetSelection,
            here_semantics,
            document_relation,
            work_budget,
            materialization_budget,
        )?;
        match filter.operation() {
            XPathFilterOperation::Intersect => {
                node_filter_budget.charge(result.len())?;
                result.intersect_with(&selected);
            }
            XPathFilterOperation::Subtract => {
                node_filter_budget.charge(result.len())?;
                result.subtract(&selected);
            }
            XPathFilterOperation::Union => {
                node_filter_budget.charge(selected.len())?;
                result.union_with_budget(&selected, materialization_budget)?;
            }
        }
    }
    node_filter_budget.charge(result.len())?;
    result.intersect_with(&input);
    Ok(result)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests use fixed XML and XPath fixtures")]
mod tests {
    use super::*;
    use crate::c14n::{C14nAlgorithm, C14nMode, canonicalize_with_visibility};
    use crate::xmldsig::TransformData;
    use roxmltree::Document;

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
        // unrelated source document that exceeds the node-set materialization cap.
        let xml = format!(
            "<root><target Id=\"selected\"><child/></target>{}</root>",
            "<outside/>".repeat(65_537)
        );
        let document = Document::parse(&xml).expect("fixed oversized fixture must parse");
        let target = document
            .descendants()
            .find(|node| node.attribute("Id") == Some("selected"))
            .expect("fixed fixture contains selected subtree");

        let error = apply_xpath_filter(
            NodeSet::subtree(target).expect("selected subtree fits the node-set budget"),
            &XPathExpression::new("true()"),
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
                &input,
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

    fn built_mirror_string_bytes(mirror: &Mirror<'_>) -> usize {
        let mut bytes = 0_usize;
        for element in mirror.elements.keys() {
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
        bytes += mirror
            .texts
            .keys()
            .map(|text| text.text().len())
            .sum::<usize>();
        bytes += mirror
            .comments
            .keys()
            .map(|comment| comment.text().len())
            .sum::<usize>();
        bytes += mirror
            .processing_instructions
            .keys()
            .map(|pi| pi.target().len() + pi.value().map_or(0, |value| value.len()))
            .sum::<usize>();
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

        let projected_bytes = Mirror::projected_string_bytes(&document)
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
            remaining: Rc::new(Cell::new(MAX_XPATH_CUMULATIVE_EVALUATION_WORK)),
            evaluation_limit_exceeded: Rc::new(Cell::new(false)),
            mirror_bytes_remaining: Rc::new(Cell::new(MAX_XPATH_MIRROR_STRING_BYTES)),
            string_work_bytes_remaining: Rc::new(Cell::new(one_scan_work)),
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
            remaining: Rc::new(Cell::new(MAX_XPATH_CUMULATIVE_EVALUATION_WORK)),
            evaluation_limit_exceeded: Rc::new(Cell::new(false)),
            mirror_bytes_remaining: Rc::new(Cell::new(MAX_XPATH_MIRROR_STRING_BYTES)),
            string_work_bytes_remaining: Rc::new(Cell::new(one_scan_work)),
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
            remaining: Rc::new(Cell::new(MAX_XPATH_CUMULATIVE_EVALUATION_WORK)),
            evaluation_limit_exceeded: Rc::new(Cell::new(false)),
            mirror_bytes_remaining: Rc::new(Cell::new(MAX_XPATH_MIRROR_STRING_BYTES)),
            string_work_bytes_remaining: Rc::new(Cell::new(one_scan_work)),
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
            remaining: Rc::new(Cell::new(MAX_XPATH_CUMULATIVE_EVALUATION_WORK)),
            evaluation_limit_exceeded: Rc::new(Cell::new(false)),
            mirror_bytes_remaining: Rc::new(Cell::new(MAX_XPATH_MIRROR_STRING_BYTES)),
            string_work_bytes_remaining: Rc::new(Cell::new(one_scan_work)),
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
        // sxd-xpath-no-unsafe 0.5.1 hashes each node-set's string values before
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
