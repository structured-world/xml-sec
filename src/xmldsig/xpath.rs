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
    MAX_XPATH_EXPRESSION_BYTES, MAX_XPATH_FILTERS, XPathExpression, XPathFilter,
    XPathFilterOperation, XPathHereSemantics,
};
use super::types::{NodeSet, TransformError};
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
const MAX_XPATH_CONTEXT_EVALUATIONS: usize = 4_096;
/// Bound conservative XPath evaluator node visits across one signature.
const MAX_XPATH_CUMULATIVE_EVALUATION_WORK: usize = 6_000_000;
/// Bound operators, names, literals, and path punctuation in one expression.
const MAX_XPATH_EXPRESSION_COMPLEXITY: usize = 256;
/// Namespace URI permanently bound to the reserved `xml` prefix.
const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

#[derive(Clone)]
pub(super) struct XPathWorkBudget {
    remaining: Rc<Cell<usize>>,
}

impl Default for XPathWorkBudget {
    fn default() -> Self {
        Self {
            remaining: Rc::new(Cell::new(MAX_XPATH_CUMULATIVE_EVALUATION_WORK)),
        }
    }
}

impl XPathWorkBudget {
    #[cfg(test)]
    pub(super) fn with_limit(limit: usize) -> Self {
        Self {
            remaining: Rc::new(Cell::new(limit)),
        }
    }

    fn charge(&self, work: usize) -> Result<(), TransformError> {
        let remaining = self.remaining.get();
        let Some(next) = remaining.checked_sub(work) else {
            self.remaining.set(0);
            return Err(TransformError::XPath(format!(
                "XPath transform exceeds signature-wide cumulative evaluation work budget of \
                 {MAX_XPATH_CUMULATIVE_EVALUATION_WORK} node-evaluations"
            )));
        };
        self.remaining.set(next);
        Ok(())
    }

    fn charge_function(&self, work: usize) -> Result<(), function::Error> {
        self.charge(work).map_err(|error| function::Error::Other {
            what: error.to_string(),
        })
    }
}

/// SXD's tokenizer rejects otherwise valid whitespace between a function QName
/// and `(`. Normalize only that token boundary, preserving quoted literals and
/// all whitespace that can affect string values or operator tokenization.
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
        if quote.is_none() && character.is_whitespace() {
            let whitespace_start = index;
            while index < chars.len() && chars[index].is_whitespace() {
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

pub(super) fn compile_xpath(source: &str) -> Result<sxd_xpath_no_unsafe::XPath, String> {
    if source.is_empty() || source.len() > MAX_XPATH_EXPRESSION_BYTES {
        return Err(format!(
            "XPath expression length must be between 1 and {MAX_XPATH_EXPRESSION_BYTES} bytes"
        ));
    }
    if xpath_expression_complexity(source) > MAX_XPATH_EXPRESSION_COMPLEXITY {
        return Err(format!(
            "XPath expression complexity exceeds {MAX_XPATH_EXPRESSION_COMPLEXITY} tokens"
        ));
    }
    Factory::new()
        .build(&normalize_function_spacing(source))
        .map_err(|error| error.to_string())
}

fn xpath_expression_complexity(source: &str) -> usize {
    let mut chars = source.chars().peekable();
    let mut tokens = 0_usize;
    while let Some(character) = chars.next() {
        if character.is_whitespace() {
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

/// Estimate one XPath evaluation before entering SXD's non-interruptible engine.
///
/// One top-level traversal is covered by the baseline document-size charge. A
/// traversal inside a predicate can run once per node selected by every enclosing
/// predicate, so its worst-case cost gains one document-size factor per level.
/// Saturation deliberately turns arithmetic overflow into a budget rejection.
fn xpath_evaluation_work(source: &str, document_size: usize) -> usize {
    let bytes = source.as_bytes();
    let mut work = document_size;
    let mut predicate_depth = 0_usize;
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
            b'[' => predicate_depth = predicate_depth.saturating_add(1),
            b']' => predicate_depth = predicate_depth.saturating_sub(1),
            b'/' if predicate_depth > 0 => {
                work = work.saturating_add(nested_traversal_work(document_size, predicate_depth));
                if bytes.get(index + 1) == Some(&b'/') {
                    index += 1;
                }
            }
            b':' if predicate_depth > 0 && bytes.get(index + 1) == Some(&b':') => {
                let mut axis_start = index;
                while axis_start > 0 && is_xpath_name_byte(bytes[axis_start - 1]) {
                    axis_start -= 1;
                }
                if is_document_scanning_axis(&source[axis_start..index]) {
                    work =
                        work.saturating_add(nested_traversal_work(document_size, predicate_depth));
                }
                index += 1;
            }
            _ => {}
        }
        index += 1;
    }

    work
}

fn nested_traversal_work(document_size: usize, predicate_depth: usize) -> usize {
    (0..=predicate_depth).fold(1_usize, |work, _| work.saturating_mul(document_size))
}

fn is_xpath_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
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

impl<'d> Mirror<'d> {
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
                // roxmltree, like XPath's data model, does not expose
                // whitespace outside the document element as a root child.
                // Every source text node therefore has an element parent and
                // retains the same child index in the SXD mirror.
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
        expand_subtrees: bool,
    ) -> NodeSet<'a> {
        let mut result = NodeSet::empty(source);
        for node in selected.document_order() {
            match node {
                nodeset::Node::Root(_) => {
                    if expand_subtrees {
                        result.insert_subtree(source.root());
                    } else {
                        result.insert_node(source.root());
                    }
                }
                nodeset::Node::Element(element) => {
                    if let Some(source_node) = self.source_node(source, self.elements.get(&element))
                    {
                        if expand_subtrees {
                            result.insert_subtree(source_node);
                        } else {
                            result.insert_node(source_node);
                        }
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
                    result.insert_attribute(source_parent, name.namespace_uri(), name.local_part());
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
                        result.insert_namespace(source_parent, namespace.prefix(), namespace.uri());
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
        result
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

struct LangFunction;

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

fn evaluate_expression<'a>(
    input: &NodeSet<'a>,
    expression: &XPathExpression,
    wrap_as_filter: bool,
    here_semantics: XPathHereSemantics,
    document_relation: XPathDocumentRelation,
    work_budget: &XPathWorkBudget,
) -> Result<NodeSet<'a>, TransformError> {
    let document = input.document();
    let document_size = NodeSet::ensure_subtree_materialization_fits(document.root())?;
    // Mirroring duplicates the complete source document and builds lookup maps;
    // charge it before allocating the secondary DOM.
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
                    here_path(document, expression.here_node(here_semantics))
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
    context.set_function("lang", LangFunction);

    let xpath = compile_xpath(expression.expression()).map_err(TransformError::XPath)?;
    let evaluation_work = xpath_evaluation_work(expression.expression(), document_size);

    if wrap_as_filter {
        // XMLDSig evaluates the expression independently for every input node;
        // XPath::evaluate establishes position=1 and size=1 for each call.
        let all_nodes_xpath = Factory::new()
            .build(ALL_XPATH_NODES)
            .map_err(|error| TransformError::XPath(error.to_string()))?;
        work_budget.charge(document_size)?;
        let all_nodes = all_nodes_xpath
            .evaluate(&context, target.root())
            .map_err(|error| TransformError::XPath(error.to_string()))?;
        let Value::Nodeset(all_nodes) = all_nodes else {
            unreachable!("the fixed all-nodes XPath expression returns a node-set");
        };
        let all_ordered_nodes = all_nodes.document_order();
        let ordered_nodes = all_ordered_nodes
            .into_iter()
            .filter(|node| mirror.input_contains(document, input, node))
            .collect::<Vec<_>>();
        if ordered_nodes.len() > MAX_XPATH_CONTEXT_EVALUATIONS {
            return Err(TransformError::XPath(format!(
                "XPath transform input exceeds {MAX_XPATH_CONTEXT_EVALUATIONS} per-node evaluations"
            )));
        }
        let mut selected = nodeset::Nodeset::new();
        for node in ordered_nodes {
            // SXD exposes no interrupt hook. Charge nested predicate scans
            // before execution so they cannot hide cubic work inside one call.
            work_budget.charge(evaluation_work)?;
            let include = xpath
                .evaluate(&context, node.clone())
                .map_err(|error| TransformError::XPath(error.to_string()))?
                .into_boolean();
            if include {
                selected.add(node);
            }
        }
        return Ok(mirror.project(document, selected, false));
    }

    work_budget.charge(evaluation_work)?;
    let value = xpath
        .evaluate(&context, target.root())
        .map_err(|error| TransformError::XPath(error.to_string()))?;
    let Value::Nodeset(selected) = value else {
        return Err(TransformError::XPath(
            "XPath Filter 2.0 expression must return a node-set".into(),
        ));
    };
    Ok(mirror.project(document, selected, !wrap_as_filter))
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

pub(super) fn apply_xpath_filter_with_semantics<'a>(
    mut input: NodeSet<'a>,
    expression: &XPathExpression,
    here_semantics: XPathHereSemantics,
    document_relation: XPathDocumentRelation,
    work_budget: &XPathWorkBudget,
) -> Result<NodeSet<'a>, TransformError> {
    let selected = evaluate_expression(
        &input,
        expression,
        true,
        here_semantics,
        document_relation,
        work_budget,
    )?;
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

pub(super) fn apply_xpath_filter2_with_semantics<'a>(
    input: NodeSet<'a>,
    filters: &[XPathFilter],
    here_semantics: XPathHereSemantics,
    document_relation: XPathDocumentRelation,
    work_budget: &XPathWorkBudget,
) -> Result<NodeSet<'a>, TransformError> {
    if filters.is_empty() || filters.len() > MAX_XPATH_FILTERS {
        return Err(TransformError::XPath(format!(
            "XPath Filter 2.0 requires between 1 and {MAX_XPATH_FILTERS} expressions"
        )));
    }
    let mut result = NodeSet::try_entire_document(input.document())?;
    for filter in filters {
        let selected = evaluate_expression(
            &input,
            filter.xpath(),
            false,
            here_semantics,
            document_relation,
            work_budget,
        )?;
        match filter.operation() {
            XPathFilterOperation::Intersect => result.intersect_with(&selected),
            XPathFilterOperation::Subtract => result.subtract(&selected),
            XPathFilterOperation::Union => result.union_with(&selected),
        }
    }
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
    fn xpath_filter_evaluates_position_and_size_per_input_node() {
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

        assert!(matches!(error, TransformError::XPath(_)));
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

        assert!(matches!(error, TransformError::NodeSetTooLarge { .. }));
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

        assert!(error.to_string().contains("cumulative evaluation work"));
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

        assert!(error.to_string().contains("cumulative evaluation work"));
    }

    #[test]
    fn xpath_work_profile_tracks_nested_paths_but_ignores_literals() {
        // The preflight meter must recognize both abbreviated paths and named
        // axes without treating XPath punctuation inside quoted data as work.
        assert_eq!(xpath_evaluation_work("//*[count(//*) > 0]", 10), 110);
        assert_eq!(xpath_evaluation_work("//*[ancestor::*]", 10), 110);
        assert_eq!(
            xpath_evaluation_work("//*[contains(., '//ancestor::*')]", 10),
            10
        );
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

        assert!(error.to_string().contains("signature-wide"));
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

        assert!(error.to_string().contains("complexity"));
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
    fn xpath_here_function_uses_xpath_element() {
        // XMLDSig defines here() as the parent of the text node that directly
        // bears the expression, which is the XPath parameter element.
        let xml = r#"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><data/><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>count(. | here()) = 1</ds:XPath></ds:Transform></root>"#;
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
