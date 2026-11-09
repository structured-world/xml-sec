//! `XPath` selection over a tree-backed document.
//!
//! A compatibility layer that keeps its own node sets over the caller's tree
//! (for example libxmlsec1's `xmlSecNodeSet`) evaluates expressions here and
//! receives the selected nodes as the external nodes they were projected from.
//! Evaluation is the engine of the `XPath` transforms, with the same function
//! library and resource budgets.

use alloc::vec::Vec;

use super::transforms::{ExpressionParameter, XPathExpression, XPathHereSemantics};
use super::types::{NodeSet, NodeSetMaterializationBudget, TransformError};
use super::xpath::{XPathRequestContext, XPathWorkBudget, select_projection};
use crate::document::external::ExternalNode;
use crate::sxd_document::XmlChar;
use crate::xml::IdAttributeRegistration;
use crate::xml::dom::NodeId;

/// How an expression's result becomes a node set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XPathForm {
    /// Every node of the document for which the expression, evaluated with
    /// that node as context, is true (`XMLDSig` 1.1 section 6.6.3).
    /// <https://www.w3.org/TR/xmldsig-core1/#sec-XPath>
    EachNode,
    /// The node-set the expression evaluates to from the document root, each
    /// node as itself (`XPath` Filter 2.0 section 3.3 before its subtree
    /// expansion, and `XPointer`'s `xpointer()` scheme).
    NodeSet,
}

/// One selected node, as the external tree knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectedNode<'a> {
    /// A document, element, text, comment or processing-instruction node.
    Node(ExternalNode),
    /// An attribute node of `owner`.
    Attribute {
        /// The element carrying the attribute.
        owner: ExternalNode,
        /// Namespace URI of the attribute name.
        namespace: Option<&'a str>,
        /// Local part of the attribute name.
        local_name: &'a str,
    },
    /// A namespace node of `owner`: one in-scope binding, declared on `owner`
    /// or an ancestor.
    Namespace {
        /// The element whose namespace axis holds the binding.
        owner: ExternalNode,
        /// Bound prefix; `None` for the default namespace.
        prefix: Option<&'a str>,
        /// Namespace URI.
        uri: &'a str,
    },
}

/// Evaluate `expression` over the document of `view` and return the selected
/// nodes in document order (an element, then its namespace nodes, then its
/// attributes).
///
/// `here` is the node `here()` returns; `registrations` declares the ID
/// attributes `id()` matches. Work, node-set size and copied strings are bound
/// by `resources` as for an `XPath` transform.
///
/// # Errors
/// An invalid expression, a scalar result for [`XPathForm::NodeSet`], a `here`
/// node outside the document, or an exhausted resource limit. A selected node
/// that an entity expansion produced has no external node and is refused.
pub fn select_xpath<'a>(
    view: crate::DocumentView<'a>,
    expression: &XPathExpression,
    here: Option<ExternalNode>,
    form: XPathForm,
    registrations: &[IdAttributeRegistration],
    resources: &crate::policy::ResourcePolicy,
) -> Result<Vec<SelectedNode<'a>>, TransformError> {
    let document = view.document();
    let here = match here {
        Some(external) => Some(
            view.node_of_external(external)
                .ok_or(TransformError::CrossDocumentNodeSetInput)?
                .id(),
        ),
        None => None,
    };
    let materialization = NodeSetMaterializationBudget::with_limits(
        resources.max_node_set_entries,
        resources.max_node_set_owned_string_bytes,
        resources.max_node_set_cumulative_owned_string_bytes,
    );
    let input = NodeSet::projected(document.root(), true, Some(&materialization))?;
    let selected = select_projection(
        &input.projection,
        &Located { expression, here },
        matches!(form, XPathForm::EachNode),
        XPathRequestContext::new(XPathHereSemantics::default(), registrations),
        &XPathWorkBudget::with_limits(resources),
        &materialization,
    )?;
    let selected = NodeSet {
        projection: selected,
    };
    let external = |node| {
        view.external_node_of(node)
            .ok_or(TransformError::CrossDocumentNodeSetInput)
    };
    let mut nodes = Vec::new();
    for node in document.root().descendants() {
        if selected.contains(node) {
            nodes.push(SelectedNode::Node(external(node)?));
        }
        if !node.is_element() {
            continue;
        }
        for namespace in node.namespaces() {
            if selected.contains_namespace(node, namespace.name().unwrap_or(""), namespace.uri()) {
                nodes.push(SelectedNode::Namespace {
                    owner: external(node)?,
                    prefix: namespace.name(),
                    uri: namespace.uri(),
                });
            }
        }
        for attribute in node.attributes() {
            if selected.contains_attribute(node, attribute.namespace(), attribute.name()) {
                nodes.push(SelectedNode::Attribute {
                    owner: external(node)?,
                    namespace: attribute.namespace(),
                    local_name: attribute.name(),
                });
            }
        }
    }
    Ok(nodes)
}

/// Evaluate an `XPointer` over the document of `view` (`XPointer` Framework
/// section 3.3): its pointer parts left to right, the first that identifies a
/// non-empty node set gives the result. A shorthand pointer and the
/// `element()` scheme name an element by ID or child sequence, `xmlns()` binds
/// a prefix for the parts after it, `xpointer()` is an `XPath` expression read
/// as a node-set, and parts of any other scheme identify nothing.
/// <https://www.w3.org/TR/2003/REC-xptr-framework-20030325/#processing>
///
/// `namespaces` are bindings in scope before the first part, `here` and
/// `registrations` are as for [`select_xpath`].
///
/// # Errors
/// A pointer that identifies nothing (Framework section 3.3: a shorthand
/// naming no element, or no part identifying a subresource), one that breaks
/// the Framework grammar, an invalid `element()` child sequence, an
/// `xpointer()` part [`select_xpath`] refuses, or an exhausted resource limit.
pub fn select_xpointer<'a>(
    view: crate::DocumentView<'a>,
    pointer: &str,
    namespaces: &[(&str, &str)],
    here: Option<ExternalNode>,
    registrations: &[IdAttributeRegistration],
    resources: &crate::policy::ResourcePolicy,
) -> Result<Vec<SelectedNode<'a>>, TransformError> {
    let invalid = || TransformError::XPath("invalid XPointer".into());
    let nothing = || TransformError::XPath("the XPointer identifies nothing".into());
    let mut bindings = XPathExpression::new("");
    for (prefix, uri) in namespaces {
        bindings = bindings.with_namespace(*prefix, *uri);
    }
    let pointer = pointer.trim_matches(is_xml_space);
    if is_ncname(pointer) {
        // An NCName holds no quote, so the literal is always well formed.
        let expression = XPathExpression::new(alloc::format!("id('{pointer}')"));
        let nodes = select_xpath(
            view,
            &expression,
            here,
            XPathForm::NodeSet,
            registrations,
            resources,
        )?;
        return if nodes.is_empty() {
            Err(nothing())
        } else {
            Ok(nodes)
        };
    }
    let mut rest = pointer;
    while !rest.is_empty() {
        let open = rest.find('(').ok_or_else(invalid)?;
        let scheme = &rest[..open];
        let (data, after) = scheme_data(&rest[open + 1..]).ok_or_else(invalid)?;
        rest = after.trim_start_matches(is_xml_space);
        let expression = match scheme {
            "xmlns" => {
                let (prefix, uri) = data.split_once('=').ok_or_else(invalid)?;
                let prefix = prefix.trim_matches(is_xml_space);
                if !is_ncname(prefix) {
                    return Err(invalid());
                }
                bindings = bindings.with_namespace(prefix, uri.trim_matches(is_xml_space));
                continue;
            }
            "xpointer" => data,
            "element" => element_path(&data).ok_or_else(invalid)?,
            _ if is_qname(scheme) => continue,
            _ => return Err(invalid()),
        };
        let mut part = XPathExpression::new(expression);
        for (prefix, uri) in bindings.namespaces() {
            part = part.with_namespace(prefix.as_str(), uri.as_str());
        }
        let nodes = select_xpath(
            view,
            &part,
            here,
            XPathForm::NodeSet,
            registrations,
            resources,
        )?;
        if !nodes.is_empty() {
            return Ok(nodes);
        }
    }
    Err(nothing())
}

/// Unescaped scheme data up to its balancing `)`, and the text after it
/// (`XPointer` Framework section 3.1 [7]: `^(`, `^)` and `^^` escape).
fn scheme_data(text: &str) -> Option<(alloc::string::String, &str)> {
    let mut data = alloc::string::String::new();
    let mut depth = 0usize;
    let mut characters = text.char_indices();
    while let Some((position, character)) = characters.next() {
        match character {
            '^' => match characters.next() {
                Some((_, escaped @ ('(' | ')' | '^'))) => data.push(escaped),
                _ => return None,
            },
            '(' => {
                depth += 1;
                data.push('(');
            }
            ')' if depth == 0 => return Some((data, &text[position + 1..])),
            ')' => {
                depth -= 1;
                data.push(')');
            }
            other => data.push(other),
        }
    }
    None
}

/// The `XPath` an `element()` child sequence names (`XPointer` `element()`
/// Scheme section 3): an optional leading `NCName` ID, then `/n` steps.
/// <https://www.w3.org/TR/2003/REC-xptr-element-20030325/#syntax>
fn element_path(data: &str) -> Option<alloc::string::String> {
    let (id, steps) = match data.find('/') {
        Some(slash) => (&data[..slash], &data[slash..]),
        None => (data, ""),
    };
    let mut path = if id.is_empty() {
        alloc::string::String::new()
    } else if is_ncname(id) {
        // An NCName holds no quote, so the literal is always well formed.
        alloc::format!("id('{id}')")
    } else {
        return None;
    };
    if id.is_empty() && steps.is_empty() {
        return None;
    }
    for step in steps.split('/').skip(1) {
        let first = step.bytes().next()?;
        if !(b'1'..=b'9').contains(&first) || !step.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        path.push_str("/*[");
        path.push_str(step);
        path.push(']');
    }
    Some(path)
}

fn is_xml_space(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\n' | '\r')
}

/// `NCName` of Namespaces in XML 1.0 section 3, over the XML 1.0 fifth
/// edition name characters.
/// <https://www.w3.org/TR/xml-names/#NT-NCName>
fn is_ncname(text: &str) -> bool {
    let mut characters = text.chars();
    characters.next().is_some_and(XmlChar::is_ncname_start_char)
        && characters.all(XmlChar::is_ncname_char)
}

fn is_qname(text: &str) -> bool {
    match text.split_once(':') {
        Some((prefix, local)) => is_ncname(prefix) && is_ncname(local),
        None => is_ncname(text),
    }
}

/// An expression located at an explicit `here()` node of the evaluated
/// document; both `here()` semantics name that node.
struct Located<'e> {
    expression: &'e XPathExpression,
    here: Option<NodeId>,
}

impl ExpressionParameter for Located<'_> {
    fn expression(&self) -> &str {
        self.expression.expression()
    }

    fn namespaces(&self) -> impl Iterator<Item = (&str, &str)> {
        self.expression
            .namespaces()
            .iter()
            .map(|(prefix, uri)| (prefix.as_str(), uri.as_str()))
    }

    fn here_context_node(&self, _: XPathHereSemantics) -> Option<NodeId> {
        self.here
    }

    fn parsed_document_identity(&self) -> Option<super::transforms::XPathDocumentIdentity> {
        None
    }
}

#[cfg(test)]
mod tests;
