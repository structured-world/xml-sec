//! Transform pipeline for XMLDSig `<Reference>` processing.
//!
//! Implements [XMLDSig §6.6](https://www.w3.org/TR/xmldsig-core1/#sec-Transforms):
//! each `<Reference>` specifies a chain of transforms applied sequentially to
//! produce bytes for digest computation.
//!
//! The pipeline is a simple `Vec<Transform>` iterated front-to-back — a dramatic
//! simplification of xmlsec1's bidirectional push/pop doubly-linked list with
//! auto-inserted type adapters.
//!
//! ## Supported transforms
//!
//! | Transform | Direction | Priority |
//! |-----------|-----------|----------|
//! | Enveloped signature | NodeSet → NodeSet | P0 (SAML) |
//! | Inclusive C14N 1.0/1.1 | NodeSet → Binary | P0 |
//! | Exclusive C14N 1.0 | NodeSet → Binary | P0 |
//! | Base64 decode | NodeSet/Binary → Binary | P1 |
//! | XPath 1.0 | NodeSet → NodeSet | P1 |
//! | XPath Filter 2.0 | NodeSet → NodeSet | P1 |

use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use roxmltree::Node;

use super::parse::XMLDSIG_NS;
use super::types::{TransformData, TransformError};
use super::whitespace::{is_xml_whitespace_only, normalize_xml_base64_bytes};
use super::xpath::{
    apply_xpath_filter_with_semantics, apply_xpath_filter2_with_semantics,
    normalize_function_spacing,
};
use crate::c14n::{self, C14nAlgorithm};

/// The algorithm URI for the enveloped signature transform.
pub const ENVELOPED_SIGNATURE_URI: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
/// The algorithm URI for the Base64 decode transform.
pub const BASE64_TRANSFORM_URI: &str = "http://www.w3.org/2000/09/xmldsig#base64";
/// The algorithm URI for the XPath 1.0 transform.
pub const XPATH_TRANSFORM_URI: &str = "http://www.w3.org/TR/1999/REC-xpath-19991116";
/// The algorithm URI for the XPath Filter 2.0 transform.
pub const XPATH_FILTER2_TRANSFORM_URI: &str = "http://www.w3.org/2002/06/xmldsig-filter2";
/// The implicit default canonicalization URI applied when no explicit C14N
/// transform is present in a `<Reference>`.
pub const DEFAULT_IMPLICIT_C14N_URI: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
/// Maximum transforms accepted for one reference.
///
/// Execution retains one stack frame when a binary-to-node-set adapter parses
/// temporary XML, so bounding the chain also bounds stack and retained input.
pub const MAX_TRANSFORMS_PER_REFERENCE: usize = 64;
/// xmlsec1 donor vectors use this XPath expression as a compatibility form of
/// enveloped-signature exclusion.
const ENVELOPED_SIGNATURE_XPATH_EXPR: &str = "not(ancestor-or-self::dsig:Signature)";
pub(super) const MAX_XPATH_EXPRESSION_BYTES: usize = 16 * 1024;
pub(super) const MAX_XPATH_FILTERS: usize = 64;

/// Namespace URI for Exclusive C14N `<InclusiveNamespaces>` elements.
const EXCLUSIVE_C14N_NS_URI: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

/// Node returned by the XMLDSig XPath `here()` extension function.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum XPathHereSemantics {
    /// Follow XMLDSig: return the `<XPath>` parameter element that contains
    /// the expression text.
    #[default]
    Specification,
    /// Match libxmlsec1, which returns the owning `<Transform>` element.
    ///
    /// This mode is opt-in because the two interpretations can select
    /// different data for the same signed XML document.
    XmlSecLegacy,
}

/// Options controlling execution of an XMLDSig transform chain.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransformOptions {
    xpath_here_semantics: XPathHereSemantics,
}

impl TransformOptions {
    /// Select the node returned by the XPath `here()` extension function.
    #[must_use]
    pub fn xpath_here_semantics(mut self, semantics: XPathHereSemantics) -> Self {
        self.xpath_here_semantics = semantics;
        self
    }

    pub(crate) fn here_semantics(self) -> XPathHereSemantics {
        self.xpath_here_semantics
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct XPathHereNodes {
    xpath: roxmltree::NodeId,
    transform: roxmltree::NodeId,
}

/// An XPath 1.0 expression and the namespace bindings in scope where it was declared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XPathExpression {
    expression: String,
    namespaces: BTreeMap<String, String>,
    here_nodes: Option<XPathHereNodes>,
}

impl XPathExpression {
    /// Create an expression for signature-template generation.
    pub fn new(expression: impl Into<String>) -> Self {
        Self {
            expression: expression.into(),
            namespaces: BTreeMap::new(),
            here_nodes: None,
        }
    }

    /// Bind a prefix used by this XPath expression.
    pub fn with_namespace(mut self, prefix: impl Into<String>, uri: impl Into<String>) -> Self {
        self.namespaces.insert(prefix.into(), uri.into());
        self
    }

    /// XPath source text.
    pub fn expression(&self) -> &str {
        &self.expression
    }

    /// Namespace prefix bindings used during evaluation.
    pub fn namespaces(&self) -> &BTreeMap<String, String> {
        &self.namespaces
    }

    pub(crate) fn here_node(&self, semantics: XPathHereSemantics) -> Option<roxmltree::NodeId> {
        self.here_nodes.map(|nodes| match semantics {
            XPathHereSemantics::Specification => nodes.xpath,
            XPathHereSemantics::XmlSecLegacy => nodes.transform,
        })
    }
}

/// Set operation applied by one XPath Filter 2.0 step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XPathFilterOperation {
    /// Keep only nodes in the selected subtrees.
    Intersect,
    /// Remove nodes in the selected subtrees.
    Subtract,
    /// Add nodes in the selected subtrees.
    Union,
}

impl XPathFilterOperation {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Intersect => "intersect",
            Self::Subtract => "subtract",
            Self::Union => "union",
        }
    }
}

/// One expression and set operation in an XPath Filter 2.0 transform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XPathFilter {
    operation: XPathFilterOperation,
    xpath: XPathExpression,
}

impl XPathFilter {
    /// Create a Filter 2.0 step.
    pub fn new(operation: XPathFilterOperation, xpath: XPathExpression) -> Self {
        Self { operation, xpath }
    }

    /// Operation applied to the subtree-expanded expression result.
    pub fn operation(&self) -> XPathFilterOperation {
        self.operation
    }

    /// XPath expression evaluated by this step.
    pub fn xpath(&self) -> &XPathExpression {
        &self.xpath
    }
}

/// A single transform in the pipeline.
#[derive(Debug, Clone)]
pub enum Transform {
    /// Enveloped signature: removes the `<Signature>` element subtree
    /// that contains the `<Reference>` being processed.
    ///
    /// Input: `NodeSet` → Output: `NodeSet`
    Enveloped,

    /// Narrow XPath compatibility form used by some donor vectors:
    /// `not(ancestor-or-self::dsig:Signature)`.
    ///
    /// Unlike `Enveloped`, this excludes every `ds:Signature` subtree in the
    /// current document, not only the containing signature.
    XpathExcludeAllSignatures,

    /// General XMLDSig XPath 1.0 node filter.
    XPath(XPathExpression),

    /// XPath Filter 2.0 ordered subtree set operations.
    XPathFilter2(Vec<XPathFilter>),

    /// XML Canonicalization (any supported variant).
    ///
    /// Input: `NodeSet` → Output: `Binary`
    C14n(C14nAlgorithm),

    /// Decode base64 text into the octets consumed by the next transform or digest.
    ///
    /// Node-set input is converted by concatenating included text nodes in
    /// document order, as required by XMLDSig section 6.6.2. Binary input is
    /// decoded directly.
    ///
    /// Input: `NodeSet` or `Binary` → Output: `Binary`
    Base64Decode,
}

/// Apply a single transform to the pipeline data.
///
/// `signature_node` is the `<Signature>` element that contains the
/// `<Reference>` being processed. It is used by the enveloped transform
/// to know which signature subtree to exclude. The node must belong to the
/// same document as the `NodeSet` in `input`; a cross-document mismatch
/// returns [`TransformError::CrossDocumentSignatureNode`].
#[cfg(test)]
pub(crate) fn apply_transform<'a>(
    signature_node: Node<'a, 'a>,
    transform: &Transform,
    input: TransformData<'a>,
) -> Result<TransformData<'a>, TransformError> {
    apply_transform_with_options(
        signature_node,
        transform,
        input,
        TransformOptions::default(),
    )
}

pub(super) fn apply_transform_with_options<'s, 'd>(
    signature_node: Node<'s, 's>,
    transform: &Transform,
    input: TransformData<'d>,
    options: TransformOptions,
) -> Result<TransformData<'d>, TransformError> {
    match transform {
        Transform::Enveloped => {
            let mut nodes = input.into_node_set()?;
            // Exclude the Signature element and all its descendants from
            // the node set. This is the core mechanism of the enveloped
            // signature transform: the digest is computed as if the
            // <Signature> were not present in the document.
            //
            // xmlsec1 equivalent:
            //   xmlSecNodeSetGetChildren(doc, signatureNode, 1, 1)  // inverted tree
            //   xmlSecNodeSetAdd(inNodes, children, Intersection)   // intersect = subtract
            if !std::ptr::eq(signature_node.document(), nodes.document()) {
                return Err(TransformError::CrossDocumentSignatureNode);
            }
            nodes.exclude_subtree(signature_node);
            Ok(TransformData::NodeSet(nodes))
        }
        Transform::XpathExcludeAllSignatures => {
            let mut nodes = input.into_node_set()?;
            let doc = nodes.document();

            for node in doc.descendants().filter(|node| {
                node.is_element()
                    && node.tag_name().name() == "Signature"
                    && node.tag_name().namespace() == Some(XMLDSIG_NS)
            }) {
                nodes.exclude_subtree(node);
            }

            Ok(TransformData::NodeSet(nodes))
        }
        Transform::XPath(xpath) => {
            let nodes = input.into_node_set()?;
            let here_is_same_document = std::ptr::eq(signature_node.document(), nodes.document());
            Ok(TransformData::NodeSet(apply_xpath_filter_with_semantics(
                nodes,
                xpath,
                options.here_semantics(),
                here_is_same_document,
            )?))
        }
        Transform::XPathFilter2(filters) => {
            let nodes = input.into_node_set()?;
            let here_is_same_document = std::ptr::eq(signature_node.document(), nodes.document());
            Ok(TransformData::NodeSet(apply_xpath_filter2_with_semantics(
                nodes,
                filters,
                options.here_semantics(),
                here_is_same_document,
            )?))
        }
        Transform::C14n(algo) => {
            let nodes = input.into_node_set()?;
            let mut output = Vec::new();
            c14n::canonicalize_with_visibility(nodes.document(), Some(&nodes), algo, &mut output)?;
            Ok(TransformData::Binary(output))
        }
        Transform::Base64Decode => {
            let mut normalized = Vec::new();
            match input {
                TransformData::Binary(bytes) => {
                    normalized.reserve(bytes.len());
                    append_normalized_base64(&bytes, &mut normalized)?;
                }
                TransformData::NodeSet(nodes) => {
                    for node in nodes.document().descendants() {
                        if nodes.contains(node) && node.is_text() {
                            append_normalized_base64(
                                node.text().unwrap_or_default().as_bytes(),
                                &mut normalized,
                            )?;
                        }
                    }
                }
            }
            Ok(TransformData::Binary(decode_base64_transform(normalized)?))
        }
    }
}

/// Decode the RFC 2045 alphabet accepted by xmlsec1's Base64 transform.
///
/// XML whitespace is insignificant in XMLDSig Base64 data. Other bytes are
/// rejected rather than ignored so malformed signed content cannot acquire
/// multiple textual representations with different application meaning.
fn append_normalized_base64(
    encoded: &[u8],
    normalized: &mut Vec<u8>,
) -> Result<(), TransformError> {
    normalize_xml_base64_bytes(encoded, normalized, |byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
    })
    .map_err(|err| {
        TransformError::Base64(format!(
            "invalid byte 0x{:02X} in encoded input",
            err.invalid_byte
        ))
    })
}

fn decode_base64_transform(normalized: Vec<u8>) -> Result<Vec<u8>, TransformError> {
    STANDARD
        .decode(normalized)
        .map_err(|error| TransformError::Base64(error.to_string()))
}

/// Execute a chain of transforms for a single `<Reference>`.
///
/// 1. Start with `initial_data` (from URI dereference).
/// 2. Apply each transform sequentially.
/// 3. If the result is still a `NodeSet`, apply default inclusive C14N 1.0
///    to produce bytes (per [XMLDSig §4.3.3.2](https://www.w3.org/TR/xmldsig-core1/#sec-ReferenceProcessingModel)).
///
/// Returns the final byte sequence ready for digest computation.
pub fn execute_transforms<'a>(
    signature_node: Node<'a, 'a>,
    initial_data: TransformData<'a>,
    transforms: &[Transform],
) -> Result<Vec<u8>, TransformError> {
    execute_transforms_with_options(
        signature_node,
        initial_data,
        transforms,
        TransformOptions::default(),
    )
}

/// Execute a transform chain with explicit compatibility options.
pub fn execute_transforms_with_options<'a>(
    signature_node: Node<'a, 'a>,
    initial_data: TransformData<'a>,
    transforms: &[Transform],
    options: TransformOptions,
) -> Result<Vec<u8>, TransformError> {
    ensure_transform_count(transforms.len())?;
    execute_transform_chain(signature_node, initial_data, transforms, options)
}

fn ensure_transform_count(count: usize) -> Result<(), TransformError> {
    if count > MAX_TRANSFORMS_PER_REFERENCE {
        return Err(TransformError::TooManyTransforms {
            max: MAX_TRANSFORMS_PER_REFERENCE,
        });
    }
    Ok(())
}

fn execute_transform_chain<'s, 'd>(
    signature_node: Node<'s, 's>,
    data: TransformData<'d>,
    transforms: &[Transform],
    options: TransformOptions,
) -> Result<Vec<u8>, TransformError> {
    let Some((transform, remaining)) = transforms.split_first() else {
        return finalize_transform_data(data);
    };

    if transform_requires_node_set(transform)
        && let TransformData::Binary(bytes) = data
    {
        // The parsed document must outlive every remaining node-set transform.
        // Recursive execution keeps all borrows scoped to this stack frame and
        // returns only owned digest bytes.
        let xml = std::str::from_utf8(&bytes)
            .map_err(|error| TransformError::XmlParse(error.to_string()))?;
        let document = roxmltree::Document::parse(xml)
            .map_err(|error| TransformError::XmlParse(error.to_string()))?;
        let nodes = super::types::NodeSet::entire_document_with_comments(&document);
        return execute_transform_chain(
            signature_node,
            TransformData::NodeSet(nodes),
            transforms,
            options,
        );
    }

    let data = apply_transform_with_options(signature_node, transform, data, options)?;
    execute_transform_chain(signature_node, data, remaining, options)
}

fn transform_requires_node_set(transform: &Transform) -> bool {
    !matches!(transform, Transform::Base64Decode)
}

fn finalize_transform_data(data: TransformData<'_>) -> Result<Vec<u8>, TransformError> {
    // Final coercion: if the result is still a NodeSet, canonicalize with
    // default inclusive C14N 1.0 per XMLDSig spec §4.3.3.2.
    match data {
        TransformData::Binary(bytes) => Ok(bytes),
        TransformData::NodeSet(nodes) => {
            #[expect(clippy::expect_used, reason = "hardcoded URI is a known constant")]
            let algo = C14nAlgorithm::from_uri(DEFAULT_IMPLICIT_C14N_URI)
                .expect("default C14N algorithm URI must be supported by C14nAlgorithm::from_uri");
            let mut output = Vec::new();
            c14n::canonicalize_with_visibility(nodes.document(), Some(&nodes), &algo, &mut output)?;
            Ok(output)
        }
    }
}

/// Parse a `<Transforms>` element into a `Vec<Transform>`.
///
/// Reads each `<Transform Algorithm="...">` child element and constructs
/// the corresponding [`Transform`] variant. Unrecognized algorithm URIs
/// produce an error.
///
/// For Exclusive C14N, also parses the optional `<InclusiveNamespaces
/// PrefixList="...">` child element.
pub fn parse_transforms(transforms_node: Node) -> Result<Vec<Transform>, TransformError> {
    // Validate that we received a <ds:Transforms> element.
    if !transforms_node.is_element() {
        return Err(TransformError::UnsupportedTransform(
            "expected <Transforms> element but got non-element node".into(),
        ));
    }
    let transforms_tag = transforms_node.tag_name();
    if transforms_tag.name() != "Transforms" || transforms_tag.namespace() != Some(XMLDSIG_NS) {
        return Err(TransformError::UnsupportedTransform(
            "expected <ds:Transforms> element in XMLDSig namespace".into(),
        ));
    }

    let mut chain = Vec::new();

    for child in transforms_node.children() {
        if !child.is_element() {
            continue;
        }
        ensure_transform_count(chain.len() + 1)?;

        // Only <ds:Transform> children are allowed; fail closed on any other element.
        let tag = child.tag_name();
        if tag.name() != "Transform" || tag.namespace() != Some(XMLDSIG_NS) {
            return Err(TransformError::UnsupportedTransform(
                "unexpected child element of <ds:Transforms>; only <ds:Transform> is allowed"
                    .into(),
            ));
        }
        let uri = child.attribute("Algorithm").ok_or_else(|| {
            TransformError::UnsupportedTransform(
                "missing Algorithm attribute on <Transform>".into(),
            )
        })?;

        let transform = if uri == ENVELOPED_SIGNATURE_URI {
            Transform::Enveloped
        } else if uri == BASE64_TRANSFORM_URI {
            validate_empty_transform(child, "Base64")?;
            Transform::Base64Decode
        } else if uri == XPATH_TRANSFORM_URI {
            parse_xpath_transform(child)?
        } else if uri == XPATH_FILTER2_TRANSFORM_URI {
            parse_xpath_filter2_transform(child)?
        } else if let Some(mut algo) = C14nAlgorithm::from_uri(uri) {
            // For exclusive C14N, check for InclusiveNamespaces child
            if algo.mode() == c14n::C14nMode::Exclusive1_0
                && let Some(prefix_list) = parse_inclusive_prefixes(child)?
            {
                algo = algo.with_prefix_list(&prefix_list);
            }
            Transform::C14n(algo)
        } else {
            return Err(TransformError::UnsupportedTransform(uri.to_string()));
        };
        chain.push(transform);
    }

    Ok(chain)
}

/// Validate transforms whose XML syntax does not define parameter content.
fn validate_empty_transform(
    transform_node: Node,
    transform_name: &'static str,
) -> Result<(), TransformError> {
    for child in transform_node.children() {
        if child.is_element()
            || (child.is_text()
                && child
                    .text()
                    .is_some_and(|text| !is_xml_whitespace_only(text)))
        {
            return Err(TransformError::UnsupportedTransform(format!(
                "{transform_name} transform must not contain parameters"
            )));
        }
    }
    Ok(())
}

pub(super) fn parse_xpath_transform(transform_node: Node) -> Result<Transform, TransformError> {
    let mut xpath_node = None;

    for child in transform_node.children() {
        if child.is_text() && child.text().is_some_and(is_xml_whitespace_only) {
            continue;
        }
        if !child.is_element() {
            return Err(TransformError::XPath(
                "XPath transform contains non-whitespace parameter content".into(),
            ));
        }
        let tag = child.tag_name();
        if tag.name() == "XPath" && tag.namespace() == Some(XMLDSIG_NS) {
            if xpath_node.is_some() {
                return Err(TransformError::XPath(
                    "XPath transform must contain exactly one XMLDSig <XPath> child element".into(),
                ));
            }
            xpath_node = Some(child);
        } else {
            return Err(TransformError::XPath(
                "XPath transform allows only a single XMLDSig <XPath> child element".into(),
            ));
        }
    }

    let xpath_node = xpath_node.ok_or_else(|| {
        TransformError::XPath(
            "XPath transform requires a single XMLDSig <XPath> child element".into(),
        )
    })?;
    if xpath_node.attributes().len() != 0 {
        return Err(TransformError::XPath(
            "XMLDSig <XPath> does not allow attributes".into(),
        ));
    }
    let xpath = parse_xpath_expression(xpath_node, transform_node.id())?;

    if xpath.expression() == ENVELOPED_SIGNATURE_XPATH_EXPR
        && xpath.namespaces().get("dsig").map(String::as_str) == Some(XMLDSIG_NS)
    {
        Ok(Transform::XpathExcludeAllSignatures)
    } else {
        Ok(Transform::XPath(xpath))
    }
}

fn parse_xpath_filter2_transform(transform_node: Node) -> Result<Transform, TransformError> {
    let mut filters = Vec::new();
    for child in transform_node.children() {
        if child.is_text() && child.text().is_some_and(is_xml_whitespace_only) {
            continue;
        }
        if !child.is_element()
            || child.tag_name().name() != "XPath"
            || child.tag_name().namespace() != Some(XPATH_FILTER2_TRANSFORM_URI)
        {
            return Err(TransformError::XPath(
                "XPath Filter 2.0 allows only filter-namespace <XPath> children".into(),
            ));
        }
        if filters.len() == MAX_XPATH_FILTERS {
            return Err(TransformError::XPath(format!(
                "XPath Filter 2.0 exceeds the maximum of {MAX_XPATH_FILTERS} expressions"
            )));
        }
        if child.attributes().len() != 1 || child.attribute("Filter").is_none() {
            return Err(TransformError::XPath(
                "XPath Filter 2.0 <XPath> requires only the unqualified Filter attribute".into(),
            ));
        }
        let operation = match child.attribute("Filter") {
            Some("intersect") => XPathFilterOperation::Intersect,
            Some("subtract") => XPathFilterOperation::Subtract,
            Some("union") => XPathFilterOperation::Union,
            Some(value) => {
                return Err(TransformError::XPath(format!(
                    "unsupported XPath Filter 2.0 operation: {value}"
                )));
            }
            None => unreachable!("Filter presence was checked above"),
        };
        filters.push(XPathFilter::new(
            operation,
            parse_xpath_expression(child, transform_node.id())?,
        ));
    }
    if filters.is_empty() {
        return Err(TransformError::XPath(
            "XPath Filter 2.0 requires at least one expression".into(),
        ));
    }
    Ok(Transform::XPathFilter2(filters))
}

fn parse_xpath_expression(
    xpath_node: Node,
    transform_node: roxmltree::NodeId,
) -> Result<XPathExpression, TransformError> {
    let mut source = String::new();
    for child in xpath_node.children() {
        if child.is_text() {
            source.push_str(child.text().unwrap_or_default());
        } else if child.is_element() {
            return Err(TransformError::XPath(
                "XPath expressions must contain text only".into(),
            ));
        }
    }
    let source = source.trim();
    if source.is_empty() {
        return Err(TransformError::XPath(
            "XPath expression must not be empty".into(),
        ));
    }
    if source.len() > MAX_XPATH_EXPRESSION_BYTES {
        return Err(TransformError::XPath(format!(
            "XPath expression exceeds {MAX_XPATH_EXPRESSION_BYTES} bytes"
        )));
    }
    sxd_xpath_no_unsafe::Factory::new()
        .build(&normalize_function_spacing(source))
        .map_err(|error| TransformError::XPath(error.to_string()))?;

    let mut xpath = XPathExpression {
        expression: source.to_owned(),
        namespaces: BTreeMap::new(),
        here_nodes: Some(XPathHereNodes {
            xpath: xpath_node.id(),
            transform: transform_node,
        }),
    };
    for namespace in xpath_node.namespaces() {
        if let Some(prefix) = namespace.name() {
            xpath
                .namespaces
                .insert(prefix.to_owned(), namespace.uri().to_owned());
        }
    }
    Ok(xpath)
}

/// Parse the `PrefixList` attribute from an `<ec:InclusiveNamespaces>` child
/// element, if present.
///
/// Per the [Exclusive C14N spec](https://www.w3.org/TR/xml-exc-c14n/#def-InclusiveNamespaces-PrefixList),
/// the element MUST be in the `http://www.w3.org/2001/10/xml-exc-c14n#` namespace.
/// Elements with the same local name but a different namespace are ignored.
///
/// Returns `Ok(None)` if no `<InclusiveNamespaces>` child is present.
/// Returns `Err` if the element exists but lacks the required `PrefixList` attribute
/// (fail-closed: malformed control elements are rejected, not silently ignored).
///
/// The element is typically:
/// ```xml
/// <ec:InclusiveNamespaces
///     xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"
///     PrefixList="ds saml #default"/>
/// ```
fn parse_inclusive_prefixes(transform_node: Node) -> Result<Option<String>, TransformError> {
    for child in transform_node.children() {
        if child.is_element() {
            let tag = child.tag_name();
            if tag.name() == "InclusiveNamespaces" && tag.namespace() == Some(EXCLUSIVE_C14N_NS_URI)
            {
                let prefix_list = child.attribute("PrefixList").ok_or_else(|| {
                    TransformError::UnsupportedTransform(
                        "missing PrefixList attribute on <InclusiveNamespaces>".into(),
                    )
                })?;
                return Ok(Some(prefix_list.to_string()));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests use trusted XML fixtures")]
mod tests {
    use super::*;
    use crate::xmldsig::NodeSet;
    use roxmltree::Document;

    // ── Enveloped transform ──────────────────────────────────────────

    #[test]
    fn enveloped_excludes_signature_subtree() {
        // Simulates a SAML-like document with an enveloped signature
        let xml = r#"<root>
            <data>hello</data>
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
                <SignedInfo><Reference URI=""/></SignedInfo>
                <SignatureValue>abc</SignatureValue>
            </Signature>
        </root>"#;
        let doc = Document::parse(xml).unwrap();

        // Find the Signature element
        let sig_node = doc
            .descendants()
            .find(|n| n.is_element() && n.tag_name().name() == "Signature")
            .unwrap();

        // Start with entire document without comments (empty URI)
        let node_set = NodeSet::entire_document_without_comments(&doc);
        let data = TransformData::NodeSet(node_set);

        // Apply enveloped transform
        let result = apply_transform(sig_node, &Transform::Enveloped, data).unwrap();
        let node_set = result.into_node_set().unwrap();

        // Root and data should be in the set
        assert!(node_set.contains(doc.root_element()));
        let data_elem = doc
            .descendants()
            .find(|n| n.is_element() && n.tag_name().name() == "data")
            .unwrap();
        assert!(node_set.contains(data_elem));

        // Signature and its children should be excluded
        assert!(
            !node_set.contains(sig_node),
            "Signature element should be excluded"
        );
        let signed_info = doc
            .descendants()
            .find(|n| n.is_element() && n.tag_name().name() == "SignedInfo")
            .unwrap();
        assert!(
            !node_set.contains(signed_info),
            "SignedInfo (child of Signature) should be excluded"
        );
    }

    #[test]
    fn enveloped_requires_node_set_input() {
        let xml = "<root/>";
        let doc = Document::parse(xml).unwrap();
        // Binary input should fail with TypeMismatch
        let data = TransformData::Binary(vec![1, 2, 3]);
        let result = apply_transform(doc.root_element(), &Transform::Enveloped, data);
        assert!(result.is_err());
        match result.unwrap_err() {
            TransformError::TypeMismatch { expected, got } => {
                assert_eq!(expected, "NodeSet");
                assert_eq!(got, "Binary");
            }
            other => panic!("expected TypeMismatch, got: {other:?}"),
        }
    }

    #[test]
    fn enveloped_rejects_cross_document_signature_node() {
        // Signature node from a different Document must be rejected,
        // not silently used to exclude wrong subtree.
        let xml = r#"<Root><Signature Id="sig"/></Root>"#;
        let doc1 = Document::parse(xml).unwrap();
        let doc2 = Document::parse(xml).unwrap();

        // NodeSet from doc1, Signature node from doc2
        let node_set = NodeSet::entire_document_without_comments(&doc1);
        let input = TransformData::NodeSet(node_set);
        let sig_from_doc2 = doc2
            .descendants()
            .find(|n| n.is_element() && n.tag_name().name() == "Signature")
            .unwrap();

        let result = apply_transform(sig_from_doc2, &Transform::Enveloped, input);
        assert!(matches!(
            result,
            Err(TransformError::CrossDocumentSignatureNode)
        ));
    }

    // ── C14N transform ───────────────────────────────────────────────

    #[test]
    fn c14n_transform_produces_bytes() {
        let xml = r#"<root b="2" a="1"><child/></root>"#;
        let doc = Document::parse(xml).unwrap();

        let node_set = NodeSet::entire_document_without_comments(&doc);
        let data = TransformData::NodeSet(node_set);

        let algo =
            C14nAlgorithm::from_uri("http://www.w3.org/TR/2001/REC-xml-c14n-20010315").unwrap();
        let result = apply_transform(doc.root_element(), &Transform::C14n(algo), data).unwrap();

        let bytes = result.into_binary().unwrap();
        let output = String::from_utf8(bytes).unwrap();
        // Attributes sorted, empty element expanded
        assert_eq!(output, r#"<root a="1" b="2"><child></child></root>"#);
    }

    #[test]
    fn c14n_transform_requires_node_set() {
        let xml = "<root/>";
        let doc = Document::parse(xml).unwrap();

        let algo =
            C14nAlgorithm::from_uri("http://www.w3.org/TR/2001/REC-xml-c14n-20010315").unwrap();
        let data = TransformData::Binary(vec![1, 2, 3]);
        let result = apply_transform(doc.root_element(), &Transform::C14n(algo), data);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TransformError::TypeMismatch { .. }
        ));
    }

    // ── Base64 transform ────────────────────────────────────────────

    #[test]
    fn base64_transform_decodes_binary_with_xml_whitespace() {
        // XML line wrapping is insignificant to the standard transform.
        let doc = Document::parse("<root/>").unwrap();
        let input = TransformData::Binary(b" SGV\tsbG8=\r\n".to_vec());

        let result = apply_transform(doc.root_element(), &Transform::Base64Decode, input).unwrap();

        assert_eq!(result.into_binary().unwrap(), b"Hello");
    }

    #[test]
    fn base64_transform_concatenates_only_selected_text_nodes_in_document_order() {
        // Tags, comments, and processing instructions must not enter the
        // encoded octet stream; descendant text remains in document order.
        let xml = r#"<root><Data ID="payload">SGV<!-- split --><Part>sb</Part><?pi ignored?>G8=</Data></root>"#;
        let doc = Document::parse(xml).unwrap();
        let data = doc
            .descendants()
            .find(|node| node.attribute("ID") == Some("payload"))
            .unwrap();
        let input = TransformData::NodeSet(NodeSet::subtree(data));

        let result = apply_transform(data, &Transform::Base64Decode, input).unwrap();

        assert_eq!(result.into_binary().unwrap(), b"Hello");
    }

    #[test]
    fn base64_transform_omits_text_excluded_from_the_node_set() {
        // A prior node-set transform can remove a subtree. Its text must not
        // be resurrected while converting the remaining node set to octets.
        let xml = "<root>SGV<Excluded>QUJD</Excluded>sbG8=</root>";
        let doc = Document::parse(xml).unwrap();
        let excluded = doc
            .descendants()
            .find(|node| node.has_tag_name("Excluded"))
            .unwrap();
        let mut nodes = NodeSet::subtree(doc.root_element());
        nodes.exclude_subtree(excluded);

        let result = apply_transform(
            doc.root_element(),
            &Transform::Base64Decode,
            TransformData::NodeSet(nodes),
        )
        .unwrap();

        assert_eq!(result.into_binary().unwrap(), b"Hello");
    }

    #[test]
    fn base64_transform_rejects_invalid_alphabet_and_padding() {
        let doc = Document::parse("<root/>").unwrap();

        for encoded in [b"SGVs!bG8=".as_slice(), b"SGVsbG8===".as_slice()] {
            let result = apply_transform(
                doc.root_element(),
                &Transform::Base64Decode,
                TransformData::Binary(encoded.to_vec()),
            );
            assert!(matches!(result, Err(TransformError::Base64(_))));
        }
    }

    #[test]
    fn base64_transform_accepts_empty_input() {
        let doc = Document::parse("<root/>").unwrap();
        let result = apply_transform(
            doc.root_element(),
            &Transform::Base64Decode,
            TransformData::Binary(Vec::new()),
        )
        .unwrap();

        assert!(result.into_binary().unwrap().is_empty());
    }

    #[test]
    fn pipeline_rejects_unbounded_programmatic_transform_chain() {
        // The public executor is a trust boundary too: callers can bypass XML
        // parsing and must not be able to create an arbitrarily deep recursion.
        let doc = Document::parse("<root/>").unwrap();
        let transforms = vec![Transform::Base64Decode; 65];

        let result = execute_transforms(
            doc.root_element(),
            TransformData::Binary(Vec::new()),
            &transforms,
        );

        assert!(matches!(
            result,
            Err(TransformError::TooManyTransforms {
                max: MAX_TRANSFORMS_PER_REFERENCE
            })
        ));
    }

    // ── Pipeline execution ───────────────────────────────────────────

    #[test]
    fn pipeline_enveloped_then_c14n() {
        // Standard SAML transform chain: enveloped-signature → exc-c14n
        let xml = r#"<root xmlns:ns="http://example.com" b="2" a="1">
            <data>hello</data>
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
                <SignedInfo/>
                <SignatureValue>abc</SignatureValue>
            </Signature>
        </root>"#;
        let doc = Document::parse(xml).unwrap();

        let sig_node = doc
            .descendants()
            .find(|n| n.is_element() && n.tag_name().name() == "Signature")
            .unwrap();

        let initial = TransformData::NodeSet(NodeSet::entire_document_without_comments(&doc));
        let transforms = vec![
            Transform::Enveloped,
            Transform::C14n(
                C14nAlgorithm::from_uri("http://www.w3.org/2001/10/xml-exc-c14n#").unwrap(),
            ),
        ];

        let result = execute_transforms(sig_node, initial, &transforms).unwrap();

        let output = String::from_utf8(result).unwrap();
        // Signature subtree should be gone; attributes sorted
        assert!(!output.contains("Signature"));
        assert!(!output.contains("SignedInfo"));
        assert!(!output.contains("SignatureValue"));
        assert!(output.contains("<data>hello</data>"));
    }

    #[test]
    fn pipeline_no_transforms_applies_default_c14n() {
        // No explicit transforms → pipeline falls back to inclusive C14N 1.0
        let xml = r#"<root b="2" a="1"><child/></root>"#;
        let doc = Document::parse(xml).unwrap();

        let initial = TransformData::NodeSet(NodeSet::entire_document_without_comments(&doc));
        let result = execute_transforms(doc.root_element(), initial, &[]).unwrap();

        let output = String::from_utf8(result).unwrap();
        assert_eq!(output, r#"<root a="1" b="2"><child></child></root>"#);
    }

    #[test]
    fn pipeline_binary_passthrough() {
        // If initial data is already binary (unusual, but spec-compliant)
        // and no transforms, returns bytes directly
        let xml = "<root/>";
        let doc = Document::parse(xml).unwrap();

        let initial = TransformData::Binary(b"raw bytes".to_vec());
        let result = execute_transforms(doc.root_element(), initial, &[]).unwrap();

        assert_eq!(result, b"raw bytes");
    }

    // ── Nested signatures ────────────────────────────────────────────

    #[test]
    fn enveloped_only_excludes_own_signature() {
        // Two real <Signature> elements: enveloped transform should only
        // exclude the specific one being verified, not the other.
        let xml = r#"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <data>hello</data>
            <ds:Signature Id="sig-other">
                <ds:SignedInfo><ds:Reference URI=""/></ds:SignedInfo>
            </ds:Signature>
            <ds:Signature Id="sig-target">
                <ds:SignedInfo><ds:Reference URI=""/></ds:SignedInfo>
            </ds:Signature>
        </root>"#;
        let doc = Document::parse(xml).unwrap();

        // We are verifying sig-target, not sig-other
        let sig_node = doc
            .descendants()
            .find(|n| n.is_element() && n.attribute("Id") == Some("sig-target"))
            .unwrap();

        let node_set = NodeSet::entire_document_without_comments(&doc);
        let data = TransformData::NodeSet(node_set);

        let result = apply_transform(sig_node, &Transform::Enveloped, data).unwrap();
        let node_set = result.into_node_set().unwrap();

        // sig-other should still be in the set
        let sig_other = doc
            .descendants()
            .find(|n| n.is_element() && n.attribute("Id") == Some("sig-other"))
            .unwrap();
        assert!(
            node_set.contains(sig_other),
            "other Signature elements should NOT be excluded"
        );

        // Signature should be excluded
        assert!(
            !node_set.contains(sig_node),
            "the specific Signature being verified should be excluded"
        );
    }

    // ── parse_transforms ─────────────────────────────────────────────

    #[test]
    fn parse_transforms_enveloped_and_exc_c14n() {
        let xml = r#"<Transforms xmlns="http://www.w3.org/2000/09/xmldsig#">
            <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </Transforms>"#;
        let doc = Document::parse(xml).unwrap();
        let transforms_node = doc.root_element();

        let chain = parse_transforms(transforms_node).unwrap();
        assert_eq!(chain.len(), 2);
        assert!(matches!(chain[0], Transform::Enveloped));
        assert!(matches!(chain[1], Transform::C14n(_)));
    }

    #[test]
    fn parse_transforms_rejects_unbounded_chain() {
        // Signed XML is untrusted input; reject excess transforms before
        // constructing a chain that would consume one stack frame per entry.
        let entries = format!(r#"<Transform Algorithm="{BASE64_TRANSFORM_URI}"/>"#).repeat(65);
        let xml = format!(r#"<Transforms xmlns="{XMLDSIG_NS}">{entries}</Transforms>"#);
        let doc = Document::parse(&xml).unwrap();

        assert!(matches!(
            parse_transforms(doc.root_element()),
            Err(TransformError::TooManyTransforms {
                max: MAX_TRANSFORMS_PER_REFERENCE
            })
        ));
    }

    #[test]
    fn parse_transforms_accepts_parameterless_base64() {
        let xml = format!(
            r#"<Transforms xmlns="{XMLDSIG_NS}"><Transform Algorithm="{BASE64_TRANSFORM_URI}">
            </Transform></Transforms>"#
        );
        let doc = Document::parse(&xml).unwrap();

        let chain = parse_transforms(doc.root_element()).unwrap();

        assert_eq!(chain.len(), 1);
        assert!(matches!(chain[0], Transform::Base64Decode));
    }

    #[test]
    fn parse_transforms_rejects_base64_parameters() {
        for parameter in ["<Parameter/>", "unexpected", "\u{00A0}"] {
            let xml = format!(
                r#"<Transforms xmlns="{XMLDSIG_NS}"><Transform Algorithm="{BASE64_TRANSFORM_URI}">{parameter}</Transform></Transforms>"#
            );
            let doc = Document::parse(&xml).unwrap();

            let result = parse_transforms(doc.root_element());

            assert!(matches!(
                result,
                Err(TransformError::UnsupportedTransform(_))
            ));
        }
    }

    #[test]
    fn parse_transforms_with_inclusive_prefixes() {
        let xml = r#"<Transforms xmlns="http://www.w3.org/2000/09/xmldsig#"
                                xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#">
            <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
                <ec:InclusiveNamespaces PrefixList="ds saml #default"/>
            </Transform>
        </Transforms>"#;
        let doc = Document::parse(xml).unwrap();
        let transforms_node = doc.root_element();

        let chain = parse_transforms(transforms_node).unwrap();
        assert_eq!(chain.len(), 1);
        match &chain[0] {
            Transform::C14n(algo) => {
                assert!(algo.inclusive_prefixes().contains("ds"));
                assert!(algo.inclusive_prefixes().contains("saml"));
                assert!(algo.inclusive_prefixes().contains("")); // #default
            }
            other => panic!("expected C14n, got: {other:?}"),
        }
    }

    #[test]
    fn parse_transforms_ignores_wrong_ns_inclusive_namespaces() {
        // InclusiveNamespaces in a foreign namespace should be ignored —
        // only elements in http://www.w3.org/2001/10/xml-exc-c14n# are valid.
        let xml = r#"<Transforms xmlns="http://www.w3.org/2000/09/xmldsig#">
            <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
                <InclusiveNamespaces xmlns="http://example.com/fake"
                                     PrefixList="attacker-controlled"/>
            </Transform>
        </Transforms>"#;
        let doc = Document::parse(xml).unwrap();

        let chain = parse_transforms(doc.root_element()).unwrap();
        assert_eq!(chain.len(), 1);
        match &chain[0] {
            Transform::C14n(algo) => {
                // PrefixList from wrong namespace should NOT be honoured
                assert!(
                    algo.inclusive_prefixes().is_empty(),
                    "should ignore InclusiveNamespaces in wrong namespace"
                );
            }
            other => panic!("expected C14n, got: {other:?}"),
        }
    }

    #[test]
    fn parse_transforms_missing_prefix_list_is_error() {
        // InclusiveNamespaces in correct namespace but without PrefixList
        // attribute should be rejected (fail-closed), not silently ignored.
        let xml = r#"<Transforms xmlns="http://www.w3.org/2000/09/xmldsig#"
                                xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#">
            <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
                <ec:InclusiveNamespaces/>
            </Transform>
        </Transforms>"#;
        let doc = Document::parse(xml).unwrap();

        let result = parse_transforms(doc.root_element());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TransformError::UnsupportedTransform(_)
        ));
    }

    #[test]
    fn parse_transforms_unsupported_algorithm() {
        let xml = r#"<Transforms xmlns="http://www.w3.org/2000/09/xmldsig#">
            <Transform Algorithm="http://example.com/unknown"/>
        </Transforms>"#;
        let doc = Document::parse(xml).unwrap();

        let result = parse_transforms(doc.root_element());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TransformError::UnsupportedTransform(_)
        ));
    }

    #[test]
    fn parse_transforms_missing_algorithm() {
        let xml = r#"<Transforms xmlns="http://www.w3.org/2000/09/xmldsig#">
            <Transform/>
        </Transforms>"#;
        let doc = Document::parse(xml).unwrap();

        let result = parse_transforms(doc.root_element());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TransformError::UnsupportedTransform(_)
        ));
    }

    #[test]
    fn parse_transforms_empty() {
        let xml = r#"<Transforms xmlns="http://www.w3.org/2000/09/xmldsig#"/>"#;
        let doc = Document::parse(xml).unwrap();

        let chain = parse_transforms(doc.root_element()).unwrap();
        assert!(chain.is_empty());
    }

    #[test]
    fn parse_transforms_accepts_enveloped_compat_xpath() {
        let xml = r#"<Transforms xmlns="http://www.w3.org/2000/09/xmldsig#">
            <Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
                <XPath xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
                    not(ancestor-or-self::dsig:Signature)
                </XPath>
            </Transform>
        </Transforms>"#;
        let doc = Document::parse(xml).unwrap();

        let chain = parse_transforms(doc.root_element()).unwrap();
        assert_eq!(chain.len(), 1);
        assert!(matches!(chain[0], Transform::XpathExcludeAllSignatures));
    }

    #[test]
    fn parse_transforms_accepts_general_xpath_expressions() {
        // XPath 1.0 is no longer restricted to the historical enveloped-
        // signature compatibility expression.
        let xml = r#"<Transforms xmlns="http://www.w3.org/2000/09/xmldsig#">
            <Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
                <XPath>self::node()</XPath>
            </Transform>
        </Transforms>"#;
        let doc = Document::parse(xml).unwrap();

        let result = parse_transforms(doc.root_element()).unwrap();
        assert!(matches!(result.as_slice(), [Transform::XPath(_)]));
    }

    #[test]
    fn parse_transforms_bounds_raw_xpath_parameter_text() {
        // Trimming must not let an untrusted parameter force allocation of an
        // otherwise bounded expression-sized buffer.
        let padding = " ".repeat(MAX_XPATH_EXPRESSION_BYTES);
        let xml = format!(
            r#"<Transforms xmlns="{XMLDSIG_NS}"><Transform Algorithm="{XPATH_TRANSFORM_URI}"><XPath>{padding}true()</XPath></Transform></Transforms>"#
        );
        let doc = Document::parse(&xml).unwrap();

        let error = parse_transforms(doc.root_element())
            .expect_err("raw XPath parameter text must obey the expression bound");

        assert!(matches!(error, TransformError::XPath(_)));
        assert!(error.to_string().contains("exceeds"));
    }

    #[test]
    fn parse_transforms_rejects_xpath_in_wrong_namespace() {
        let xml = r#"<Transforms xmlns="http://www.w3.org/2000/09/xmldsig#">
            <Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
                <foo:XPath xmlns:foo="http://example.com/ns">
                    not(ancestor-or-self::dsig:Signature)
                </foo:XPath>
            </Transform>
        </Transforms>"#;
        let doc = Document::parse(xml).unwrap();

        let result = parse_transforms(doc.root_element());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TransformError::XPath(_)));
    }

    #[test]
    fn parse_transforms_preserves_nonstandard_prefix_bindings() {
        // A prefix URI is expression data. Binding `dsig` to another namespace
        // is valid XPath and must select that namespace rather than being
        // rewritten to XMLDSig by the parser.
        let xml = r#"<Transforms xmlns="http://www.w3.org/2000/09/xmldsig#">
            <Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
                <XPath xmlns:dsig="http://example.com/not-xmldsig">
                    not(ancestor-or-self::dsig:Signature)
                </XPath>
            </Transform>
        </Transforms>"#;
        let doc = Document::parse(xml).unwrap();

        let result = parse_transforms(doc.root_element()).unwrap();
        let [Transform::XPath(xpath)] = result.as_slice() else {
            panic!("expected general XPath transform");
        };
        assert_eq!(
            xpath.namespaces().get("dsig").map(String::as_str),
            Some("http://example.com/not-xmldsig")
        );
    }

    #[test]
    fn parse_transforms_rejects_xpath_with_internal_whitespace_mutation() {
        let xml = r#"<Transforms xmlns="http://www.w3.org/2000/09/xmldsig#">
            <Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
                <XPath xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
                    not(ancestor-or-self::dsig:Signa ture)
                </XPath>
            </Transform>
        </Transforms>"#;
        let doc = Document::parse(xml).unwrap();

        let result = parse_transforms(doc.root_element());
        assert!(matches!(result.unwrap_err(), TransformError::XPath(_)));
    }

    #[test]
    fn parse_transforms_rejects_multiple_xpath_children() {
        let xml = r#"<Transforms xmlns="http://www.w3.org/2000/09/xmldsig#">
            <Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
                <XPath xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
                    not(ancestor-or-self::dsig:Signature)
                </XPath>
                <XPath xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
                    not(ancestor-or-self::dsig:Signature)
                </XPath>
            </Transform>
        </Transforms>"#;
        let doc = Document::parse(xml).unwrap();

        let result = parse_transforms(doc.root_element());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TransformError::XPath(_)));
    }

    #[test]
    fn parse_transforms_rejects_non_xpath_element_children() {
        let xml = r#"<Transforms xmlns="http://www.w3.org/2000/09/xmldsig#">
            <Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
                <XPath xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
                    not(ancestor-or-self::dsig:Signature)
                </XPath>
                <Extra/>
            </Transform>
        </Transforms>"#;
        let doc = Document::parse(xml).unwrap();

        let result = parse_transforms(doc.root_element());
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TransformError::XPath(_)));
    }

    #[test]
    fn parse_transforms_rejects_malformed_xpath_filter2_parameters() {
        // Filter 2.0 has a deliberately narrow parameter grammar. Rejecting
        // malformed variants prevents an unsupported parameter from being
        // silently ignored while computing security-sensitive digest input.
        for parameter in [
            r#"<XPath xmlns="http://www.w3.org/2002/06/xmldsig-filter2">//Data</XPath>"#,
            r#"<XPath xmlns="http://www.w3.org/2002/06/xmldsig-filter2" Filter="exclude">//Data</XPath>"#,
            r#"<XPath xmlns="urn:wrong" Filter="intersect">//Data</XPath>"#,
            r#"<XPath xmlns="http://www.w3.org/2002/06/xmldsig-filter2" Filter="intersect" Extra="value">//Data</XPath>"#,
        ] {
            let xml = format!(
                r#"<Transforms xmlns="{XMLDSIG_NS}"><Transform Algorithm="{XPATH_FILTER2_TRANSFORM_URI}">{parameter}</Transform></Transforms>"#
            );
            let doc = Document::parse(&xml).unwrap();

            let result = parse_transforms(doc.root_element());

            assert!(matches!(result, Err(TransformError::XPath(_))));
        }
    }

    #[test]
    fn parse_transforms_rejects_empty_xpath_filter2_sequence() {
        // A no-op empty filter list is not a valid Filter 2.0 transform and
        // must not be accepted as though the transform were absent.
        let xml = format!(
            r#"<Transforms xmlns="{XMLDSIG_NS}"><Transform Algorithm="{XPATH_FILTER2_TRANSFORM_URI}"/></Transforms>"#
        );
        let doc = Document::parse(&xml).unwrap();

        let result = parse_transforms(doc.root_element());

        assert!(matches!(result, Err(TransformError::XPath(_))));
    }

    #[test]
    fn xpath_compat_excludes_other_signature_subtrees_too() {
        let xml = r#"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <payload>keep-me</payload>
            <ds:Signature Id="sig-1">
                <ds:SignedInfo/>
                <ds:SignatureValue>one</ds:SignatureValue>
            </ds:Signature>
            <ds:Signature Id="sig-2">
                <ds:SignedInfo/>
                <ds:SignatureValue>two</ds:SignatureValue>
            </ds:Signature>
        </root>"#;
        let doc = Document::parse(xml).unwrap();
        let signature_nodes: Vec<_> = doc
            .descendants()
            .filter(|node| {
                node.is_element()
                    && node.tag_name().name() == "Signature"
                    && node.tag_name().namespace() == Some(XMLDSIG_NS)
            })
            .collect();
        let sig_node = signature_nodes[0];

        let enveloped = execute_transforms(
            sig_node,
            TransformData::NodeSet(NodeSet::entire_document_without_comments(&doc)),
            &[
                Transform::Enveloped,
                Transform::C14n(C14nAlgorithm::new(
                    crate::c14n::C14nMode::Inclusive1_0,
                    false,
                )),
            ],
        )
        .unwrap();
        let xpath_compat = execute_transforms(
            sig_node,
            TransformData::NodeSet(NodeSet::entire_document_without_comments(&doc)),
            &[
                Transform::XpathExcludeAllSignatures,
                Transform::C14n(C14nAlgorithm::new(
                    crate::c14n::C14nMode::Inclusive1_0,
                    false,
                )),
            ],
        )
        .unwrap();

        let enveloped = String::from_utf8(enveloped).unwrap();
        let xpath_compat = String::from_utf8(xpath_compat).unwrap();

        assert!(enveloped.contains("sig-2"));
        assert!(!xpath_compat.contains("sig-1"));
        assert!(!xpath_compat.contains("sig-2"));
        assert!(xpath_compat.contains("keep-me"));
    }

    #[test]
    fn parse_transforms_inclusive_c14n_variants() {
        let xml = r#"<Transforms xmlns="http://www.w3.org/2000/09/xmldsig#">
            <Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
            <Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"/>
            <Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
        </Transforms>"#;
        let doc = Document::parse(xml).unwrap();

        let chain = parse_transforms(doc.root_element()).unwrap();
        assert_eq!(chain.len(), 3);
        // All should be C14n variants
        for t in &chain {
            assert!(matches!(t, Transform::C14n(_)));
        }
    }

    // ── Integration: SAML-like full pipeline ─────────────────────────

    #[test]
    fn saml_enveloped_signature_full_pipeline() {
        // Realistic SAML Response with enveloped signature
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                                     ID="_resp1">
            <saml:Assertion ID="_assert1">
                <saml:Subject>user@example.com</saml:Subject>
            </saml:Assertion>
            <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:SignedInfo>
                    <ds:Reference URI="">
                        <ds:Transforms>
                            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                        </ds:Transforms>
                    </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>fakesig==</ds:SignatureValue>
            </ds:Signature>
        </samlp:Response>"#;
        let doc = Document::parse(xml).unwrap();

        // Find the Signature element
        let sig_node = doc
            .descendants()
            .find(|n| n.is_element() && n.tag_name().name() == "Signature")
            .unwrap();

        // Parse the transforms from the XML
        let reference = doc
            .descendants()
            .find(|n| n.is_element() && n.tag_name().name() == "Reference")
            .unwrap();
        let transforms_elem = reference
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == "Transforms")
            .unwrap();
        let transforms = parse_transforms(transforms_elem).unwrap();
        assert_eq!(transforms.len(), 2);

        // Execute the pipeline with empty URI (entire document)
        let initial = TransformData::NodeSet(NodeSet::entire_document_without_comments(&doc));
        let result = execute_transforms(sig_node, initial, &transforms).unwrap();

        let output = String::from_utf8(result).unwrap();

        // Signature subtree must be completely absent
        assert!(!output.contains("Signature"), "Signature should be removed");
        assert!(
            !output.contains("SignedInfo"),
            "SignedInfo should be removed"
        );
        assert!(
            !output.contains("SignatureValue"),
            "SignatureValue should be removed"
        );
        assert!(
            !output.contains("fakesig"),
            "signature value should be removed"
        );

        // Document content should be present and canonicalized
        assert!(output.contains("samlp:Response"));
        assert!(output.contains("saml:Assertion"));
        assert!(output.contains("user@example.com"));
    }
}
