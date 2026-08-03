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

use std::borrow::Cow;
use std::cell::Cell;
use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use roxmltree::{Document, Node};
use sha2::{Digest as _, Sha256};

use super::parse::XMLDSIG_NS;
use super::types::{TransformData, TransformError};
use super::whitespace::is_xml_whitespace_only;
use super::xpath::{
    XPathDocumentRelation, XPathWorkBudget, apply_xpath_filter_with_semantics,
    apply_xpath_filter2_with_semantics, compile_xpath, is_xpath_whitespace,
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
/// temporary XML, so this bounds recursion depth. The signature-wide C14N output
/// budget below bounds both total work and buffers retained by those frames.
pub const MAX_TRANSFORMS_PER_REFERENCE: usize = 64;
/// xmlsec1 donor vectors use this XPath expression as a compatibility form of
/// enveloped-signature exclusion.
const ENVELOPED_SIGNATURE_XPATH_EXPR: &str = "not(ancestor-or-self::dsig:Signature)";
pub(super) const MAX_XPATH_EXPRESSION_BYTES: usize = 16 * 1024;
pub(super) const MAX_XPATH_FILTERS: usize = 64;
/// Maximum XPath programs retained and compiled while parsing one SignedInfo.
///
/// Per-reference bounds remain necessary for transform shape, while this bound
/// prevents their multiplication across all references in one signature.
pub(super) const MAX_XPATH_EXPRESSIONS_PER_SIGNATURE: usize = 4_096;
const MAX_XPATH_NAMESPACE_BINDINGS: usize = 1_024;
const MAX_XPATH_NAMESPACE_BYTES: usize = 64 * 1024;
const MAX_BASE64_TRANSFORM_INPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_BASE64_TRANSFORM_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_C14N_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

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

#[derive(Default)]
pub(crate) struct TransformExecutionBudget {
    xpath: XPathWorkBudget,
    base64: Base64WorkBudget,
    c14n: C14nOutputBudget,
}

struct Base64WorkBudget {
    remaining: Cell<usize>,
}

struct C14nOutputBudget {
    remaining: Cell<usize>,
}

fn charge_byte_budget(remaining: &Cell<usize>, bytes: usize) -> bool {
    let Some(next) = remaining.get().checked_sub(bytes) else {
        remaining.set(0);
        return false;
    };
    remaining.set(next);
    true
}

impl Default for C14nOutputBudget {
    fn default() -> Self {
        Self {
            remaining: Cell::new(MAX_C14N_OUTPUT_BYTES),
        }
    }
}

impl C14nOutputBudget {
    fn remaining(&self) -> usize {
        self.remaining.get()
    }

    fn charge(&self, bytes: usize) -> Result<(), TransformError> {
        if !charge_byte_budget(&self.remaining, bytes) {
            return Err(TransformError::C14nOutputTooLarge {
                max_bytes: MAX_C14N_OUTPUT_BYTES,
            });
        }
        Ok(())
    }
}

impl Default for Base64WorkBudget {
    fn default() -> Self {
        Self {
            remaining: Cell::new(MAX_BASE64_TRANSFORM_INPUT_BYTES),
        }
    }
}

impl Base64WorkBudget {
    fn charge(&self, bytes: usize) -> Result<(), TransformError> {
        if !charge_byte_budget(&self.remaining, bytes) {
            return Err(TransformError::Base64InputTooLarge {
                max_bytes: MAX_BASE64_TRANSFORM_INPUT_BYTES,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
impl TransformExecutionBudget {
    pub(crate) fn with_xpath_limit(limit: usize) -> Self {
        Self {
            xpath: XPathWorkBudget::with_limit(limit),
            base64: Base64WorkBudget::default(),
            c14n: C14nOutputBudget::default(),
        }
    }

    fn with_c14n_limit(limit: usize) -> Self {
        Self {
            xpath: XPathWorkBudget::default(),
            base64: Base64WorkBudget::default(),
            c14n: C14nOutputBudget {
                remaining: Cell::new(limit),
            },
        }
    }
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
    document: XPathDocumentIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct XPathDocumentIdentity([u8; 32]);

impl XPathDocumentIdentity {
    fn from_document(document: &Document<'_>) -> Self {
        #[cfg(test)]
        XPATH_DOCUMENT_IDENTITY_COMPUTATIONS.with(|count| count.set(count.get() + 1));
        Self(Sha256::digest(document.input_text().as_bytes()).into())
    }
}

#[cfg(test)]
thread_local! {
    static XPATH_DOCUMENT_IDENTITY_COMPUTATIONS: Cell<usize> = const { Cell::new(0) };
}

#[derive(Default)]
struct TransformChainState {
    xpath_document_identity: Cell<Option<CachedXPathDocumentIdentity>>,
}

#[derive(Clone, Copy)]
struct CachedXPathDocumentIdentity {
    document: *const (),
    identity: XPathDocumentIdentity,
}

impl TransformChainState {
    fn xpath_document_identity(&self, document: &Document<'_>) -> XPathDocumentIdentity {
        let document_key = std::ptr::from_ref(document).cast::<()>();
        if let Some(cached) = self.xpath_document_identity.get()
            && cached.document == document_key
        {
            return cached.identity;
        }
        let identity = XPathDocumentIdentity::from_document(document);
        self.xpath_document_identity
            .set(Some(CachedXPathDocumentIdentity {
                document: document_key,
                identity,
            }));
        identity
    }

    fn document_reparsed(&self) {
        self.xpath_document_identity.set(None);
    }
}

struct TransformExecutionContext<'a> {
    options: TransformOptions,
    budget: &'a TransformExecutionBudget,
    state: &'a TransformChainState,
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

    fn parsed_document_identity(&self) -> Option<XPathDocumentIdentity> {
        self.here_nodes.map(|nodes| nodes.document)
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
    let budget = TransformExecutionBudget::default();
    let state = TransformChainState::default();
    apply_transform_with_options_and_state(
        signature_node,
        transform,
        input,
        TransformOptions::default(),
        &budget,
        &state,
    )
}

#[cfg(test)]
pub(super) fn apply_transform_with_options<'s, 'd>(
    signature_node: Node<'s, 's>,
    transform: &Transform,
    input: TransformData<'d>,
    options: TransformOptions,
    budget: &TransformExecutionBudget,
) -> Result<TransformData<'d>, TransformError> {
    let state = TransformChainState::default();
    apply_transform_with_options_and_state(
        signature_node,
        transform,
        input,
        options,
        budget,
        &state,
    )
}

fn apply_transform_with_options_and_state<'s, 'd>(
    signature_node: Node<'s, 's>,
    transform: &Transform,
    input: TransformData<'d>,
    options: TransformOptions,
    budget: &TransformExecutionBudget,
    state: &TransformChainState,
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
            let document_relation = xpath_document_relation(
                signature_node.document(),
                nodes.document(),
                std::iter::once(xpath),
                state,
            );
            Ok(TransformData::NodeSet(apply_xpath_filter_with_semantics(
                nodes,
                xpath,
                options.here_semantics(),
                document_relation,
                &budget.xpath,
            )?))
        }
        Transform::XPathFilter2(filters) => {
            let nodes = input.into_node_set()?;
            let document_relation = xpath_document_relation(
                signature_node.document(),
                nodes.document(),
                filters.iter().map(XPathFilter::xpath),
                state,
            );
            Ok(TransformData::NodeSet(apply_xpath_filter2_with_semantics(
                nodes,
                filters,
                options.here_semantics(),
                document_relation,
                &budget.xpath,
            )?))
        }
        Transform::C14n(algo) => {
            let nodes = input.into_node_set()?;
            let mut output = Vec::new();
            c14n::canonicalize_with_visibility_and_position_bounded(
                nodes.document(),
                Some(&nodes),
                algo,
                None,
                budget.c14n.remaining(),
                &mut output,
            )
            .map_err(map_c14n_limit_error)?;
            budget.c14n.charge(output.len())?;
            Ok(TransformData::Binary(output))
        }
        Transform::Base64Decode => {
            let mut normalized = Vec::new();
            match input {
                TransformData::Binary(bytes) => {
                    append_normalized_base64(&bytes, &mut normalized, &budget.base64)?;
                }
                TransformData::NodeSet(nodes) => {
                    for node in nodes.document().descendants() {
                        if nodes.contains(node) && node.is_text() {
                            append_normalized_base64(
                                node.text().unwrap_or_default().as_bytes(),
                                &mut normalized,
                                &budget.base64,
                            )?;
                        }
                    }
                }
            }
            Ok(TransformData::Binary(decode_base64_transform(&normalized)?))
        }
    }
}

fn xpath_document_relation<'a>(
    signature_document: &Document<'_>,
    input_document: &Document<'_>,
    expressions: impl IntoIterator<Item = &'a XPathExpression>,
    state: &TransformChainState,
) -> XPathDocumentRelation {
    if matches!(
        XPathDocumentRelation::between(signature_document, input_document),
        XPathDocumentRelation::CrossDocument
    ) {
        return XPathDocumentRelation::CrossDocument;
    }

    let mut parsed_identities = expressions
        .into_iter()
        .filter_map(XPathExpression::parsed_document_identity);
    let Some(first) = parsed_identities.next() else {
        return XPathDocumentRelation::SameDocument;
    };
    let input_identity = state.xpath_document_identity(input_document);
    if first == input_identity && parsed_identities.all(|identity| identity == input_identity) {
        XPathDocumentRelation::SameDocument
    } else {
        XPathDocumentRelation::CrossDocument
    }
}

/// Retain the RFC 2045 alphabet consumed by the XMLDSig Base64 transform.
///
/// RFC 2045 section 6.8 requires decoders to ignore every byte outside the
/// alphabet. The raw-input budget is charged before filtering so ignored data
/// cannot be used to force unbounded scanning or allocation.
fn append_normalized_base64(
    encoded: &[u8],
    normalized: &mut Vec<u8>,
    budget: &Base64WorkBudget,
) -> Result<(), TransformError> {
    budget.charge(encoded.len())?;

    let additional = encoded
        .iter()
        .filter(|byte| is_rfc2045_base64_byte(**byte))
        .count();
    normalized.reserve(additional);
    normalized.extend(
        encoded
            .iter()
            .copied()
            .filter(|byte| is_rfc2045_base64_byte(*byte)),
    );
    Ok(())
}

fn is_rfc2045_base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
}

fn decode_base64_transform(normalized: &[u8]) -> Result<Vec<u8>, TransformError> {
    let padding = normalized
        .iter()
        .rev()
        .take_while(|byte| **byte == b'=')
        .count();
    let decoded_len = base64::decoded_len_estimate(normalized.len()).saturating_sub(padding);
    if decoded_len > MAX_BASE64_TRANSFORM_OUTPUT_BYTES {
        return Err(TransformError::Base64OutputTooLarge {
            max_bytes: MAX_BASE64_TRANSFORM_OUTPUT_BYTES,
        });
    }

    let mut decoded = vec![0_u8; decoded_len];
    let written = STANDARD
        .decode_slice(normalized, &mut decoded)
        .map_err(|error| TransformError::Base64(error.to_string()))?;
    decoded.truncate(written);
    Ok(decoded)
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
    let budget = TransformExecutionBudget::default();
    execute_transforms_with_options_and_budget(
        signature_node,
        initial_data,
        transforms,
        options,
        &budget,
    )
}

pub(crate) fn execute_transforms_with_options_and_budget<'a>(
    signature_node: Node<'a, 'a>,
    initial_data: TransformData<'a>,
    transforms: &[Transform],
    options: TransformOptions,
    budget: &TransformExecutionBudget,
) -> Result<Vec<u8>, TransformError> {
    ensure_transform_count(transforms.len())?;
    let state = TransformChainState::default();
    let context = TransformExecutionContext {
        options,
        budget,
        state: &state,
    };
    execute_transform_chain(
        signature_node,
        Some(signature_node),
        initial_data,
        transforms,
        None,
        &context,
    )
}

fn ensure_transform_count(count: usize) -> Result<(), TransformError> {
    if count > MAX_TRANSFORMS_PER_REFERENCE {
        return Err(TransformError::TooManyTransforms {
            max: MAX_TRANSFORMS_PER_REFERENCE,
        });
    }
    Ok(())
}

fn execute_transform_chain<'s, 'e, 'd>(
    source_signature: Node<'s, 's>,
    enveloped_signature: Option<Node<'e, 'e>>,
    data: TransformData<'d>,
    transforms: &[Transform],
    canonical_signature_position: Option<Option<usize>>,
    context: &TransformExecutionContext<'_>,
) -> Result<Vec<u8>, TransformError> {
    let Some((transform, remaining)) = transforms.split_first() else {
        return finalize_transform_data(data, &context.budget.c14n);
    };

    if transform_requires_node_set(transform)
        && let TransformData::Binary(bytes) = data
    {
        // The parsed document must outlive every remaining node-set transform.
        // Recursive execution keeps all borrows scoped to this stack frame and
        // returns only owned digest bytes. Every C14N output is charged before
        // recursion, so these retained buffers remain a bounded subset of the
        // signature-wide canonicalization work budget.
        let xml = decode_xml_octets(&bytes)?;
        let document = roxmltree::Document::parse(&xml)
            .map_err(|error| TransformError::XmlParse(error.to_string()))?;
        context.state.document_reparsed();
        let nodes = super::types::NodeSet::entire_document_with_comments(&document)?;
        return match canonical_signature_position {
            Some(Some(position)) => {
                let remapped = document
                    .descendants()
                    .find(|node| node.is_element() && node.range().start == position)
                    .filter(|node| {
                        enveloped_signature
                            .is_some_and(|source| node.tag_name() == source.tag_name())
                    })
                    .ok_or(TransformError::CrossDocumentSignatureNode)?;
                execute_transform_chain(
                    source_signature,
                    Some(remapped),
                    TransformData::NodeSet(nodes),
                    transforms,
                    None,
                    context,
                )
            }
            Some(None) => execute_transform_chain(
                source_signature,
                None,
                TransformData::NodeSet(nodes),
                transforms,
                None,
                context,
            ),
            None => execute_transform_chain(
                source_signature,
                // Binary input not produced by tracked canonicalization is a
                // different document. Keep source_signature for XPath here()
                // semantics, but do not apply its identity to Enveloped.
                None,
                TransformData::NodeSet(nodes),
                transforms,
                None,
                context,
            ),
        };
    }

    if let Transform::C14n(algo) = transform
        && let TransformData::NodeSet(nodes) = &data
    {
        let tracked_element = enveloped_signature
            .filter(|signature| std::ptr::eq(signature.document(), nodes.document()))
            .filter(|signature| nodes.contains(*signature))
            .map(|signature| signature.id());
        let mut output = Vec::new();
        let position = c14n::canonicalize_with_visibility_and_position_bounded(
            nodes.document(),
            Some(nodes),
            algo,
            tracked_element,
            context.budget.c14n.remaining(),
            &mut output,
        )
        .map_err(map_c14n_limit_error)?;
        context.budget.c14n.charge(output.len())?;
        return execute_transform_chain(
            source_signature,
            enveloped_signature,
            TransformData::Binary(output),
            remaining,
            Some(position),
            context,
        );
    }

    if matches!(transform, Transform::Enveloped) {
        let Some(signature) = enveloped_signature else {
            return execute_transform_chain(source_signature, None, data, remaining, None, context);
        };
        let data = apply_transform_with_options_and_state(
            signature,
            transform,
            data,
            context.options,
            context.budget,
            context.state,
        )?;
        return execute_transform_chain(
            source_signature,
            Some(signature),
            data,
            remaining,
            None,
            context,
        );
    }

    let data = apply_transform_with_options_and_state(
        source_signature,
        transform,
        data,
        context.options,
        context.budget,
        context.state,
    )?;
    execute_transform_chain(
        source_signature,
        enveloped_signature,
        data,
        remaining,
        None,
        context,
    )
}

fn decode_xml_octets(bytes: &[u8]) -> Result<Cow<'_, str>, TransformError> {
    // XML 1.0 requires processors to accept UTF-8 and UTF-16. UTF-16 external
    // entities carry a BOM, which also makes byte order detection deterministic.
    let (utf16, little_endian) = if let Some(payload) = bytes.strip_prefix(&[0xff, 0xfe]) {
        (Some(payload), true)
    } else if let Some(payload) = bytes.strip_prefix(&[0xfe, 0xff]) {
        (Some(payload), false)
    } else {
        (None, false)
    };
    if let Some(payload) = utf16 {
        if payload.len() % 2 != 0 {
            return Err(TransformError::XmlParse(
                "UTF-16 XML input has an odd byte length".into(),
            ));
        }
        let code_units = payload
            .chunks_exact(2)
            .map(|chunk| {
                let bytes = [chunk[0], chunk[1]];
                if little_endian {
                    u16::from_le_bytes(bytes)
                } else {
                    u16::from_be_bytes(bytes)
                }
            })
            .collect::<Vec<_>>();
        return String::from_utf16(&code_units)
            .map(Cow::Owned)
            .map_err(|error| TransformError::XmlParse(error.to_string()));
    }

    let payload = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    std::str::from_utf8(payload)
        .map(Cow::Borrowed)
        .map_err(|error| TransformError::XmlParse(error.to_string()))
}

fn transform_requires_node_set(transform: &Transform) -> bool {
    !matches!(transform, Transform::Base64Decode)
}

fn finalize_transform_data(
    data: TransformData<'_>,
    c14n_budget: &C14nOutputBudget,
) -> Result<Vec<u8>, TransformError> {
    // Final coercion: if the result is still a NodeSet, canonicalize with
    // default inclusive C14N 1.0 per XMLDSig spec §4.3.3.2.
    match data {
        TransformData::Binary(bytes) => Ok(bytes),
        TransformData::NodeSet(nodes) => {
            #[expect(clippy::expect_used, reason = "hardcoded URI is a known constant")]
            let algo = C14nAlgorithm::from_uri(DEFAULT_IMPLICIT_C14N_URI)
                .expect("default C14N algorithm URI must be supported by C14nAlgorithm::from_uri");
            let mut output = Vec::new();
            c14n::canonicalize_with_visibility_and_position_bounded(
                nodes.document(),
                Some(&nodes),
                &algo,
                None,
                c14n_budget.remaining(),
                &mut output,
            )
            .map_err(map_c14n_limit_error)?;
            c14n_budget.charge(output.len())?;
            Ok(output)
        }
    }
}

fn map_c14n_limit_error(error: c14n::C14nError) -> TransformError {
    if c14n::is_output_limit_error(&error) {
        TransformError::C14nOutputTooLarge {
            max_bytes: MAX_C14N_OUTPUT_BYTES,
        }
    } else {
        TransformError::C14n(error)
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
    parse_transforms_with_budget(transforms_node, &mut XPathSignatureParseBudget::default())
}

pub(crate) fn parse_transforms_with_budget(
    transforms_node: Node,
    signature_budget: &mut XPathSignatureParseBudget,
) -> Result<Vec<Transform>, TransformError> {
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
    let mut xpath_state = XPathParseState::new(signature_budget);

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
            parse_xpath_transform_with_state(child, &mut xpath_state)?
        } else if uri == XPATH_FILTER2_TRANSFORM_URI {
            parse_xpath_filter2_transform(child, &mut xpath_state)?
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

#[cfg(test)]
pub(super) fn parse_xpath_transform(transform_node: Node) -> Result<Transform, TransformError> {
    parse_xpath_transform_with_state(
        transform_node,
        &mut XPathParseState::new(&mut XPathSignatureParseBudget::default()),
    )
}

fn parse_xpath_transform_with_state(
    transform_node: Node,
    xpath_state: &mut XPathParseState,
) -> Result<Transform, TransformError> {
    let mut xpath_node = None;

    for child in transform_node.children() {
        if child.is_text() && child.text().is_some_and(is_xml_whitespace_only) {
            continue;
        }
        if child.is_comment() || child.is_pi() {
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
    let xpath = parse_xpath_expression(xpath_node, transform_node.id(), xpath_state)?;

    if xpath.expression() == ENVELOPED_SIGNATURE_XPATH_EXPR
        && xpath.namespaces().get("dsig").map(String::as_str) == Some(XMLDSIG_NS)
    {
        Ok(Transform::XpathExcludeAllSignatures)
    } else {
        Ok(Transform::XPath(xpath))
    }
}

fn parse_xpath_filter2_transform(
    transform_node: Node,
    xpath_state: &mut XPathParseState,
) -> Result<Transform, TransformError> {
    let mut filters = Vec::new();
    for child in transform_node.children() {
        if child.is_text() && child.text().is_some_and(is_xml_whitespace_only) {
            continue;
        }
        if child.is_comment() || child.is_pi() {
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
            parse_xpath_expression(child, transform_node.id(), xpath_state)?,
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
    xpath_state: &mut XPathParseState,
) -> Result<XPathExpression, TransformError> {
    let mut source = String::new();
    for child in xpath_node.children() {
        if child.is_text() {
            let text = child.text().unwrap_or_default();
            if source
                .len()
                .checked_add(text.len())
                .is_none_or(|length| length > MAX_XPATH_EXPRESSION_BYTES)
            {
                return Err(TransformError::XPath(format!(
                    "XPath expression exceeds {MAX_XPATH_EXPRESSION_BYTES} bytes"
                )));
            }
            source.push_str(text);
        } else if child.is_element() {
            return Err(TransformError::XPath(
                "XPath expressions must contain text only".into(),
            ));
        }
    }
    let source = source.trim_matches(is_xpath_whitespace);
    if source.is_empty() {
        return Err(TransformError::XPath(
            "XPath expression must not be empty".into(),
        ));
    }
    xpath_state.signature_budget.charge()?;
    compile_xpath(source).map_err(TransformError::XPath)?;

    let mut xpath = XPathExpression {
        expression: source.to_owned(),
        namespaces: BTreeMap::new(),
        here_nodes: Some(XPathHereNodes {
            xpath: xpath_node.id(),
            transform: transform_node,
            // NodeId is only meaningful within one roxmltree Document. Keep an
            // owned content identity so parsed transforms cannot outlive the
            // source and later alias unrelated nodes carrying the same indices.
            document: xpath_state.document_identity(xpath_node.document()),
        }),
    };
    for namespace in xpath_node.namespaces() {
        if let Some(prefix) = namespace.name() {
            xpath_state
                .namespace_budget
                .charge(prefix, namespace.uri())?;
            xpath
                .namespaces
                .insert(prefix.to_owned(), namespace.uri().to_owned());
        }
    }
    Ok(xpath)
}

struct XPathParseState<'a> {
    namespace_budget: XPathNamespaceBudget,
    document_identity: Option<XPathDocumentIdentity>,
    signature_budget: &'a mut XPathSignatureParseBudget,
}

impl<'a> XPathParseState<'a> {
    fn new(signature_budget: &'a mut XPathSignatureParseBudget) -> Self {
        Self {
            namespace_budget: XPathNamespaceBudget::default(),
            document_identity: None,
            signature_budget,
        }
    }

    fn document_identity(&mut self, document: &Document<'_>) -> XPathDocumentIdentity {
        *self
            .document_identity
            .get_or_insert_with(|| XPathDocumentIdentity::from_document(document))
    }
}

#[derive(Default)]
/// Parser state shared by every Reference in one SignedInfo.
pub(crate) struct XPathSignatureParseBudget {
    expressions: usize,
}

impl XPathSignatureParseBudget {
    pub(crate) fn charge(&mut self) -> Result<(), TransformError> {
        self.expressions = self.expressions.checked_add(1).ok_or_else(Self::error)?;
        if self.expressions > MAX_XPATH_EXPRESSIONS_PER_SIGNATURE {
            return Err(Self::error());
        }
        Ok(())
    }

    fn error() -> TransformError {
        TransformError::XPath(format!(
            "signature-wide XPath expression budget exceeds {MAX_XPATH_EXPRESSIONS_PER_SIGNATURE} entries"
        ))
    }
}

#[derive(Default)]
struct XPathNamespaceBudget {
    bindings: usize,
    bytes: usize,
}

impl XPathNamespaceBudget {
    fn charge(&mut self, prefix: &str, uri: &str) -> Result<(), TransformError> {
        self.bindings = self.bindings.checked_add(1).ok_or_else(Self::error)?;
        self.bytes = self
            .bytes
            .checked_add(prefix.len())
            .and_then(|bytes| bytes.checked_add(uri.len()))
            .ok_or_else(Self::error)?;
        if self.bindings > MAX_XPATH_NAMESPACE_BINDINGS || self.bytes > MAX_XPATH_NAMESPACE_BYTES {
            return Err(Self::error());
        }
        Ok(())
    }

    fn error() -> TransformError {
        TransformError::XPath(format!(
            "XPath namespace binding budget exceeds {MAX_XPATH_NAMESPACE_BINDINGS} entries or \
             {MAX_XPATH_NAMESPACE_BYTES} bytes per transform chain"
        ))
    }
}

pub(crate) fn validate_xpath_namespace_budget(
    transforms: &[Transform],
    inherited_namespace: Option<(&str, &str)>,
) -> Result<(), TransformError> {
    let mut budget = XPathNamespaceBudget::default();
    for transform in transforms {
        match transform {
            Transform::XPath(xpath) => {
                for (prefix, uri) in xpath.namespaces() {
                    budget.charge(prefix, uri)?;
                }
                if let Some((prefix, uri)) = inherited_namespace
                    && !xpath.namespaces().contains_key(prefix)
                {
                    budget.charge(prefix, uri)?;
                }
            }
            Transform::XPathFilter2(filters) => {
                for filter in filters {
                    for (prefix, uri) in filter.xpath().namespaces() {
                        budget.charge(prefix, uri)?;
                    }
                    if let Some((prefix, uri)) = inherited_namespace
                        && !filter.xpath().namespaces().contains_key(prefix)
                    {
                        budget.charge(prefix, uri)?;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
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
        let node_set = NodeSet::entire_document_without_comments(&doc).unwrap();
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
        let node_set = NodeSet::entire_document_without_comments(&doc1).unwrap();
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

        let node_set = NodeSet::entire_document_without_comments(&doc).unwrap();
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
        let input = TransformData::NodeSet(NodeSet::subtree(data).unwrap());

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
        let mut nodes = NodeSet::subtree(doc.root_element()).unwrap();
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
    fn base64_transform_ignores_rfc2045_non_alphabet_bytes() {
        let doc = Document::parse("<root/>").unwrap();
        let input = TransformData::Binary(b"SGVs!\xFFbG8=".to_vec());

        let result = apply_transform(doc.root_element(), &Transform::Base64Decode, input).unwrap();

        assert_eq!(result.into_binary().unwrap(), b"Hello");
    }

    #[test]
    fn base64_transform_rejects_invalid_padding() {
        let doc = Document::parse("<root/>").unwrap();
        let result = apply_transform(
            doc.root_element(),
            &Transform::Base64Decode,
            TransformData::Binary(b"SGVsbG8===".to_vec()),
        );

        assert!(matches!(result, Err(TransformError::Base64(_))));
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
    fn base64_transform_rejects_oversized_raw_binary_before_normalization() {
        // XML whitespace does not reach the normalized buffer, but scanning an
        // unbounded whitespace-only reference is still attacker-controlled work.
        let doc = Document::parse("<root/>").unwrap();
        let input = TransformData::Binary(vec![b' '; MAX_BASE64_TRANSFORM_INPUT_BYTES + 1]);

        let result = apply_transform(doc.root_element(), &Transform::Base64Decode, input);

        assert!(matches!(
            result,
            Err(TransformError::Base64InputTooLarge {
                max_bytes: MAX_BASE64_TRANSFORM_INPUT_BYTES
            })
        ));
    }

    #[test]
    fn base64_transform_rejects_node_set_that_decodes_past_output_budget() {
        // The output limit must be checked before the decoder allocates a
        // second buffer beside the normalized encoded text.
        let encoded_len = MAX_BASE64_TRANSFORM_OUTPUT_BYTES.div_ceil(3) * 4 + 4;
        let xml = format!("<root>{}</root>", "A".repeat(encoded_len));
        let doc = Document::parse(&xml).unwrap();
        let input = TransformData::NodeSet(NodeSet::subtree(doc.root_element()).unwrap());

        let result = apply_transform(doc.root_element(), &Transform::Base64Decode, input);

        assert!(matches!(
            result,
            Err(TransformError::Base64OutputTooLarge {
                max_bytes: MAX_BASE64_TRANSFORM_OUTPUT_BYTES
            })
        ));
    }

    #[test]
    fn base64_transform_handles_highly_fragmented_node_set_input() {
        // Comments can split an untrusted payload into thousands of tiny text
        // nodes. Normalization must retain linear allocation behavior while
        // preserving document-order concatenation.
        let expected = vec![0x42_u8; 3 * 1_024];
        let encoded = STANDARD.encode(&expected);
        let mut xml = String::from("<root>");
        for byte in encoded.bytes() {
            xml.push(char::from(byte));
            xml.push_str("<!-- split -->");
        }
        xml.push_str("</root>");
        let doc = Document::parse(&xml).unwrap();
        let input = TransformData::NodeSet(NodeSet::subtree(doc.root_element()).unwrap());

        let result = apply_transform(doc.root_element(), &Transform::Base64Decode, input).unwrap();

        assert_eq!(result.into_binary().unwrap(), expected);
    }

    #[test]
    fn pipeline_rejects_cumulative_base64_input_past_budget() {
        // Each transform is individually under 16 MiB, but charging only the
        // current input permits one reference chain to exceed the total bound.
        let doc = Document::parse("<root/>").unwrap();
        let inner = vec![b'A'; MAX_BASE64_TRANSFORM_OUTPUT_BYTES];
        let outer = STANDARD.encode(&inner);
        let transforms = [Transform::Base64Decode, Transform::Base64Decode];

        let result = execute_transforms(
            doc.root_element(),
            TransformData::Binary(outer.into_bytes()),
            &transforms,
        );

        assert!(matches!(
            result,
            Err(TransformError::Base64InputTooLarge {
                max_bytes: MAX_BASE64_TRANSFORM_INPUT_BYTES
            })
        ));
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
    fn byte_budgets_remain_exhausted_after_overflow() {
        // An overflow is a terminal state: callers must not be able to recover
        // budget by following a rejected large charge with a smaller one.
        let c14n = C14nOutputBudget::default();
        assert!(c14n.charge(MAX_C14N_OUTPUT_BYTES + 1).is_err());
        assert!(c14n.charge(1).is_err());

        let base64 = Base64WorkBudget::default();
        assert!(base64.charge(MAX_BASE64_TRANSFORM_INPUT_BYTES + 1).is_err());
        assert!(base64.charge(1).is_err());
    }

    #[test]
    fn pipeline_rejects_cumulative_c14n_output() {
        // Every C14N result is individually moderate, but a long chain can
        // multiply canonicalization work and adapter-buffer retention. The
        // shared meter must reject their cumulative output.
        let xml = format!("<root>{}</root>", "x".repeat(512 * 1024));
        let document = Document::parse(&xml).unwrap();
        let algorithm =
            C14nAlgorithm::from_uri("http://www.w3.org/TR/2001/REC-xml-c14n-20010315").unwrap();
        let transforms = vec![Transform::C14n(algorithm); 40];

        let result = execute_transforms(
            document.root_element(),
            TransformData::NodeSet(NodeSet::entire_document_without_comments(&document).unwrap()),
            &transforms,
        );

        assert!(matches!(
            result,
            Err(TransformError::C14nOutputTooLarge {
                max_bytes: MAX_C14N_OUTPUT_BYTES
            })
        ));
    }

    #[test]
    fn explicit_and_implicit_c14n_stop_at_the_execution_ceiling() {
        // Both routes must use the bounded serializer. A post-serialization
        // charge would return the same error but only after retaining all bytes.
        let xml = format!("<root>{}</root>", "x".repeat(4_096));
        let document = Document::parse(&xml).unwrap();
        let nodes = || {
            TransformData::NodeSet(NodeSet::entire_document_without_comments(&document).unwrap())
        };
        let algorithm =
            C14nAlgorithm::from_uri("http://www.w3.org/TR/2001/REC-xml-c14n-20010315").unwrap();

        for transforms in [&[][..], &[Transform::C14n(algorithm)][..]] {
            let error = execute_transforms_with_options_and_budget(
                document.root_element(),
                nodes(),
                transforms,
                TransformOptions::default(),
                &TransformExecutionBudget::with_c14n_limit(64),
            )
            .expect_err("canonicalization must stop at the execution ceiling");

            assert!(matches!(
                error,
                TransformError::C14nOutputTooLarge {
                    max_bytes: MAX_C14N_OUTPUT_BYTES
                }
            ));
        }
    }

    #[test]
    fn execution_budget_bounds_c14n_output_across_references() {
        // Each Reference remains below the signature-wide output ceiling, but
        // signing and verification share one execution budget. Repeating the
        // same C14N work across References must not reset that meter.
        let xml = format!("<root>{}</root>", "x".repeat(512 * 1024));
        let document = Document::parse(&xml).unwrap();
        let algorithm =
            C14nAlgorithm::from_uri("http://www.w3.org/TR/2001/REC-xml-c14n-20010315").unwrap();
        let transforms = vec![Transform::C14n(algorithm); 20];
        let execution_budget = TransformExecutionBudget::default();
        let input = || {
            TransformData::NodeSet(NodeSet::entire_document_without_comments(&document).unwrap())
        };

        execute_transforms_with_options_and_budget(
            document.root_element(),
            input(),
            &transforms,
            TransformOptions::default(),
            &execution_budget,
        )
        .expect("the first Reference must fit the cumulative C14N output budget");
        let result = execute_transforms_with_options_and_budget(
            document.root_element(),
            input(),
            &transforms,
            TransformOptions::default(),
            &execution_budget,
        );

        assert!(matches!(
            result,
            Err(TransformError::C14nOutputTooLarge {
                max_bytes: MAX_C14N_OUTPUT_BYTES
            })
        ));
    }

    #[test]
    fn execution_budget_bounds_implicit_c14n_across_references() {
        // References ending in node sets use implicit C14N 1.0. That terminal
        // coercion must share the same signature-wide byte ceiling as explicit
        // canonicalization transforms.
        let xml = format!("<root>{}</root>", "x".repeat(6 * 1024 * 1024));
        let document = Document::parse(&xml).unwrap();
        let execution_budget = TransformExecutionBudget::default();
        let input = || {
            TransformData::NodeSet(NodeSet::entire_document_without_comments(&document).unwrap())
        };

        for _ in 0..2 {
            execute_transforms_with_options_and_budget(
                document.root_element(),
                input(),
                &[],
                TransformOptions::default(),
                &execution_budget,
            )
            .expect("two implicit C14N outputs must fit the shared budget");
        }
        let result = execute_transforms_with_options_and_budget(
            document.root_element(),
            input(),
            &[],
            TransformOptions::default(),
            &execution_budget,
        );

        assert!(matches!(
            result,
            Err(TransformError::C14nOutputTooLarge {
                max_bytes: MAX_C14N_OUTPUT_BYTES
            })
        ));
    }

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

        let initial =
            TransformData::NodeSet(NodeSet::entire_document_without_comments(&doc).unwrap());
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
    fn pipeline_c14n_then_enveloped_remaps_the_exact_signature() {
        // Reparsing canonical octets creates a new Document. The adapter must
        // preserve which Signature owns this transform rather than removing an
        // arbitrary signature or rejecting the new node set as cross-document.
        let xml = r#"<root>
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#" Id="other"/>
            <data>hello</data>
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#" Id="owner"/>
        </root>"#;
        let document = Document::parse(xml).unwrap();
        let signature = document
            .descendants()
            .find(|node| node.attribute("Id") == Some("owner"))
            .unwrap();
        let initial =
            TransformData::NodeSet(NodeSet::entire_document_without_comments(&document).unwrap());
        let transforms = vec![
            Transform::C14n(
                C14nAlgorithm::from_uri("http://www.w3.org/TR/2001/REC-xml-c14n-20010315").unwrap(),
            ),
            Transform::Enveloped,
        ];

        let output = execute_transforms(signature, initial, &transforms).unwrap();
        let output = String::from_utf8(output).unwrap();

        assert!(output.contains("Id=\"other\""));
        assert!(!output.contains("Id=\"owner\""));
        assert!(output.contains("<data>hello</data>"));
    }

    #[test]
    fn pipeline_remaps_signature_after_xpath_removes_an_earlier_sibling() {
        // The identity of the owning Signature must survive canonicalization;
        // its source-tree sibling index is not stable after XPath filtering.
        let xml = r#"<root>
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#" Id="other"/>
            <discard/>
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#" Id="owner"/>
        </root>"#;
        let document = Document::parse(xml).unwrap();
        let signature = document
            .descendants()
            .find(|node| node.attribute("Id") == Some("owner"))
            .unwrap();
        let initial =
            TransformData::NodeSet(NodeSet::entire_document_without_comments(&document).unwrap());
        let transforms = vec![
            Transform::XPath(XPathExpression::new("not(self::discard)")),
            Transform::C14n(
                C14nAlgorithm::from_uri("http://www.w3.org/TR/2001/REC-xml-c14n-20010315").unwrap(),
            ),
            Transform::Enveloped,
        ];

        let output = execute_transforms(signature, initial, &transforms).unwrap();
        let output = String::from_utf8(output).unwrap();

        assert!(output.contains("Id=\"other\""));
        assert!(!output.contains("Id=\"owner\""));
        assert!(!output.contains("discard"));
    }

    #[test]
    fn pipeline_enveloped_ignores_signature_absent_after_base64_adaptation() {
        // A binary-producing transform may replace the source document rather
        // than serialize it. The enveloped transform must not carry the source
        // Signature identity into that unrelated decoded document.
        let source = Document::parse(
            r#"<root><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"/></root>"#,
        )
        .unwrap();
        let signature = source
            .descendants()
            .find(|node| node.tag_name().name() == "Signature")
            .unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"<payload>ok</payload>");
        let transforms = vec![
            Transform::Base64Decode,
            Transform::XPath(XPathExpression::new("true()")),
            Transform::Enveloped,
        ];

        let output = execute_transforms(
            signature,
            TransformData::Binary(encoded.into()),
            &transforms,
        )
        .unwrap();

        assert_eq!(output, b"<payload>ok</payload>");
    }

    #[test]
    fn pipeline_no_transforms_applies_default_c14n() {
        // No explicit transforms → pipeline falls back to inclusive C14N 1.0
        let xml = r#"<root b="2" a="1"><child/></root>"#;
        let doc = Document::parse(xml).unwrap();

        let initial =
            TransformData::NodeSet(NodeSet::entire_document_without_comments(&doc).unwrap());
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

        let node_set = NodeSet::entire_document_without_comments(&doc).unwrap();
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
    fn parse_transforms_rejects_non_xpath_boundary_whitespace() {
        // XPath 1.0 S excludes NBSP, so parser-level trimming must not turn
        // this malformed signed expression into a conforming `true()` call.
        let xml = format!(
            r#"<Transforms xmlns="{XMLDSIG_NS}"><Transform Algorithm="{XPATH_TRANSFORM_URI}"><XPath> true()</XPath></Transform></Transforms>"#
        );
        let doc = Document::parse(&xml).unwrap();

        let result = parse_transforms(doc.root_element());

        assert!(matches!(result, Err(TransformError::XPath(_))));
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
    fn parse_xpath_transform_ignores_comments_and_processing_instructions() {
        // Comments and PIs are not transform parameters and may surround the
        // required XPath element in an otherwise valid signature.
        let xml = format!(
            r#"<Transforms xmlns="{XMLDSIG_NS}"><Transform Algorithm="{XPATH_TRANSFORM_URI}"><!-- before --><?probe value?><XPath>true()</XPath><!-- after --><?done?></Transform></Transforms>"#
        );
        let doc = Document::parse(&xml).unwrap();

        let transforms = parse_transforms(doc.root_element()).unwrap();

        assert!(matches!(transforms.as_slice(), [Transform::XPath(_)]));
    }

    #[test]
    fn parse_filter2_transform_ignores_comments_and_processing_instructions() {
        // Filter 2.0 has the same XML comment/PI treatment while retaining its
        // stricter element and attribute grammar.
        let xml = format!(
            r#"<Transforms xmlns="{XMLDSIG_NS}"><Transform Algorithm="{XPATH_FILTER2_TRANSFORM_URI}"><!-- before --><?probe value?><XPath xmlns="{XPATH_FILTER2_TRANSFORM_URI}" Filter="intersect">/root</XPath><!-- after --><?done?></Transform></Transforms>"#
        );
        let doc = Document::parse(&xml).unwrap();

        let transforms = parse_transforms(doc.root_element()).unwrap();

        assert!(matches!(
            transforms.as_slice(),
            [Transform::XPathFilter2(filters)] if filters.len() == 1
        ));
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
    fn parse_transforms_bounds_cumulative_xpath_namespace_storage() {
        // In-scope bindings are copied into every Filter 2.0 expression, so a
        // chain-level budget must reject their multiplicative amplification.
        let declarations = (0..32)
            .map(|index| {
                format!(
                    "xmlns:n{index}=\"urn:namespace:{index}:{}\"",
                    "x".repeat(64)
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        let filters = (0..MAX_XPATH_FILTERS)
            .map(|_| {
                format!(
                    r#"<XPath xmlns="{XPATH_FILTER2_TRANSFORM_URI}" Filter="intersect">true()</XPath>"#
                )
            })
            .collect::<String>();
        let xml = format!(
            r#"<Transforms xmlns="{XMLDSIG_NS}" {declarations}><Transform Algorithm="{XPATH_FILTER2_TRANSFORM_URI}">{filters}</Transform></Transforms>"#
        );
        let doc = Document::parse(&xml).unwrap();

        let error = parse_transforms(doc.root_element())
            .expect_err("cumulative XPath namespace storage must be bounded");

        assert!(error.to_string().contains("namespace binding budget"));
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
    fn parse_transform_chain_hashes_xpath_document_once() {
        // Every parsed XPath stores the same document provenance. A maximal
        // Filter 2.0 list must not rescan and hash the complete XML per entry.
        let filters = format!(
            r#"<XPath xmlns="{XPATH_FILTER2_TRANSFORM_URI}" Filter="intersect">true()</XPath>"#
        )
        .repeat(MAX_XPATH_FILTERS);
        let transform = format!(
            r#"<Transform Algorithm="{XPATH_FILTER2_TRANSFORM_URI}">{filters}</Transform>"#
        );
        let xml =
            format!(r#"<Transforms xmlns="{XMLDSIG_NS}">{transform}{transform}</Transforms>"#);
        let document = Document::parse(&xml).unwrap();

        XPATH_DOCUMENT_IDENTITY_COMPUTATIONS.with(|count| count.set(0));
        let transforms = parse_transforms(document.root_element()).unwrap();
        let computations = XPATH_DOCUMENT_IDENTITY_COMPUTATIONS.with(Cell::get);

        assert_eq!(transforms.len(), 2);
        assert!(transforms.iter().all(
            |transform| matches!(transform, Transform::XPathFilter2(filters) if filters.len() == MAX_XPATH_FILTERS)
        ));
        assert_eq!(
            computations, 1,
            "one parsed transform chain must hash its source document once"
        );
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
            TransformData::NodeSet(NodeSet::entire_document_without_comments(&doc).unwrap()),
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
            TransformData::NodeSet(NodeSet::entire_document_without_comments(&doc).unwrap()),
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

    #[test]
    fn parsed_xpath_rejects_node_id_collision_from_another_document() {
        // NodeId is only a document-local index. Reusing a parsed transform
        // against another document must not let the same numeric id redirect
        // here() to an unrelated node in that document.
        let source = Document::parse(
            r#"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>count(. | here()) = 1</ds:XPath></ds:Transform></ds:Transforms></root>"#,
        )
        .unwrap();
        let transforms_node = source
            .descendants()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "Transforms")))
            .unwrap();
        let transforms = parse_transforms(transforms_node).unwrap();

        let target = Document::parse(
            "<root><container><parameter><unrelated/></parameter></container></root>",
        )
        .unwrap();
        let error = execute_transforms(
            target.root_element(),
            TransformData::NodeSet(NodeSet::entire_document_without_comments(&target).unwrap()),
            &transforms,
        )
        .expect_err("parsed here() provenance must reject another XML document");

        assert!(
            matches!(error, TransformError::XPath(ref message) if message.contains("same XML document"))
        );
    }

    #[test]
    fn transform_chain_computes_document_identity_once() {
        // Parsed here() provenance needs a content hash, but every XPath step
        // over the same live document must reuse it rather than rehashing XML.
        let document = Document::parse(
            r#"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Signature><ds:SignedInfo><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>count(. | here()) = 1 or true()</ds:XPath></ds:Transform><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>count(. | here()) = 1 or true()</ds:XPath></ds:Transform></ds:Transforms></ds:Reference></ds:SignedInfo></ds:Signature></root>"#,
        )
        .unwrap();
        let transforms_node = document
            .descendants()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "Transforms")))
            .unwrap();
        let transforms = parse_transforms(transforms_node).unwrap();
        let signature = document
            .descendants()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "Signature")))
            .unwrap();
        let initial = NodeSet::entire_document_without_comments(&document)
            .map(TransformData::NodeSet)
            .unwrap();

        XPATH_DOCUMENT_IDENTITY_COMPUTATIONS.with(|count| count.set(0));
        execute_transforms(signature, initial, &transforms).unwrap();
        let computations = XPATH_DOCUMENT_IDENTITY_COMPUTATIONS.with(Cell::get);

        assert_eq!(
            computations, 1,
            "one live document must be hashed once per chain"
        );
    }

    #[test]
    fn transform_chain_state_keys_identity_by_document() {
        // The cache must defend its own document association rather than rely
        // exclusively on every caller remembering explicit invalidation.
        let first_document = Document::parse("<first/>").unwrap();
        let second_document = Document::parse("<second/>").unwrap();
        let state = TransformChainState::default();

        XPATH_DOCUMENT_IDENTITY_COMPUTATIONS.with(|count| count.set(0));
        let first_identity = state.xpath_document_identity(&first_document);
        let second_identity = state.xpath_document_identity(&second_document);
        let computations = XPATH_DOCUMENT_IDENTITY_COMPUTATIONS.with(Cell::get);

        assert_ne!(first_identity, second_identity);
        assert_eq!(
            computations, 2,
            "each distinct live document must receive its own cached identity"
        );
    }

    #[test]
    fn template_xpath_skips_document_identity_hash() {
        // Builder-created expressions have no document-local here() node IDs,
        // so provenance validation must not scan and hash the input XML.
        let document = Document::parse("<root><value/></root>").unwrap();
        let transforms = [
            Transform::XPath(XPathExpression::new("true()")),
            Transform::XPath(XPathExpression::new("true()")),
        ];
        let initial = NodeSet::entire_document_without_comments(&document)
            .map(TransformData::NodeSet)
            .unwrap();

        XPATH_DOCUMENT_IDENTITY_COMPUTATIONS.with(|count| count.set(0));
        execute_transforms(document.root_element(), initial, &transforms).unwrap();
        let computations = XPATH_DOCUMENT_IDENTITY_COMPUTATIONS.with(Cell::get);

        assert_eq!(
            computations, 0,
            "XPath without parsed here() provenance must not hash XML"
        );
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
        let initial =
            TransformData::NodeSet(NodeSet::entire_document_without_comments(&doc).unwrap());
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
