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
//! | Base64 decode | Binary → Binary | P1 (future) |

use roxmltree::Node;

use super::types::{TransformData, TransformError};
use crate::c14n::{self, C14nAlgorithm};

/// The algorithm URI for the enveloped signature transform.
pub const ENVELOPED_SIGNATURE_URI: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
/// The algorithm URI for the XPath 1.0 transform.
const XPATH_URI: &str = "http://www.w3.org/TR/1999/REC-xpath-19991116";
/// xmlsec1 donor vectors use this XPath expression as a compatibility form of
/// enveloped-signature exclusion.
const ENVELOPED_SIGNATURE_XPATH_EXPR: &str = "not(ancestor-or-self::dsig:Signature)";

/// XMLDSig namespace URI for `<Transform>` elements.
const XMLDSIG_NS_URI: &str = "http://www.w3.org/2000/09/xmldsig#";

/// Namespace URI for Exclusive C14N `<InclusiveNamespaces>` elements.
const EXCLUSIVE_C14N_NS_URI: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

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

    /// XML Canonicalization (any supported variant).
    ///
    /// Input: `NodeSet` → Output: `Binary`
    C14n(C14nAlgorithm),
}

/// Apply a single transform to the pipeline data.
///
/// `signature_node` is the `<Signature>` element that contains the
/// `<Reference>` being processed. It is used by the enveloped transform
/// to know which signature subtree to exclude. The node must belong to the
/// same document as the `NodeSet` in `input`; a cross-document mismatch
/// returns [`TransformError::CrossDocumentSignatureNode`].
pub(crate) fn apply_transform<'a>(
    signature_node: Node<'a, 'a>,
    transform: &Transform,
    input: TransformData<'a>,
) -> Result<TransformData<'a>, TransformError> {
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
                    && node.tag_name().namespace() == Some(XMLDSIG_NS_URI)
            }) {
                nodes.exclude_subtree(node);
            }

            Ok(TransformData::NodeSet(nodes))
        }
        Transform::C14n(algo) => {
            let nodes = input.into_node_set()?;
            let mut output = Vec::new();
            let predicate = |node: Node| nodes.contains(node);
            c14n::canonicalize(nodes.document(), Some(&predicate), algo, &mut output)
                .map_err(|e| TransformError::C14n(e.to_string()))?;
            Ok(TransformData::Binary(output))
        }
    }
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
    let mut data = initial_data;

    for transform in transforms {
        data = apply_transform(signature_node, transform, data)?;
    }

    // Final coercion: if the result is still a NodeSet, canonicalize with
    // default inclusive C14N 1.0 per XMLDSig spec §4.3.3.2.
    match data {
        TransformData::Binary(bytes) => Ok(bytes),
        TransformData::NodeSet(nodes) => {
            #[expect(clippy::expect_used, reason = "hardcoded URI is a known constant")]
            let algo = C14nAlgorithm::from_uri("http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
                .expect("default C14N algorithm URI must be supported by C14nAlgorithm::from_uri");
            let mut output = Vec::new();
            let predicate = |node: Node| nodes.contains(node);
            c14n::canonicalize(nodes.document(), Some(&predicate), &algo, &mut output)
                .map_err(|e| TransformError::C14n(e.to_string()))?;
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
    if transforms_tag.name() != "Transforms" || transforms_tag.namespace() != Some(XMLDSIG_NS_URI) {
        return Err(TransformError::UnsupportedTransform(
            "expected <ds:Transforms> element in XMLDSig namespace".into(),
        ));
    }

    let mut chain = Vec::new();

    for child in transforms_node.children() {
        if !child.is_element() {
            continue;
        }

        // Only <ds:Transform> children are allowed; fail closed on any other element.
        let tag = child.tag_name();
        if tag.name() != "Transform" || tag.namespace() != Some(XMLDSIG_NS_URI) {
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
        } else if uri == XPATH_URI {
            parse_xpath_compat_transform(child)?
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

/// Parse the narrow XPath compatibility case we currently support.
///
/// We do not implement general XPath evaluation here. The only accepted form is
/// the xmlsec1 donor-vector expression that excludes all `ds:Signature`
/// subtrees from the current node-set.
fn parse_xpath_compat_transform(transform_node: Node) -> Result<Transform, TransformError> {
    let mut xpath_node = None;

    for child in transform_node.children().filter(|node| node.is_element()) {
        let tag = child.tag_name();
        if tag.name() == "XPath" && tag.namespace() == Some(XMLDSIG_NS_URI) {
            if xpath_node.is_some() {
                return Err(TransformError::UnsupportedTransform(
                    "XPath transform must contain exactly one <ds:XPath> child element".into(),
                ));
            }
            xpath_node = Some(child);
        } else {
            return Err(TransformError::UnsupportedTransform(
                "XPath transform allows only a single <ds:XPath> child element in the XMLDSig namespace"
                    .into(),
            ));
        }
    }

    let xpath_node = xpath_node.ok_or_else(|| {
        TransformError::UnsupportedTransform(
            "XPath transform requires a single <ds:XPath> child element in the XMLDSig namespace"
                .into(),
        )
    })?;

    let expr = xpath_node
        .text()
        .map(|text| text.trim().to_string())
        .unwrap_or_default();

    if expr == ENVELOPED_SIGNATURE_XPATH_EXPR {
        let dsig_ns = xpath_node.lookup_namespace_uri(Some("dsig"));
        if dsig_ns == Some(XMLDSIG_NS_URI) {
            Ok(Transform::XpathExcludeAllSignatures)
        } else {
            Err(TransformError::UnsupportedTransform(
                "XPath compatibility form requires the `dsig` prefix to be bound to the XMLDSig namespace"
                    .into(),
            ))
        }
    } else {
        Err(TransformError::UnsupportedTransform(
            "unsupported XPath expression in compatibility transform; only `not(ancestor-or-self::dsig:Signature)` is supported"
                .into(),
        ))
    }
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
    fn parse_transforms_rejects_other_xpath_expressions() {
        let xml = r#"<Transforms xmlns="http://www.w3.org/2000/09/xmldsig#">
            <Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
                <XPath>self::node()</XPath>
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
        assert!(matches!(
            result.unwrap_err(),
            TransformError::UnsupportedTransform(_)
        ));
    }

    #[test]
    fn parse_transforms_rejects_xpath_with_wrong_dsig_prefix_binding() {
        let xml = r#"<Transforms xmlns="http://www.w3.org/2000/09/xmldsig#">
            <Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
                <XPath xmlns:dsig="http://example.com/not-xmldsig">
                    not(ancestor-or-self::dsig:Signature)
                </XPath>
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
        assert!(matches!(
            result.unwrap_err(),
            TransformError::UnsupportedTransform(_)
        ));
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
        assert!(matches!(
            result.unwrap_err(),
            TransformError::UnsupportedTransform(_)
        ));
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
        assert!(matches!(
            result.unwrap_err(),
            TransformError::UnsupportedTransform(_)
        ));
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
                    && node.tag_name().namespace() == Some(XMLDSIG_NS_URI)
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
