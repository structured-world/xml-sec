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

use roxmltree::{Document, Node, NodeId};

use super::types::{TransformData, TransformError};
use crate::c14n::{self, C14nAlgorithm};

/// The algorithm URI for the enveloped signature transform.
pub const ENVELOPED_SIGNATURE_URI: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

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

    /// XML Canonicalization (any supported variant).
    ///
    /// Input: `NodeSet` → Output: `Binary`
    C14n(C14nAlgorithm),
}

/// Apply a single transform to the pipeline data.
///
/// `signature_node_id` is the `NodeId` of the `<Signature>` element that
/// contains the `<Reference>` being processed. It is used by the enveloped
/// transform to know which signature subtree to exclude.
pub fn apply_transform<'a>(
    doc: &'a Document<'a>,
    signature_node_id: NodeId,
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
            let signature_node = doc
                .get_node(signature_node_id)
                .ok_or(TransformError::EnvelopedSignatureNotFound)?;
            nodes.exclude_subtree(signature_node);
            Ok(TransformData::NodeSet(nodes))
        }
        Transform::C14n(algo) => {
            let nodes = input.into_node_set()?;
            let mut output = Vec::new();
            // Build a predicate closure that checks node membership in
            // the NodeSet. The C14N serializer calls this for each node
            // during document-order traversal.
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
///    to produce bytes (per [XMLDSig §4.3.3.2]).
///
/// Returns the final byte sequence ready for digest computation.
pub fn execute_transforms<'a>(
    doc: &'a Document<'a>,
    signature_node_id: NodeId,
    initial_data: TransformData<'a>,
    transforms: &[Transform],
) -> Result<Vec<u8>, TransformError> {
    let mut data = initial_data;

    for transform in transforms {
        data = apply_transform(doc, signature_node_id, transform, data)?;
    }

    // Final coercion: if the result is still a NodeSet, canonicalize with
    // default inclusive C14N 1.0 per XMLDSig spec §4.3.3.2.
    match data {
        TransformData::Binary(bytes) => Ok(bytes),
        TransformData::NodeSet(nodes) => {
            let algo = C14nAlgorithm::from_uri("http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
                .ok_or_else(|| {
                TransformError::C14n("unsupported default C14N algorithm URI".to_string())
            })?;
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
    let mut chain = Vec::new();

    for child in transforms_node.children() {
        if !child.is_element() {
            continue;
        }
        // Match on local name, ignoring namespace prefix (could be ds:Transform or Transform)
        if child.tag_name().name() != "Transform" {
            continue;
        }
        let uri = child.attribute("Algorithm").ok_or_else(|| {
            TransformError::UnsupportedTransform(
                "missing Algorithm attribute on <Transform>".into(),
            )
        })?;

        let transform = if uri == ENVELOPED_SIGNATURE_URI {
            Transform::Enveloped
        } else if let Some(mut algo) = C14nAlgorithm::from_uri(uri) {
            // For exclusive C14N, check for InclusiveNamespaces child
            if algo.mode() == c14n::C14nMode::Exclusive1_0 {
                if let Some(prefix_list) = parse_inclusive_prefixes(child) {
                    algo = algo.with_prefix_list(&prefix_list);
                }
            }
            Transform::C14n(algo)
        } else {
            return Err(TransformError::UnsupportedTransform(uri.to_string()));
        };
        chain.push(transform);
    }

    Ok(chain)
}

/// Parse the `PrefixList` attribute from an `<ec:InclusiveNamespaces>` child
/// element, if present.
///
/// Per the [Exclusive C14N spec](https://www.w3.org/TR/xml-exc-c14n/#def-InclusiveNamespaces-PrefixList),
/// the element MUST be in the `http://www.w3.org/2001/10/xml-exc-c14n#` namespace.
/// Elements with the same local name but a different namespace are ignored.
///
/// The element is typically:
/// ```xml
/// <ec:InclusiveNamespaces
///     xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"
///     PrefixList="ds saml #default"/>
/// ```
fn parse_inclusive_prefixes(transform_node: Node) -> Option<String> {
    for child in transform_node.children() {
        if child.is_element() {
            let tag = child.tag_name();
            if tag.name() == "InclusiveNamespaces" && tag.namespace() == Some(EXCLUSIVE_C14N_NS_URI)
            {
                return child.attribute("PrefixList").map(String::from);
            }
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::xmldsig::NodeSet;

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
        let result = apply_transform(&doc, sig_node.id(), &Transform::Enveloped, data).unwrap();
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
        let sig_id = doc.root_element().id();

        // Binary input should fail with TypeMismatch
        let data = TransformData::Binary(vec![1, 2, 3]);
        let result = apply_transform(&doc, sig_id, &Transform::Enveloped, data);
        assert!(result.is_err());
        match result.unwrap_err() {
            TransformError::TypeMismatch { expected, got } => {
                assert_eq!(expected, "NodeSet");
                assert_eq!(got, "Binary");
            }
            other => panic!("expected TypeMismatch, got: {other:?}"),
        }
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
        let result =
            apply_transform(&doc, doc.root_element().id(), &Transform::C14n(algo), data).unwrap();

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
        let result = apply_transform(&doc, doc.root_element().id(), &Transform::C14n(algo), data);

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

        let result = execute_transforms(&doc, sig_node.id(), initial, &transforms).unwrap();

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
        let result = execute_transforms(&doc, doc.root_element().id(), initial, &[]).unwrap();

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
        let result = execute_transforms(&doc, doc.root_element().id(), initial, &[]).unwrap();

        assert_eq!(result, b"raw bytes");
    }

    // ── Nested signatures ────────────────────────────────────────────

    #[test]
    fn enveloped_only_excludes_own_signature() {
        // Nested signatures: enveloped transform should only exclude
        // the specific <Signature> being verified, not all signatures
        let xml = r#"<root>
            <data>hello</data>
            <Sig1 xmlns="http://www.w3.org/2000/09/xmldsig#">
                <SignedInfo><Reference URI=""/></SignedInfo>
            </Sig1>
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
                <SignedInfo><Reference URI=""/></SignedInfo>
            </Signature>
        </root>"#;
        let doc = Document::parse(xml).unwrap();

        // We are verifying the <Signature> element, not <Sig1>
        let sig_node = doc
            .descendants()
            .find(|n| n.is_element() && n.tag_name().name() == "Signature")
            .unwrap();

        let node_set = NodeSet::entire_document_without_comments(&doc);
        let data = TransformData::NodeSet(node_set);

        let result = apply_transform(&doc, sig_node.id(), &Transform::Enveloped, data).unwrap();
        let node_set = result.into_node_set().unwrap();

        // Sig1 should still be in the set
        let sig1 = doc
            .descendants()
            .find(|n| n.is_element() && n.tag_name().name() == "Sig1")
            .unwrap();
        assert!(
            node_set.contains(sig1),
            "other signature elements should NOT be excluded"
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
        let result = execute_transforms(&doc, sig_node.id(), initial, &transforms).unwrap();

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
