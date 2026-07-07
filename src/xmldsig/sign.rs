//! Signing-side XMLDSig digest computation.
//!
//! This pass fills `<DigestValue>` elements before `<SignedInfo>` is
//! canonicalized and signed. It intentionally uses a signing-template parser
//! instead of [`crate::xmldsig::parse::parse_signed_info`], because verification
//! must continue to reject empty or malformed stored digest values.

use base64::Engine;
use roxmltree::{Document, Node};

use super::digest::{DigestAlgorithm, compute_digest};
use super::mutation::{XmlMutationError, fill_digest_values};
use super::parse::XMLDSIG_NS;
use super::transforms::{Transform, execute_transforms, parse_transforms};
use super::types::TransformError;
use super::uri::UriReferenceResolver;

/// Result for one computed signing-template reference digest.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "use the computed digest value to fill the corresponding <DigestValue>"]
pub struct ComputedReferenceDigest {
    /// Zero-based reference index in `<SignedInfo>` document order.
    pub index: usize,
    /// Reference URI used for same-document dereference.
    pub uri: String,
    /// Digest algorithm declared by `<DigestMethod>`.
    pub digest_method: DigestAlgorithm,
    /// Base64-encoded digest value ready for `<DigestValue>`.
    pub digest_value: String,
}

/// Errors returned by the XMLDSig signing digest pass.
#[derive(Debug, thiserror::Error)]
pub enum SigningDigestError {
    /// The input XML document is not well-formed.
    #[error("XML parse error: {0}")]
    XmlParse(#[from] roxmltree::Error),

    /// Required XMLDSig element is missing.
    #[error("missing required element: <{element}>")]
    MissingElement {
        /// Required element name.
        element: &'static str,
    },

    /// XMLDSig template structure is invalid.
    #[error("invalid signing template: {0}")]
    InvalidStructure(String),

    /// Digest algorithm URI is not supported.
    #[error("unsupported digest algorithm: {uri}")]
    UnsupportedAlgorithm {
        /// Unrecognized algorithm URI.
        uri: String,
    },

    /// Digest algorithm is supported for verification but disabled for signing.
    #[error("digest algorithm is disabled for signing: {uri}")]
    SigningAlgorithmDisabled {
        /// Algorithm URI rejected for new signatures.
        uri: &'static str,
    },

    /// URI dereference or transform execution failed.
    #[error("reference processing error: {0}")]
    Transform(#[from] TransformError),

    /// Writing computed digest values back into XML failed.
    #[error("XML mutation error: {0}")]
    XmlMutation(#[from] XmlMutationError),
}

#[derive(Debug)]
struct SigningReference {
    uri: String,
    transforms: Vec<Transform>,
    digest_method: DigestAlgorithm,
}

/// Compute base64 digest values for every `<Reference>` in the signing template.
///
/// References are processed in `<SignedInfo>` document order. The input must
/// contain exactly one XMLDSig `<Signature>` element so an enveloped-signature
/// transform cannot accidentally target the wrong signature subtree.
pub fn compute_reference_digest_values(
    xml: &str,
) -> Result<Vec<ComputedReferenceDigest>, SigningDigestError> {
    let doc = Document::parse(xml)?;
    let signature = find_single_signature_node(&doc)?;
    let signed_info = find_required_child(signature, "SignedInfo")?;
    let references = parse_signing_references(signed_info)?;
    let resolver = UriReferenceResolver::new(&doc);

    references
        .into_iter()
        .enumerate()
        .map(|(index, reference)| {
            let initial_data = resolver.dereference(&reference.uri)?;
            let pre_digest = execute_transforms(signature, initial_data, &reference.transforms)?;
            let digest = compute_digest(reference.digest_method, &pre_digest);
            let digest_value = base64::engine::general_purpose::STANDARD.encode(digest);
            Ok(ComputedReferenceDigest {
                index,
                uri: reference.uri,
                digest_method: reference.digest_method,
                digest_value,
            })
        })
        .collect()
}

/// Compute and fill all signing-template `<DigestValue>` elements.
///
/// This is the signing counterpart to verification reference processing: it
/// dereferences each `<Reference>`, applies transforms, computes the digest,
/// and writes the base64 digest into the matching `<DigestValue>` in document
/// order.
pub fn fill_reference_digest_values(xml: &str) -> Result<String, SigningDigestError> {
    let digest_values = compute_reference_digest_values(xml)?
        .into_iter()
        .map(|digest| digest.digest_value);
    Ok(fill_digest_values(xml, digest_values)?)
}

fn find_single_signature_node<'a>(
    doc: &'a Document<'a>,
) -> Result<Node<'a, 'a>, SigningDigestError> {
    let mut signatures = doc.descendants().filter(|node| {
        node.is_element()
            && node.tag_name().name() == "Signature"
            && node.tag_name().namespace() == Some(XMLDSIG_NS)
    });
    let signature = signatures
        .next()
        .ok_or(SigningDigestError::MissingElement {
            element: "Signature",
        })?;
    if signatures.next().is_some() {
        return Err(SigningDigestError::InvalidStructure(
            "expected exactly one <ds:Signature> element".into(),
        ));
    }
    Ok(signature)
}

fn parse_signing_references(
    signed_info: Node<'_, '_>,
) -> Result<Vec<SigningReference>, SigningDigestError> {
    verify_ds_element(signed_info, "SignedInfo")?;
    let mut children = element_children(signed_info);

    let c14n_node = children.next().ok_or(SigningDigestError::MissingElement {
        element: "CanonicalizationMethod",
    })?;
    verify_ds_element(c14n_node, "CanonicalizationMethod")?;
    required_algorithm_attr(c14n_node, "CanonicalizationMethod")?;

    let signature_method_node = children.next().ok_or(SigningDigestError::MissingElement {
        element: "SignatureMethod",
    })?;
    verify_ds_element(signature_method_node, "SignatureMethod")?;
    required_algorithm_attr(signature_method_node, "SignatureMethod")?;

    let mut references = Vec::new();
    for child in children {
        verify_ds_element(child, "Reference")?;
        references.push(parse_signing_reference(child)?);
    }
    if references.is_empty() {
        return Err(SigningDigestError::MissingElement {
            element: "Reference",
        });
    }
    Ok(references)
}

fn parse_signing_reference(
    reference_node: Node<'_, '_>,
) -> Result<SigningReference, SigningDigestError> {
    let uri = reference_node
        .attribute("URI")
        .ok_or_else(|| {
            SigningDigestError::InvalidStructure(
                "signing Reference must include URI attribute".into(),
            )
        })?
        .to_string();
    let mut children = element_children(reference_node);

    let mut transforms = Vec::new();
    let mut next = children.next().ok_or(SigningDigestError::MissingElement {
        element: "DigestMethod",
    })?;
    if next.tag_name().name() == "Transforms" && next.tag_name().namespace() == Some(XMLDSIG_NS) {
        transforms = parse_transforms(next)?;
        next = children.next().ok_or(SigningDigestError::MissingElement {
            element: "DigestMethod",
        })?;
    }

    verify_ds_element(next, "DigestMethod")?;
    let digest_uri = required_algorithm_attr(next, "DigestMethod")?;
    let digest_method = DigestAlgorithm::from_uri(digest_uri).ok_or_else(|| {
        SigningDigestError::UnsupportedAlgorithm {
            uri: digest_uri.to_string(),
        }
    })?;
    if !digest_method.signing_allowed() {
        return Err(SigningDigestError::SigningAlgorithmDisabled {
            uri: digest_method.uri(),
        });
    }

    let digest_value_node = children.next().ok_or(SigningDigestError::MissingElement {
        element: "DigestValue",
    })?;
    verify_ds_element(digest_value_node, "DigestValue")?;

    if let Some(unexpected) = children.next() {
        return Err(SigningDigestError::InvalidStructure(format!(
            "unexpected element <{}> after <DigestValue> in <Reference>",
            unexpected.tag_name().name()
        )));
    }

    Ok(SigningReference {
        uri,
        transforms,
        digest_method,
    })
}

fn find_required_child<'a>(
    parent: Node<'a, 'a>,
    child_name: &'static str,
) -> Result<Node<'a, 'a>, SigningDigestError> {
    parent
        .children()
        .find(|node| {
            node.is_element()
                && node.tag_name().name() == child_name
                && node.tag_name().namespace() == Some(XMLDSIG_NS)
        })
        .ok_or(SigningDigestError::MissingElement {
            element: child_name,
        })
}

fn element_children<'a>(node: Node<'a, 'a>) -> impl Iterator<Item = Node<'a, 'a>> {
    node.children().filter(Node::is_element)
}

fn verify_ds_element(
    node: Node<'_, '_>,
    expected_name: &'static str,
) -> Result<(), SigningDigestError> {
    if !node.is_element() {
        return Err(SigningDigestError::InvalidStructure(format!(
            "expected element <{expected_name}>, got non-element node"
        )));
    }
    let tag = node.tag_name();
    if tag.name() != expected_name || tag.namespace() != Some(XMLDSIG_NS) {
        return Err(SigningDigestError::InvalidStructure(format!(
            "expected <ds:{expected_name}>, got <{}>",
            tag.name()
        )));
    }
    Ok(())
}

fn required_algorithm_attr<'a>(
    node: Node<'a, 'a>,
    element_name: &'static str,
) -> Result<&'a str, SigningDigestError> {
    node.attribute("Algorithm").ok_or_else(|| {
        SigningDigestError::InvalidStructure(format!(
            "missing Algorithm attribute on <{element_name}>"
        ))
    })
}
