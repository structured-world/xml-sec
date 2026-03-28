//! Reference processing and digest verification for XMLDSig.
//!
//! Implements [XMLDSig §4.3.3](https://www.w3.org/TR/xmldsig-core1/#sec-CoreValidation):
//! for each `<Reference>` in `<SignedInfo>`, dereference the URI, apply transforms,
//! compute the digest, and compare with the stored `<DigestValue>`.
//!
//! This module wires together:
//! - [`UriReferenceResolver`] for URI dereference
//! - [`execute_transforms`] for the transform pipeline
//! - [`compute_digest`] + [`constant_time_eq`] for digest computation and comparison

use base64::Engine;
use roxmltree::{Document, Node};

use crate::c14n::canonicalize;

use super::digest::{DigestAlgorithm, compute_digest, constant_time_eq};
use super::parse::parse_signed_info;
use super::parse::{Reference, SignatureAlgorithm};
use super::signature::{
    SignatureVerificationError, verify_ecdsa_signature_pem, verify_rsa_signature_pem,
};
use super::transforms::execute_transforms;
use super::uri::UriReferenceResolver;

const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

/// Per-reference verification result.
#[derive(Debug)]
pub struct ReferenceResult {
    /// URI from the `<Reference>` element (for diagnostics).
    pub uri: Option<String>,
    /// Digest algorithm used.
    pub digest_algorithm: DigestAlgorithm,
    /// Whether the computed digest matched the stored `<DigestValue>`.
    pub valid: bool,
    /// Pre-digest bytes (populated when `store_pre_digest` is enabled).
    pub pre_digest_data: Option<Vec<u8>>,
}

/// Result of processing all `<Reference>` elements in `<SignedInfo>`.
#[derive(Debug)]
pub struct ReferencesResult {
    /// Per-reference results (one per `<Reference>` in order).
    /// On fail-fast, only references up to and including the failed one are present.
    pub results: Vec<ReferenceResult>,
    /// Index of the first failed reference, if any.
    pub first_failure: Option<usize>,
}

impl ReferencesResult {
    /// Whether all references passed digest verification.
    #[must_use]
    pub fn all_valid(&self) -> bool {
        self.first_failure.is_none()
    }
}

/// Process a single `<Reference>`: dereference URI → apply transforms → compute
/// digest → compare with stored `<DigestValue>`.
///
/// # Arguments
///
/// - `reference`: The parsed `<Reference>` element.
/// - `resolver`: URI resolver for the document.
/// - `signature_node`: The `<Signature>` element (for enveloped-signature transform).
/// - `store_pre_digest`: If true, store the pre-digest bytes in the result.
///
/// # Errors
///
/// Returns `Err` for processing failures (URI dereference, transform errors).
/// Digest mismatch is NOT an error — it produces `Ok(ReferenceResult { valid: false })`.
pub fn process_reference(
    reference: &Reference,
    resolver: &UriReferenceResolver<'_>,
    signature_node: Node<'_, '_>,
    store_pre_digest: bool,
) -> Result<ReferenceResult, ReferenceProcessingError> {
    // 1. Dereference URI. Omitted URI is distinct from URI="" in XMLDSig and
    // must be rejected until caller-provided external object resolution exists.
    let uri = reference
        .uri
        .as_deref()
        .ok_or(ReferenceProcessingError::MissingUri)?;
    let initial_data = resolver
        .dereference(uri)
        .map_err(ReferenceProcessingError::UriDereference)?;

    // 2. Apply transform chain
    let pre_digest_bytes = execute_transforms(signature_node, initial_data, &reference.transforms)
        .map_err(ReferenceProcessingError::Transform)?;

    // 3. Compute digest
    let computed_digest = compute_digest(reference.digest_method, &pre_digest_bytes);

    // 4. Compare with stored DigestValue (constant-time)
    let valid = constant_time_eq(&computed_digest, &reference.digest_value);

    Ok(ReferenceResult {
        uri: reference.uri.clone(),
        digest_algorithm: reference.digest_method,
        valid,
        pre_digest_data: if store_pre_digest {
            Some(pre_digest_bytes)
        } else {
            None
        },
    })
}

/// Process all `<Reference>` elements in a `<SignedInfo>`, with fail-fast
/// on the first digest mismatch.
///
/// Per XMLDSig spec: if any reference fails, the entire signature is invalid.
/// Processing stops at the first failure for efficiency.
///
/// # Errors
///
/// Returns `Err` only for processing failures (malformed XML, unsupported
/// transform, etc.). Digest mismatches are reported via
/// `ReferencesResult::first_failure`.
pub fn process_all_references(
    references: &[Reference],
    resolver: &UriReferenceResolver<'_>,
    signature_node: Node<'_, '_>,
    store_pre_digest: bool,
) -> Result<ReferencesResult, ReferenceProcessingError> {
    let mut results = Vec::with_capacity(references.len());

    for (i, reference) in references.iter().enumerate() {
        let result = process_reference(reference, resolver, signature_node, store_pre_digest)?;
        let failed = !result.valid;
        results.push(result);

        if failed {
            return Ok(ReferencesResult {
                results,
                first_failure: Some(i),
            });
        }
    }

    Ok(ReferencesResult {
        results,
        first_failure: None,
    })
}

/// Errors during reference processing.
///
/// Distinct from digest mismatch (which is a validation result, not a processing error).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReferenceProcessingError {
    /// `<Reference>` omitted the `URI` attribute, which we do not resolve implicitly.
    #[error("reference URI is required; omitted URI references are not supported")]
    MissingUri,

    /// URI dereference failed.
    #[error("URI dereference failed: {0}")]
    UriDereference(super::types::TransformError),

    /// Transform execution failed.
    #[error("transform failed: {0}")]
    Transform(super::types::TransformError),
}

/// End-to-end XMLDSig verification result for one `<Signature>`.
#[derive(Debug)]
#[must_use = "inspect signature_valid (and signature_checked for stage diagnostics) before accepting the document"]
pub struct SignatureVerificationResult {
    /// Reference validation results from `<SignedInfo>`.
    pub references: ReferencesResult,
    /// Whether final `<SignatureValue>` verification was attempted.
    ///
    /// This is `false` when a reference digest mismatch happened first.
    pub signature_checked: bool,
    /// Whether `<SignatureValue>` verification succeeded.
    ///
    /// Only meaningful when `signature_checked` is `true`.
    pub signature_valid: bool,
}

/// Errors while running end-to-end XMLDSig verification.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignatureVerificationPipelineError {
    /// XML parsing failed.
    #[error("XML parse error: {0}")]
    XmlParse(#[from] roxmltree::Error),

    /// Required signature element is missing.
    #[error("missing required element: <{element}>")]
    MissingElement {
        /// Name of the missing element.
        element: &'static str,
    },

    /// Signature element tree shape violates XMLDSig structure requirements.
    #[error("invalid Signature structure: {reason}")]
    InvalidStructure {
        /// Validation failure reason.
        reason: &'static str,
    },

    /// `<SignedInfo>` parsing failed.
    #[error("failed to parse SignedInfo: {0}")]
    ParseSignedInfo(#[from] super::parse::ParseError),

    /// Reference processing failed.
    #[error("reference processing failed: {0}")]
    Reference(#[from] ReferenceProcessingError),

    /// SignedInfo canonicalization failed.
    #[error("SignedInfo canonicalization failed: {0}")]
    Canonicalization(#[from] crate::c14n::C14nError),

    /// SignatureValue base64 decoding failed.
    #[error("invalid SignatureValue base64: {0}")]
    SignatureValueBase64(#[from] base64::DecodeError),

    /// Cryptographic verification failed before validity decision.
    #[error("signature verification failed: {0}")]
    Crypto(#[from] SignatureVerificationError),
}

/// Verify one XMLDSig `<Signature>` end-to-end with a PEM public key.
///
/// Pipeline:
/// 1. Parse `<SignedInfo>`
/// 2. Validate all `<Reference>` digests (fail-fast)
/// 3. Canonicalize `<SignedInfo>`
/// 4. Base64-decode `<SignatureValue>`
/// 5. Verify signature bytes against canonicalized `<SignedInfo>`
///
/// If any `<Reference>` digest mismatches, returns `Ok` with
/// `signature_checked == false` and `signature_valid == false`.
///
/// Structural constraints enforced by this API:
/// - The document must contain exactly one XMLDSig `<Signature>` element.
/// - `<SignedInfo>` must be the first element child of `<Signature>` and appear once.
/// - `<SignatureValue>` must be the second element child of `<Signature>` and appear once.
/// - `<SignatureValue>` must not contain nested element children.
pub fn verify_signature_with_pem_key(
    xml: &str,
    public_key_pem: &str,
    store_pre_digest: bool,
) -> Result<SignatureVerificationResult, SignatureVerificationPipelineError> {
    let doc = Document::parse(xml)?;
    let mut signatures = doc.descendants().filter(|node| {
        node.is_element()
            && node.tag_name().name() == "Signature"
            && node.tag_name().namespace() == Some(XMLDSIG_NS)
    });
    let signature_node = match (signatures.next(), signatures.next()) {
        (None, _) => {
            return Err(SignatureVerificationPipelineError::MissingElement {
                element: "Signature",
            });
        }
        (Some(node), None) => node,
        (Some(_), Some(_)) => {
            return Err(SignatureVerificationPipelineError::InvalidStructure {
                reason: "Signature must appear exactly once in document",
            });
        }
    };

    let mut signature_element_children = signature_node.children().filter(|node| node.is_element());
    let signed_info_node = match signature_element_children.next() {
        Some(node)
            if node.tag_name().name() == "SignedInfo"
                && node.tag_name().namespace() == Some(XMLDSIG_NS) =>
        {
            node
        }
        Some(_) => {
            return Err(SignatureVerificationPipelineError::InvalidStructure {
                reason: "SignedInfo must be the first element child of Signature",
            });
        }
        None => {
            return Err(SignatureVerificationPipelineError::MissingElement {
                element: "SignedInfo",
            });
        }
    };

    if signature_element_children.any(|node| {
        node.tag_name().name() == "SignedInfo" && node.tag_name().namespace() == Some(XMLDSIG_NS)
    }) {
        return Err(SignatureVerificationPipelineError::InvalidStructure {
            reason: "SignedInfo must appear exactly once under Signature",
        });
    }

    let signed_info = parse_signed_info(signed_info_node)?;
    let resolver = UriReferenceResolver::new(&doc);
    let references = process_all_references(
        &signed_info.references,
        &resolver,
        signature_node,
        store_pre_digest,
    )?;

    if references.first_failure.is_some() {
        return Ok(SignatureVerificationResult {
            references,
            signature_checked: false,
            signature_valid: false,
        });
    }

    let mut canonical_signed_info = Vec::new();
    canonicalize(
        &doc,
        Some(&|node| {
            node == signed_info_node
                || node
                    .ancestors()
                    .any(|ancestor| ancestor == signed_info_node)
        }),
        &signed_info.c14n_method,
        &mut canonical_signed_info,
    )?;

    let signature_value = decode_signature_value(signature_node)?;
    let signature_valid = verify_with_algorithm(
        signed_info.signature_method,
        public_key_pem,
        &canonical_signed_info,
        &signature_value,
    )?;

    Ok(SignatureVerificationResult {
        references,
        signature_checked: true,
        signature_valid,
    })
}

fn decode_signature_value(
    signature_node: Node<'_, '_>,
) -> Result<Vec<u8>, SignatureVerificationPipelineError> {
    let mut element_index = 0usize;
    let mut seen_signed_info = false;
    let mut signature_value_node: Option<Node<'_, '_>> = None;
    for child in signature_node.children().filter(|node| node.is_element()) {
        element_index += 1;
        if child.tag_name().namespace() != Some(XMLDSIG_NS) {
            continue;
        }
        match child.tag_name().name() {
            "SignedInfo" => {
                seen_signed_info = true;
            }
            "SignatureValue" => {
                if signature_value_node.is_some() {
                    return Err(SignatureVerificationPipelineError::InvalidStructure {
                        reason: "SignatureValue must appear exactly once under Signature",
                    });
                }
                if !seen_signed_info || element_index != 2 {
                    return Err(SignatureVerificationPipelineError::InvalidStructure {
                        reason: "SignatureValue must be the second element child of Signature",
                    });
                }
                signature_value_node = Some(child);
            }
            _ => {}
        }
    }

    let signature_value_node =
        signature_value_node.ok_or(SignatureVerificationPipelineError::MissingElement {
            element: "SignatureValue",
        })?;
    if signature_value_node
        .children()
        .any(|child| child.is_element())
    {
        return Err(SignatureVerificationPipelineError::InvalidStructure {
            reason: "SignatureValue must not contain element children",
        });
    }

    let normalized: String = signature_value_node
        .children()
        .filter(|child| child.is_text())
        .filter_map(|child| child.text())
        .flat_map(str::chars)
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect();

    Ok(base64::engine::general_purpose::STANDARD.decode(normalized)?)
}

fn verify_with_algorithm(
    algorithm: SignatureAlgorithm,
    public_key_pem: &str,
    signed_data: &[u8],
    signature_value: &[u8],
) -> Result<bool, SignatureVerificationPipelineError> {
    match algorithm {
        SignatureAlgorithm::RsaSha1
        | SignatureAlgorithm::RsaSha256
        | SignatureAlgorithm::RsaSha384
        | SignatureAlgorithm::RsaSha512 => Ok(verify_rsa_signature_pem(
            algorithm,
            public_key_pem,
            signed_data,
            signature_value,
        )?),
        SignatureAlgorithm::EcdsaP256Sha256 | SignatureAlgorithm::EcdsaP384Sha384 => {
            match verify_ecdsa_signature_pem(
                algorithm,
                public_key_pem,
                signed_data,
                signature_value,
            ) {
                Ok(valid) => Ok(valid),
                Err(SignatureVerificationError::InvalidSignatureFormat) => Ok(false),
                Err(error) => Err(error.into()),
            }
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests use trusted XML fixtures")]
mod tests {
    use super::*;
    use crate::xmldsig::digest::DigestAlgorithm;
    use crate::xmldsig::parse::{Reference, parse_signed_info};
    use crate::xmldsig::transforms::Transform;
    use crate::xmldsig::uri::UriReferenceResolver;
    use roxmltree::Document;

    // ── Helpers ──────────────────────────────────────────────────────

    /// Build a Reference with given URI, transforms, digest method, and expected digest.
    fn make_reference(
        uri: &str,
        transforms: Vec<Transform>,
        digest_method: DigestAlgorithm,
        digest_value: Vec<u8>,
    ) -> Reference {
        Reference {
            uri: Some(uri.to_string()),
            id: None,
            ref_type: None,
            transforms,
            digest_method,
            digest_value,
        }
    }

    // ── process_reference: happy path ────────────────────────────────

    #[test]
    fn reference_with_correct_digest_passes() {
        // Create a simple document, compute its canonical form digest,
        // then verify that process_reference returns valid=true.
        let xml = r##"<root>
            <data>hello world</data>
            <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="sig1">
                <ds:SignedInfo/>
            </ds:Signature>
        </root>"##;
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);
        let sig_node = doc
            .descendants()
            .find(|n| n.is_element() && n.tag_name().name() == "Signature")
            .unwrap();

        // First, compute the expected digest by running the pipeline
        let initial_data = resolver.dereference("").unwrap();
        let transforms = vec![
            Transform::Enveloped,
            Transform::C14n(
                crate::c14n::C14nAlgorithm::from_uri("http://www.w3.org/2001/10/xml-exc-c14n#")
                    .unwrap(),
            ),
        ];
        let pre_digest_bytes =
            crate::xmldsig::execute_transforms(sig_node, initial_data, &transforms).unwrap();
        let expected_digest = compute_digest(DigestAlgorithm::Sha256, &pre_digest_bytes);

        // Now build a Reference with the correct digest and verify
        let reference = make_reference("", transforms, DigestAlgorithm::Sha256, expected_digest);

        let result = process_reference(&reference, &resolver, sig_node, false).unwrap();
        assert!(result.valid, "digest should match");
        assert!(result.pre_digest_data.is_none());
    }

    #[test]
    fn reference_with_wrong_digest_fails() {
        let xml = r##"<root>
            <data>hello</data>
            <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:SignedInfo/>
            </ds:Signature>
        </root>"##;
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);
        let sig_node = doc
            .descendants()
            .find(|n| n.is_element() && n.tag_name().name() == "Signature")
            .unwrap();

        let transforms = vec![Transform::Enveloped];
        // Wrong digest value — all zeros
        let wrong_digest = vec![0u8; 32];
        let reference = make_reference("", transforms, DigestAlgorithm::Sha256, wrong_digest);

        let result = process_reference(&reference, &resolver, sig_node, false).unwrap();
        assert!(!result.valid, "wrong digest should fail");
    }

    #[test]
    fn reference_stores_pre_digest_data() {
        let xml = "<root><child>text</child></root>";
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        // No transforms, no enveloped — just canonicalize entire document
        let initial_data = resolver.dereference("").unwrap();
        let pre_digest =
            crate::xmldsig::execute_transforms(doc.root_element(), initial_data, &[]).unwrap();
        let digest = compute_digest(DigestAlgorithm::Sha256, &pre_digest);

        let reference = make_reference("", vec![], DigestAlgorithm::Sha256, digest);
        let result = process_reference(&reference, &resolver, doc.root_element(), true).unwrap();

        assert!(result.valid);
        assert!(result.pre_digest_data.is_some());
        assert_eq!(result.pre_digest_data.unwrap(), pre_digest);
    }

    // ── process_reference: URI dereference ───────────────────────────

    #[test]
    fn reference_with_id_uri() {
        let xml = r##"<root>
            <item ID="target">specific content</item>
            <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:SignedInfo/>
            </ds:Signature>
        </root>"##;
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);
        let sig_node = doc
            .descendants()
            .find(|n| n.is_element() && n.tag_name().name() == "Signature")
            .unwrap();

        // Compute expected digest for the #target subtree
        let initial_data = resolver.dereference("#target").unwrap();
        let transforms = vec![Transform::C14n(
            crate::c14n::C14nAlgorithm::from_uri("http://www.w3.org/2001/10/xml-exc-c14n#")
                .unwrap(),
        )];
        let pre_digest =
            crate::xmldsig::execute_transforms(sig_node, initial_data, &transforms).unwrap();
        let expected_digest = compute_digest(DigestAlgorithm::Sha256, &pre_digest);

        let reference = make_reference(
            "#target",
            transforms,
            DigestAlgorithm::Sha256,
            expected_digest,
        );
        let result = process_reference(&reference, &resolver, sig_node, false).unwrap();
        assert!(result.valid);
    }

    #[test]
    fn reference_with_nonexistent_id_fails() {
        let xml = "<root><child/></root>";
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        let reference =
            make_reference("#nonexistent", vec![], DigestAlgorithm::Sha256, vec![0; 32]);
        let result = process_reference(&reference, &resolver, doc.root_element(), false);
        assert!(result.is_err());
    }

    #[test]
    fn reference_with_absent_uri_fails_closed() {
        let xml = "<root><child>text</child></root>";
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        let reference = Reference {
            uri: None, // absent URI
            id: None,
            ref_type: None,
            transforms: vec![],
            digest_method: DigestAlgorithm::Sha256,
            digest_value: vec![0; 32],
        };

        let result = process_reference(&reference, &resolver, doc.root_element(), false);
        assert!(matches!(result, Err(ReferenceProcessingError::MissingUri)));
    }

    // ── process_all_references: fail-fast ────────────────────────────

    #[test]
    fn all_references_pass() {
        let xml = "<root><child>text</child></root>";
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        // Compute correct digest
        let initial_data = resolver.dereference("").unwrap();
        let pre_digest =
            crate::xmldsig::execute_transforms(doc.root_element(), initial_data, &[]).unwrap();
        let digest = compute_digest(DigestAlgorithm::Sha256, &pre_digest);

        let refs = vec![
            make_reference("", vec![], DigestAlgorithm::Sha256, digest.clone()),
            make_reference("", vec![], DigestAlgorithm::Sha256, digest),
        ];

        let result = process_all_references(&refs, &resolver, doc.root_element(), false).unwrap();
        assert!(result.all_valid());
        assert_eq!(result.results.len(), 2);
        assert!(result.first_failure.is_none());
    }

    #[test]
    fn fail_fast_on_first_mismatch() {
        let xml = "<root><child>text</child></root>";
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        let wrong_digest = vec![0u8; 32];
        let refs = vec![
            make_reference("", vec![], DigestAlgorithm::Sha256, wrong_digest.clone()),
            // Second reference should NOT be processed
            make_reference("", vec![], DigestAlgorithm::Sha256, wrong_digest),
        ];

        let result = process_all_references(&refs, &resolver, doc.root_element(), false).unwrap();
        assert!(!result.all_valid());
        assert_eq!(result.first_failure, Some(0));
        // Only first reference should be in results (fail-fast)
        assert_eq!(result.results.len(), 1);
        assert!(!result.results[0].valid);
    }

    #[test]
    fn fail_fast_second_reference() {
        let xml = "<root><child>text</child></root>";
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        // Compute correct digest for first ref
        let initial_data = resolver.dereference("").unwrap();
        let pre_digest =
            crate::xmldsig::execute_transforms(doc.root_element(), initial_data, &[]).unwrap();
        let correct_digest = compute_digest(DigestAlgorithm::Sha256, &pre_digest);
        let wrong_digest = vec![0u8; 32];

        let refs = vec![
            make_reference("", vec![], DigestAlgorithm::Sha256, correct_digest),
            make_reference("", vec![], DigestAlgorithm::Sha256, wrong_digest),
        ];

        let result = process_all_references(&refs, &resolver, doc.root_element(), false).unwrap();
        assert!(!result.all_valid());
        assert_eq!(result.first_failure, Some(1));
        // Both references should be in results
        assert_eq!(result.results.len(), 2);
        assert!(result.results[0].valid);
        assert!(!result.results[1].valid);
    }

    #[test]
    fn empty_references_list() {
        let xml = "<root/>";
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        let result = process_all_references(&[], &resolver, doc.root_element(), false).unwrap();
        assert!(result.all_valid());
        assert!(result.results.is_empty());
    }

    // ── Digest algorithms ────────────────────────────────────────────

    #[test]
    fn reference_sha1_digest() {
        let xml = "<root>content</root>";
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        let initial_data = resolver.dereference("").unwrap();
        let pre_digest =
            crate::xmldsig::execute_transforms(doc.root_element(), initial_data, &[]).unwrap();
        let digest = compute_digest(DigestAlgorithm::Sha1, &pre_digest);

        let reference = make_reference("", vec![], DigestAlgorithm::Sha1, digest);
        let result = process_reference(&reference, &resolver, doc.root_element(), false).unwrap();
        assert!(result.valid);
        assert_eq!(result.digest_algorithm, DigestAlgorithm::Sha1);
    }

    #[test]
    fn reference_sha512_digest() {
        let xml = "<root>content</root>";
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        let initial_data = resolver.dereference("").unwrap();
        let pre_digest =
            crate::xmldsig::execute_transforms(doc.root_element(), initial_data, &[]).unwrap();
        let digest = compute_digest(DigestAlgorithm::Sha512, &pre_digest);

        let reference = make_reference("", vec![], DigestAlgorithm::Sha512, digest);
        let result = process_reference(&reference, &resolver, doc.root_element(), false).unwrap();
        assert!(result.valid);
        assert_eq!(result.digest_algorithm, DigestAlgorithm::Sha512);
    }

    // ── SAML-like end-to-end ─────────────────────────────────────────

    #[test]
    fn saml_enveloped_reference_processing() {
        // Realistic SAML Response with enveloped signature
        let xml = r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                                     ID="_resp1">
            <saml:Assertion ID="_assert1">
                <saml:Subject>user@example.com</saml:Subject>
            </saml:Assertion>
            <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:SignedInfo>
                    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                    <ds:Reference URI="">
                        <ds:Transforms>
                            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                        </ds:Transforms>
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>fakesig==</ds:SignatureValue>
            </ds:Signature>
        </samlp:Response>"##;
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);
        let sig_node = doc
            .descendants()
            .find(|n| n.is_element() && n.tag_name().name() == "Signature")
            .unwrap();

        // Parse SignedInfo to get the Reference
        let signed_info_node = sig_node
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == "SignedInfo")
            .unwrap();
        let signed_info = parse_signed_info(signed_info_node).unwrap();
        let reference = &signed_info.references[0];

        // Compute the correct digest by running the actual pipeline
        let initial_data = resolver.dereference("").unwrap();
        let pre_digest =
            crate::xmldsig::execute_transforms(sig_node, initial_data, &reference.transforms)
                .unwrap();
        let correct_digest = compute_digest(reference.digest_method, &pre_digest);

        // Build a reference with the correct digest
        let corrected_ref = make_reference(
            "",
            reference.transforms.clone(),
            reference.digest_method,
            correct_digest,
        );

        // Verify: should pass
        let result = process_reference(&corrected_ref, &resolver, sig_node, true).unwrap();
        assert!(result.valid, "SAML reference should verify");
        assert!(result.pre_digest_data.is_some());

        // Verify the pre-digest data contains the canonicalized document without Signature
        let pre_digest_str = String::from_utf8(result.pre_digest_data.unwrap()).unwrap();
        assert!(
            pre_digest_str.contains("samlp:Response"),
            "pre-digest should contain Response"
        );
        assert!(
            !pre_digest_str.contains("SignatureValue"),
            "pre-digest should NOT contain Signature"
        );
    }

    #[test]
    fn pipeline_missing_signed_info_returns_missing_element() {
        let xml = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"></ds:Signature>"#;

        let err = verify_signature_with_pem_key(xml, "dummy-key", false)
            .expect_err("missing SignedInfo must fail before crypto stage");
        assert!(matches!(
            err,
            SignatureVerificationPipelineError::MissingElement {
                element: "SignedInfo"
            }
        ));
    }

    #[test]
    fn pipeline_multiple_signature_elements_are_rejected() {
        let xml = r#"
<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:Signature>
    <ds:SignedInfo/>
  </ds:Signature>
  <ds:Signature/>
</root>
"#;

        let err = verify_signature_with_pem_key(xml, "dummy-key", false)
            .expect_err("multiple signatures must fail closed");
        assert!(matches!(
            err,
            SignatureVerificationPipelineError::InvalidStructure {
                reason: "Signature must appear exactly once in document",
            }
        ));
    }
}
