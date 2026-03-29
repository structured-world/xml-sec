//! XMLDSig reference processing and end-to-end signature verification pipeline.
//!
//! Implements [XMLDSig §4.3.3](https://www.w3.org/TR/xmldsig-core1/#sec-CoreValidation):
//! for each `<Reference>` in `<SignedInfo>`, dereference the URI, apply transforms,
//! compute the digest, and compare with the stored `<DigestValue>`.
//!
//! This module wires together:
//! - [`UriReferenceResolver`] for URI dereference
//! - [`execute_transforms`] for the transform pipeline
//! - [`compute_digest`] + [`constant_time_eq`] for digest computation and comparison
//! - [`verify_signature_with_pem_key`] for full pipeline validation (`SignedInfo` + `SignatureValue`)

use base64::Engine;
use roxmltree::{Document, Node};
use std::collections::HashSet;

use crate::c14n::canonicalize;

use super::digest::{DigestAlgorithm, compute_digest, constant_time_eq};
use super::parse::parse_signed_info;
use super::parse::{Reference, SignatureAlgorithm, XMLDSIG_NS};
use super::signature::{
    SignatureVerificationError, verify_ecdsa_signature_pem, verify_rsa_signature_pem,
};
use super::transforms::{
    DEFAULT_IMPLICIT_C14N_URI, Transform, XPATH_TRANSFORM_URI, execute_transforms,
};
use super::uri::UriReferenceResolver;

const MAX_SIGNATURE_VALUE_LEN: usize = 8192;
const MAX_SIGNATURE_VALUE_TEXT_LEN: usize = 65_536;
const MANIFEST_REFERENCE_TYPE_URI: &str = "http://www.w3.org/2000/09/xmldsig#Manifest";
/// Cryptographic verifier used by [`VerifyContext`].
///
/// This trait intentionally has no `Send + Sync` supertraits so lightweight
/// single-threaded verifiers can be used without additional bounds.
pub trait VerifyingKey {
    /// Verify `signature_value` over `signed_data` with the declared algorithm.
    fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        signed_data: &[u8],
        signature_value: &[u8],
    ) -> Result<bool, SignatureVerificationPipelineError>;
}

/// Key resolver hook used by [`VerifyContext`] when no pre-set key is provided.
///
/// This trait intentionally has no `Send + Sync` supertraits; callers that need
/// cross-thread sharing can wrap resolvers/keys in their own thread-safe types.
pub trait KeyResolver {
    /// Resolve a verification key for the provided XML document.
    ///
    /// Return `Ok(None)` when no suitable key could be resolved from available
    /// key material (for example, missing `<KeyInfo>` candidates). `VerifyContext`
    /// maps `Ok(None)` to `DsigStatus::Invalid(FailureReason::KeyNotFound)`;
    /// reserve `Err(...)` for resolver failures.
    fn resolve<'a>(
        &'a self,
        xml: &str,
    ) -> Result<Option<Box<dyn VerifyingKey + 'a>>, SignatureVerificationPipelineError>;
}

/// Allowed URI classes for `<Reference URI="...">`.
///
/// Note: `UriReferenceResolver` currently supports only same-document URIs.
/// Allowing external URIs via this policy only disables the early policy
/// rejection; dereference still fails until an external resolver path is added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "pass the policy to VerifyContext::allowed_uri_types(), or store it for reuse"]
pub struct UriTypeSet {
    allow_empty: bool,
    allow_same_document: bool,
    allow_external: bool,
}

impl UriTypeSet {
    /// Create a custom URI policy.
    pub const fn new(allow_empty: bool, allow_same_document: bool, allow_external: bool) -> Self {
        Self {
            allow_empty,
            allow_same_document,
            allow_external,
        }
    }

    /// Allow only same-document references (`""`, `#id`, `#xpointer(...)`).
    pub const SAME_DOCUMENT: Self = Self {
        allow_empty: true,
        allow_same_document: true,
        allow_external: false,
    };

    /// Allow all URI classes.
    ///
    /// This includes external URI classes at policy level, but external
    /// dereference is not implemented yet by the default resolver.
    pub const ALL: Self = Self {
        allow_empty: true,
        allow_same_document: true,
        allow_external: true,
    };

    fn allows(self, uri: &str) -> bool {
        if uri.is_empty() {
            return self.allow_empty;
        }
        if uri.starts_with('#') {
            return self.allow_same_document;
        }
        self.allow_external
    }
}

impl Default for UriTypeSet {
    fn default() -> Self {
        Self::SAME_DOCUMENT
    }
}

/// Verification builder/configuration.
#[must_use = "configure the context and call verify(), or store it for reuse"]
pub struct VerifyContext<'a> {
    key: Option<&'a dyn VerifyingKey>,
    key_resolver: Option<&'a dyn KeyResolver>,
    process_manifests: bool,
    allowed_uri_types: UriTypeSet,
    allowed_transforms: Option<HashSet<String>>,
    store_pre_digest: bool,
}

impl<'a> VerifyContext<'a> {
    /// Create a context with conservative defaults.
    ///
    /// Defaults:
    /// - no pre-set key, no key resolver
    /// - manifests disabled
    /// - same-document URIs only
    /// - all transforms allowed
    /// - pre-digest buffers not stored
    pub fn new() -> Self {
        Self {
            key: None,
            key_resolver: None,
            process_manifests: false,
            allowed_uri_types: UriTypeSet::default(),
            allowed_transforms: None,
            store_pre_digest: false,
        }
    }

    /// Set a pre-resolved verification key.
    pub fn key(mut self, key: &'a dyn VerifyingKey) -> Self {
        self.key = Some(key);
        self
    }

    /// Set a key resolver fallback used when `key()` is not provided.
    pub fn key_resolver(mut self, resolver: &'a dyn KeyResolver) -> Self {
        self.key_resolver = Some(resolver);
        self
    }

    /// Enable or disable `<Manifest>` processing.
    ///
    /// Note: manifest verification is not implemented yet. When enabled, the
    /// verifier fails closed with `ManifestProcessingUnsupported` if a
    /// `<ds:Manifest>` is present under `<ds:Object>` or if a
    /// `<Reference Type="http://www.w3.org/2000/09/xmldsig#Manifest">` is present.
    pub fn process_manifests(mut self, enabled: bool) -> Self {
        self.process_manifests = enabled;
        self
    }

    /// Restrict allowed reference URI classes.
    pub fn allowed_uri_types(mut self, types: UriTypeSet) -> Self {
        self.allowed_uri_types = types;
        self
    }

    /// Restrict allowed transform algorithms by URI.
    ///
    /// Example values:
    /// - `http://www.w3.org/2000/09/xmldsig#enveloped-signature`
    /// - `http://www.w3.org/2001/10/xml-exc-c14n#`
    ///
    /// When a `<Reference>` has no explicit canonicalization transform, XMLDSig
    /// applies implicit default C14N (`http://www.w3.org/TR/2001/REC-xml-c14n-20010315`).
    /// If an allowlist is configured, include that URI as well unless all
    /// references use explicit `Transform::C14n(...)`.
    pub fn allowed_transforms<I, S>(mut self, transforms: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowed_transforms = Some(transforms.into_iter().map(Into::into).collect());
        self
    }

    /// Store pre-digest buffers for diagnostics.
    pub fn store_pre_digest(mut self, enabled: bool) -> Self {
        self.store_pre_digest = enabled;
        self
    }

    fn allowed_transform_uris(&self) -> Option<&HashSet<String>> {
        self.allowed_transforms.as_ref()
    }

    /// Verify one XMLDSig signature using this context.
    ///
    /// Returns `Ok(VerifyResult)` for both valid and invalid signatures; inspect
    /// `VerifyResult::status` for the verification outcome. `Err(...)` is
    /// reserved for pipeline failures.
    pub fn verify(&self, xml: &str) -> Result<VerifyResult, SignatureVerificationPipelineError> {
        verify_signature_with_context(xml, self)
    }
}

impl Default for VerifyContext<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-reference verification result.
#[derive(Debug)]
#[non_exhaustive]
#[must_use = "inspect status before accepting the reference result"]
pub struct ReferenceResult {
    /// URI from the `<Reference>` element (for diagnostics).
    pub uri: Option<String>,
    /// Digest algorithm used.
    pub digest_algorithm: DigestAlgorithm,
    /// Reference verification status.
    pub status: DsigStatus,
    /// Pre-digest bytes (populated when `store_pre_digest` is enabled).
    pub pre_digest_data: Option<Vec<u8>>,
}

/// Verification status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DsigStatus {
    /// Signature/reference is cryptographically valid.
    Valid,
    /// Signature/reference is invalid with a concrete reason.
    Invalid(FailureReason),
}

/// Why XMLDSig verification failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FailureReason {
    /// `<DigestValue>` mismatch for a `<Reference>` at `ref_index`.
    ReferenceDigestMismatch {
        /// Zero-based index of the failing `<Reference>` in `<SignedInfo>`.
        ref_index: usize,
    },
    /// `<SignatureValue>` does not match canonicalized `<SignedInfo>`.
    SignatureMismatch,
    /// No verification key was configured or could be resolved.
    KeyNotFound,
}

/// Result of processing all `<Reference>` elements in `<SignedInfo>`.
#[derive(Debug)]
#[must_use = "check first_failure/results before accepting the reference set"]
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
        self.results
            .iter()
            .all(|result| matches!(result.status, DsigStatus::Valid))
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
/// - `ref_index`: Zero-based index of this reference in `<SignedInfo>`.
/// - `store_pre_digest`: If true, store the pre-digest bytes in the result.
///
/// # Errors
///
/// Returns `Err` for processing failures (URI dereference, transform errors).
/// Digest mismatch is NOT an error — it produces
/// `Ok(ReferenceResult { status: Invalid(ReferenceDigestMismatch { .. }) })`.
pub fn process_reference(
    reference: &Reference,
    resolver: &UriReferenceResolver<'_>,
    signature_node: Node<'_, '_>,
    ref_index: usize,
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
    let status = if constant_time_eq(&computed_digest, &reference.digest_value) {
        DsigStatus::Valid
    } else {
        DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index })
    };

    Ok(ReferenceResult {
        uri: reference.uri.clone(),
        digest_algorithm: reference.digest_method,
        status,
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
        let result = process_reference(reference, resolver, signature_node, i, store_pre_digest)?;
        let failed = matches!(result.status, DsigStatus::Invalid(_));
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
#[non_exhaustive]
#[must_use = "inspect status before accepting the document"]
pub struct VerifyResult {
    /// Final XMLDSig status for this signature.
    pub status: DsigStatus,
    /// `<Reference>` verification results from `<SignedInfo>`.
    /// On fail-fast, this includes references up to and including
    /// the first digest mismatch only.
    pub signed_info_references: Vec<ReferenceResult>,
    /// `<Manifest>` reference results. Empty until manifest processing is implemented.
    pub manifest_references: Vec<ReferenceResult>,
    /// Canonicalized `<SignedInfo>` bytes when `store_pre_digest` is enabled
    /// and verification reaches SignedInfo canonicalization.
    pub canonicalized_signed_info: Option<Vec<u8>>,
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

    /// A `<Reference>` URI class is rejected by policy.
    #[error("reference URI is not allowed by policy: {uri}")]
    DisallowedUri {
        /// Offending URI value from `<Reference URI="...">`.
        uri: String,
    },

    /// A `<Transform>` algorithm is rejected by policy.
    #[error("transform is not allowed by policy: {algorithm}")]
    DisallowedTransform {
        /// Rejected transform algorithm URI.
        algorithm: String,
    },

    /// Manifest processing was requested but is not implemented in this phase.
    #[error("manifest processing is not implemented yet")]
    ManifestProcessingUnsupported,
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
/// `status == Invalid(ReferenceDigestMismatch { .. })`.
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
) -> Result<VerifyResult, SignatureVerificationPipelineError> {
    struct PemVerifyingKey<'a> {
        public_key_pem: &'a str,
    }

    impl VerifyingKey for PemVerifyingKey<'_> {
        fn verify(
            &self,
            algorithm: SignatureAlgorithm,
            signed_data: &[u8],
            signature_value: &[u8],
        ) -> Result<bool, SignatureVerificationPipelineError> {
            verify_with_algorithm(algorithm, self.public_key_pem, signed_data, signature_value)
        }
    }

    let key = PemVerifyingKey { public_key_pem };
    VerifyContext::new()
        .key(&key)
        .store_pre_digest(store_pre_digest)
        .verify(xml)
}

fn verify_signature_with_context(
    xml: &str,
    ctx: &VerifyContext<'_>,
) -> Result<VerifyResult, SignatureVerificationPipelineError> {
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

    let signature_children = parse_signature_children(signature_node)?;
    let signed_info_node = signature_children.signed_info_node;

    if ctx.process_manifests && has_manifest_children(signature_node) {
        return Err(SignatureVerificationPipelineError::ManifestProcessingUnsupported);
    }

    let signed_info = parse_signed_info(signed_info_node)?;
    if ctx.process_manifests && has_manifest_type_references(&signed_info.references) {
        return Err(SignatureVerificationPipelineError::ManifestProcessingUnsupported);
    }
    enforce_reference_policies(
        &signed_info.references,
        ctx.allowed_uri_types,
        ctx.allowed_transform_uris(),
    )?;

    let resolver = UriReferenceResolver::new(&doc);
    let references = process_all_references(
        &signed_info.references,
        &resolver,
        signature_node,
        ctx.store_pre_digest,
    )?;

    if let Some(first_failure) = references.first_failure {
        return Ok(VerifyResult {
            status: DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch {
                ref_index: first_failure,
            }),
            signed_info_references: references.results,
            manifest_references: Vec::new(),
            canonicalized_signed_info: None,
        });
    }

    let signed_info_subtree: HashSet<_> = signed_info_node
        .descendants()
        .map(|node: Node<'_, '_>| node.id())
        .collect();
    let mut canonical_signed_info = Vec::new();
    canonicalize(
        &doc,
        Some(&|node| signed_info_subtree.contains(&node.id())),
        &signed_info.c14n_method,
        &mut canonical_signed_info,
    )?;

    let signature_value = decode_signature_value(signature_children.signature_value_node)?;
    let Some(resolved_key) = resolve_verifying_key(ctx, xml)? else {
        return Ok(VerifyResult {
            status: DsigStatus::Invalid(FailureReason::KeyNotFound),
            signed_info_references: references.results,
            manifest_references: Vec::new(),
            canonicalized_signed_info: if ctx.store_pre_digest {
                Some(canonical_signed_info)
            } else {
                None
            },
        });
    };
    let verifier = resolved_key.as_ref();
    let signature_valid = verifier.verify(
        signed_info.signature_method,
        &canonical_signed_info,
        &signature_value,
    )?;

    Ok(VerifyResult {
        status: if signature_valid {
            DsigStatus::Valid
        } else {
            DsigStatus::Invalid(FailureReason::SignatureMismatch)
        },
        signed_info_references: references.results,
        manifest_references: Vec::new(),
        canonicalized_signed_info: if ctx.store_pre_digest {
            Some(canonical_signed_info)
        } else {
            None
        },
    })
}

fn has_manifest_children(signature_node: Node<'_, '_>) -> bool {
    signature_node.children().any(|child| {
        child.is_element()
            && child.tag_name().namespace() == Some(XMLDSIG_NS)
            && child.tag_name().name() == "Object"
            && child.descendants().any(|inner| {
                inner.is_element()
                    && inner.tag_name().namespace() == Some(XMLDSIG_NS)
                    && inner.tag_name().name() == "Manifest"
            })
    })
}

fn has_manifest_type_references(references: &[Reference]) -> bool {
    references
        .iter()
        .any(|reference| reference.ref_type.as_deref() == Some(MANIFEST_REFERENCE_TYPE_URI))
}

enum ResolvedVerifyingKey<'a> {
    Borrowed(&'a dyn VerifyingKey),
    Owned(Box<dyn VerifyingKey + 'a>),
}

impl ResolvedVerifyingKey<'_> {
    fn as_ref(&self) -> &dyn VerifyingKey {
        match self {
            Self::Borrowed(key) => *key,
            Self::Owned(key) => key.as_ref(),
        }
    }
}

fn resolve_verifying_key<'k>(
    ctx: &VerifyContext<'k>,
    xml: &str,
) -> Result<Option<ResolvedVerifyingKey<'k>>, SignatureVerificationPipelineError> {
    if let Some(key) = ctx.key {
        return Ok(Some(ResolvedVerifyingKey::Borrowed(key)));
    }
    if let Some(resolver) = ctx.key_resolver {
        let resolved = resolver.resolve(xml)?;
        return Ok(resolved.map(ResolvedVerifyingKey::Owned));
    }
    Ok(None)
}

fn enforce_reference_policies(
    references: &[Reference],
    allowed_uri_types: UriTypeSet,
    allowed_transforms: Option<&HashSet<String>>,
) -> Result<(), SignatureVerificationPipelineError> {
    for reference in references {
        let uri = reference
            .uri
            .as_deref()
            .ok_or(SignatureVerificationPipelineError::Reference(
                ReferenceProcessingError::MissingUri,
            ))?;
        if !allowed_uri_types.allows(uri) {
            return Err(SignatureVerificationPipelineError::DisallowedUri {
                uri: uri.to_owned(),
            });
        }

        if let Some(allowed) = allowed_transforms {
            for transform in &reference.transforms {
                let transform_uri = transform_uri(transform);
                if !allowed.contains(transform_uri) {
                    return Err(SignatureVerificationPipelineError::DisallowedTransform {
                        algorithm: transform_uri.to_owned(),
                    });
                }
            }

            let has_explicit_c14n = reference
                .transforms
                .iter()
                .any(|transform| matches!(transform, Transform::C14n(_)));
            if !has_explicit_c14n && !allowed.contains(DEFAULT_IMPLICIT_C14N_URI) {
                return Err(SignatureVerificationPipelineError::DisallowedTransform {
                    algorithm: DEFAULT_IMPLICIT_C14N_URI.to_owned(),
                });
            }
        }
    }
    Ok(())
}

fn transform_uri(transform: &Transform) -> &'static str {
    match transform {
        Transform::Enveloped => super::transforms::ENVELOPED_SIGNATURE_URI,
        Transform::XpathExcludeAllSignatures => XPATH_TRANSFORM_URI,
        Transform::C14n(algo) => algo.uri(),
    }
}

#[derive(Debug, Clone, Copy)]
struct SignatureChildNodes<'a, 'input> {
    signed_info_node: Node<'a, 'input>,
    signature_value_node: Node<'a, 'input>,
}

fn parse_signature_children<'a, 'input>(
    signature_node: Node<'a, 'input>,
) -> Result<SignatureChildNodes<'a, 'input>, SignatureVerificationPipelineError> {
    let mut signed_info_node: Option<Node<'_, '_>> = None;
    let mut signature_value_node: Option<Node<'_, '_>> = None;
    let mut signed_info_index: Option<usize> = None;
    let mut signature_value_index: Option<usize> = None;
    for (zero_based_index, child) in signature_node
        .children()
        .filter(|node| node.is_element())
        .enumerate()
    {
        let element_index = zero_based_index + 1;
        if child.tag_name().namespace() != Some(XMLDSIG_NS) {
            continue;
        }
        match child.tag_name().name() {
            "SignedInfo" => {
                if signed_info_node.is_some() {
                    return Err(SignatureVerificationPipelineError::InvalidStructure {
                        reason: "SignedInfo must appear exactly once under Signature",
                    });
                }
                signed_info_node = Some(child);
                signed_info_index = Some(element_index);
            }
            "SignatureValue" => {
                if signature_value_node.is_some() {
                    return Err(SignatureVerificationPipelineError::InvalidStructure {
                        reason: "SignatureValue must appear exactly once under Signature",
                    });
                }
                signature_value_node = Some(child);
                signature_value_index = Some(element_index);
            }
            _ => {}
        }
    }

    let signed_info_node =
        signed_info_node.ok_or(SignatureVerificationPipelineError::MissingElement {
            element: "SignedInfo",
        })?;
    let signature_value_node =
        signature_value_node.ok_or(SignatureVerificationPipelineError::MissingElement {
            element: "SignatureValue",
        })?;
    if signed_info_index != Some(1) {
        return Err(SignatureVerificationPipelineError::InvalidStructure {
            reason: "SignedInfo must be the first element child of Signature",
        });
    }
    if signature_value_index != Some(2) {
        return Err(SignatureVerificationPipelineError::InvalidStructure {
            reason: "SignatureValue must be the second element child of Signature",
        });
    }
    Ok(SignatureChildNodes {
        signed_info_node,
        signature_value_node,
    })
}

fn decode_signature_value(
    signature_value_node: Node<'_, '_>,
) -> Result<Vec<u8>, SignatureVerificationPipelineError> {
    if signature_value_node
        .children()
        .any(|child| child.is_element())
    {
        return Err(SignatureVerificationPipelineError::InvalidStructure {
            reason: "SignatureValue must not contain element children",
        });
    }

    let mut normalized = String::new();
    let mut raw_text_len = 0usize;
    for child in signature_value_node
        .children()
        .filter(|child| child.is_text())
    {
        if let Some(text) = child.text() {
            push_normalized_signature_text(text, &mut raw_text_len, &mut normalized)?;
        }
    }

    Ok(base64::engine::general_purpose::STANDARD.decode(normalized)?)
}

fn push_normalized_signature_text(
    text: &str,
    raw_text_len: &mut usize,
    normalized: &mut String,
) -> Result<(), SignatureVerificationPipelineError> {
    for ch in text.chars() {
        if raw_text_len.saturating_add(ch.len_utf8()) > MAX_SIGNATURE_VALUE_TEXT_LEN {
            return Err(SignatureVerificationPipelineError::InvalidStructure {
                reason: "SignatureValue exceeds maximum allowed text length",
            });
        }
        *raw_text_len = raw_text_len.saturating_add(ch.len_utf8());
        if matches!(ch, ' ' | '\t' | '\r' | '\n') {
            continue;
        }
        if ch.is_ascii_whitespace() {
            let invalid_byte =
                u8::try_from(u32::from(ch)).expect("ASCII whitespace always fits into u8");
            return Err(SignatureVerificationPipelineError::SignatureValueBase64(
                base64::DecodeError::InvalidByte(normalized.len(), invalid_byte),
            ));
        }
        if normalized.len().saturating_add(ch.len_utf8()) > MAX_SIGNATURE_VALUE_LEN {
            return Err(SignatureVerificationPipelineError::InvalidStructure {
                reason: "SignatureValue exceeds maximum allowed length",
            });
        }
        normalized.push(ch);
    }
    Ok(())
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
            // Malformed ECDSA signature bytes are treated as a verification miss
            // (Ok(false)) instead of a pipeline error; only key/algorithm and
            // crypto-operation failures propagate as Err.
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
    use base64::Engine;
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

    struct RejectingKey;

    impl VerifyingKey for RejectingKey {
        fn verify(
            &self,
            _algorithm: SignatureAlgorithm,
            _signed_data: &[u8],
            _signature_value: &[u8],
        ) -> Result<bool, SignatureVerificationPipelineError> {
            Ok(false)
        }
    }

    struct PanicResolver;

    impl KeyResolver for PanicResolver {
        fn resolve<'a>(
            &'a self,
            _xml: &str,
        ) -> Result<Option<Box<dyn VerifyingKey + 'a>>, SignatureVerificationPipelineError>
        {
            panic!("resolver should not be called when references already fail");
        }
    }

    struct MissingKeyResolver;

    impl KeyResolver for MissingKeyResolver {
        fn resolve<'a>(
            &'a self,
            _xml: &str,
        ) -> Result<Option<Box<dyn VerifyingKey + 'a>>, SignatureVerificationPipelineError>
        {
            Ok(None)
        }
    }

    fn minimal_signature_xml(reference_uri: &str, transforms_xml: &str) -> String {
        format!(
            r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <ds:Reference URI="{reference_uri}">
      {transforms_xml}
      <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      <ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>AQ==</ds:SignatureValue>
</ds:Signature>"#
        )
    }

    fn signature_with_target_reference(signature_value_b64: &str) -> String {
        let xml_template = r##"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <target ID="target">payload</target>
  <ds:Signature>
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#target">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>SIGNATURE_VALUE_PLACEHOLDER</ds:SignatureValue>
  </ds:Signature>
</root>"##;

        let doc = Document::parse(xml_template).unwrap();
        let sig_node = doc
            .descendants()
            .find(|node| node.is_element() && node.tag_name().name() == "Signature")
            .unwrap();
        let signed_info_node = sig_node
            .children()
            .find(|node| node.is_element() && node.tag_name().name() == "SignedInfo")
            .unwrap();
        let signed_info = parse_signed_info(signed_info_node).unwrap();
        let reference = &signed_info.references[0];
        let resolver = UriReferenceResolver::new(&doc);
        let initial_data = resolver
            .dereference(reference.uri.as_deref().unwrap())
            .unwrap();
        let pre_digest =
            crate::xmldsig::execute_transforms(sig_node, initial_data, &reference.transforms)
                .unwrap();
        let digest = compute_digest(reference.digest_method, &pre_digest);
        let digest_b64 = base64::engine::general_purpose::STANDARD.encode(digest);
        xml_template
            .replace("AAAAAAAAAAAAAAAAAAAAAAAAAAA=", &digest_b64)
            .replace("SIGNATURE_VALUE_PLACEHOLDER", signature_value_b64)
    }

    #[test]
    fn verify_context_reports_key_not_found_status_without_key_or_resolver() {
        let xml = signature_with_target_reference("AQ==");

        let result = VerifyContext::new()
            .verify(&xml)
            .expect("missing key config must be reported as verification status");
        assert!(
            matches!(
                result.status,
                DsigStatus::Invalid(FailureReason::KeyNotFound)
            ),
            "unexpected status: {:?}",
            result.status
        );
    }

    #[test]
    fn verify_context_rejects_disallowed_uri() {
        let xml = minimal_signature_xml("http://example.com/external", "");
        let err = VerifyContext::new()
            .key(&RejectingKey)
            .verify(&xml)
            .expect_err("external URI should be rejected by default policy");
        assert!(matches!(
            err,
            SignatureVerificationPipelineError::DisallowedUri { .. }
        ));
    }

    #[test]
    fn verify_context_rejects_empty_uri_when_policy_disallows_empty() {
        let xml = minimal_signature_xml("", "");
        let err = VerifyContext::new()
            .key(&RejectingKey)
            .allowed_uri_types(UriTypeSet::new(false, true, false))
            .verify(&xml)
            .expect_err("empty URI must be rejected when empty references are disabled");
        assert!(matches!(
            err,
            SignatureVerificationPipelineError::DisallowedUri { ref uri } if uri.is_empty()
        ));
    }

    #[test]
    fn verify_context_rejects_disallowed_transform() {
        let xml = minimal_signature_xml(
            "",
            r#"<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms>"#,
        );
        let err = VerifyContext::new()
            .key(&RejectingKey)
            .allowed_transforms(["http://www.w3.org/2001/10/xml-exc-c14n#"])
            .verify(&xml)
            .expect_err("enveloped transform should be rejected by allowlist");
        assert!(matches!(
            err,
            SignatureVerificationPipelineError::DisallowedTransform { .. }
        ));
    }

    fn signature_with_manifest_xml() -> String {
        r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <ds:Reference URI="">
      <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      <ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>AQ==</ds:SignatureValue>
  <ds:Object>
    <ds:Manifest>
      <ds:Reference URI="">
        <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>
      </ds:Reference>
    </ds:Manifest>
  </ds:Object>
</ds:Signature>"#
            .to_owned()
    }

    fn signature_with_nested_manifest_xml() -> String {
        r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <ds:Reference URI="">
      <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      <ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>AQ==</ds:SignatureValue>
  <ds:Object>
    <wrapper>
      <ds:Manifest>
        <ds:Reference URI="">
          <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
          <ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>
        </ds:Reference>
      </ds:Manifest>
    </wrapper>
  </ds:Object>
</ds:Signature>"#
            .to_owned()
    }

    fn signature_with_manifest_type_reference_xml() -> String {
        r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <ds:Reference URI="" Type="http://www.w3.org/2000/09/xmldsig#Manifest">
      <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      <ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>AQ==</ds:SignatureValue>
</ds:Signature>"#
            .to_owned()
    }

    #[test]
    fn verify_context_manifest_policy_toggle_is_enforced() {
        let xml = signature_with_manifest_xml();
        let err = VerifyContext::new()
            .key(&RejectingKey)
            .process_manifests(true)
            .verify(&xml)
            .expect_err("manifest processing must fail closed while unsupported");
        assert!(matches!(
            err,
            SignatureVerificationPipelineError::ManifestProcessingUnsupported
        ));

        let result = VerifyContext::new()
            .key(&RejectingKey)
            .process_manifests(false)
            .verify(&xml)
            .expect("manifest processing disabled should preserve prior behavior");
        assert!(matches!(
            result.status,
            DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 })
        ));
    }

    #[test]
    fn verify_context_rejects_nested_manifest_when_processing_enabled() {
        let xml = signature_with_nested_manifest_xml();
        let err = VerifyContext::new()
            .key(&RejectingKey)
            .process_manifests(true)
            .verify(&xml)
            .expect_err("nested manifests under <Object> must also be rejected");
        assert!(matches!(
            err,
            SignatureVerificationPipelineError::ManifestProcessingUnsupported
        ));
    }

    #[test]
    fn verify_context_rejects_manifest_type_reference_when_processing_enabled() {
        let xml = signature_with_manifest_type_reference_xml();
        let err = VerifyContext::new()
            .key(&RejectingKey)
            .process_manifests(true)
            .verify(&xml)
            .expect_err("manifest-typed references must fail closed while unsupported");
        assert!(matches!(
            err,
            SignatureVerificationPipelineError::ManifestProcessingUnsupported
        ));
    }

    #[test]
    fn verify_context_rejects_implicit_default_c14n_when_not_allowlisted() {
        let xml = minimal_signature_xml("", "");
        let err = VerifyContext::new()
            .key(&RejectingKey)
            .allowed_transforms(["http://www.w3.org/2001/10/xml-exc-c14n#"])
            .verify(&xml)
            .expect_err("implicit default C14N must be checked against allowlist");
        assert!(matches!(
            err,
            SignatureVerificationPipelineError::DisallowedTransform { .. }
        ));
    }

    #[test]
    fn verify_context_skips_resolver_when_reference_processing_fails() {
        let xml = minimal_signature_xml("", "");
        let result = VerifyContext::new()
            .key_resolver(&PanicResolver)
            .verify(&xml)
            .expect("reference digest mismatch should short-circuit before resolver");
        assert!(matches!(
            result.status,
            DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 })
        ));
    }

    #[test]
    fn verify_context_reports_key_not_found_when_resolver_misses() {
        let xml = signature_with_target_reference("AQ==");
        let result = VerifyContext::new()
            .key_resolver(&MissingKeyResolver)
            .verify(&xml)
            .expect("resolver miss should report status, not pipeline error");
        assert!(matches!(
            result.status,
            DsigStatus::Invalid(FailureReason::KeyNotFound)
        ));
        assert_eq!(
            result.signed_info_references.len(),
            1,
            "KeyNotFound path must preserve SignedInfo reference diagnostics",
        );
        assert!(matches!(
            result.signed_info_references[0].status,
            DsigStatus::Valid
        ));
    }

    #[test]
    fn verify_context_preserves_signaturevalue_decode_errors_when_resolver_misses() {
        let xml = signature_with_target_reference("@@@");

        let err = VerifyContext::new()
            .key_resolver(&MissingKeyResolver)
            .verify(&xml)
            .expect_err("invalid SignatureValue must remain a decode error on resolver miss");
        assert!(matches!(
            err,
            SignatureVerificationPipelineError::SignatureValueBase64(_)
        ));
    }

    #[test]
    fn verify_context_preserves_signaturevalue_decode_errors_without_key() {
        let xml = signature_with_target_reference("@@@");

        let err = VerifyContext::new()
            .verify(&xml)
            .expect_err("invalid SignatureValue must remain a decode error");
        assert!(matches!(
            err,
            SignatureVerificationPipelineError::SignatureValueBase64(_)
        ));
    }

    #[test]
    fn enforce_reference_policies_rejects_missing_uri_before_uri_type_checks() {
        let references = vec![Reference {
            uri: None,
            id: None,
            ref_type: None,
            transforms: vec![],
            digest_method: DigestAlgorithm::Sha256,
            digest_value: vec![0; 32],
        }];
        let uri_types = UriTypeSet {
            allow_empty: false,
            allow_same_document: true,
            allow_external: false,
        };

        let err = enforce_reference_policies(&references, uri_types, None)
            .expect_err("missing URI must fail before allow_empty policy is evaluated");
        assert!(matches!(
            err,
            SignatureVerificationPipelineError::Reference(ReferenceProcessingError::MissingUri)
        ));
    }

    #[test]
    fn push_normalized_signature_text_rejects_form_feed() {
        let mut normalized = String::new();
        let mut raw_text_len = 0usize;
        let err =
            push_normalized_signature_text("ab\u{000C}cd", &mut raw_text_len, &mut normalized)
                .expect_err("form-feed must not be treated as XML base64 whitespace");
        assert!(matches!(
            err,
            SignatureVerificationPipelineError::SignatureValueBase64(
                base64::DecodeError::InvalidByte(_, 0x0C)
            )
        ));
    }

    #[test]
    fn push_normalized_signature_text_enforces_byte_limit_for_multibyte_chars() {
        let mut normalized = "A".repeat(MAX_SIGNATURE_VALUE_LEN - 1);
        let mut raw_text_len = normalized.len();
        let err = push_normalized_signature_text("é", &mut raw_text_len, &mut normalized)
            .expect_err("multibyte characters must not bypass byte-size limit");
        assert!(matches!(
            err,
            SignatureVerificationPipelineError::InvalidStructure {
                reason: "SignatureValue exceeds maximum allowed length"
            }
        ));
    }

    // ── process_reference: happy path ────────────────────────────────

    #[test]
    fn reference_with_correct_digest_passes() {
        // Create a simple document, compute its canonical form digest,
        // then verify that process_reference returns Valid status.
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

        let result = process_reference(&reference, &resolver, sig_node, 0, false).unwrap();
        assert!(
            matches!(result.status, DsigStatus::Valid),
            "digest should match"
        );
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

        let result = process_reference(&reference, &resolver, sig_node, 0, false).unwrap();
        assert!(matches!(
            result.status,
            DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 })
        ));
    }

    #[test]
    fn reference_with_wrong_digest_preserves_supplied_ref_index() {
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

        let reference = make_reference(
            "",
            vec![Transform::Enveloped],
            DigestAlgorithm::Sha256,
            vec![0u8; 32],
        );
        let result = process_reference(&reference, &resolver, sig_node, 7, false).unwrap();
        assert!(matches!(
            result.status,
            DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 7 })
        ));
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
        let result = process_reference(&reference, &resolver, doc.root_element(), 0, true).unwrap();

        assert!(matches!(result.status, DsigStatus::Valid));
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
        let result = process_reference(&reference, &resolver, sig_node, 0, false).unwrap();
        assert!(matches!(result.status, DsigStatus::Valid));
    }

    #[test]
    fn reference_with_nonexistent_id_fails() {
        let xml = "<root><child/></root>";
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        let reference =
            make_reference("#nonexistent", vec![], DigestAlgorithm::Sha256, vec![0; 32]);
        let result = process_reference(&reference, &resolver, doc.root_element(), 0, false);
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

        let result = process_reference(&reference, &resolver, doc.root_element(), 0, false);
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
        assert!(matches!(
            result.results[0].status,
            DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 })
        ));
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
        assert!(matches!(result.results[0].status, DsigStatus::Valid));
        assert!(matches!(
            result.results[1].status,
            DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 1 })
        ));
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
        let result =
            process_reference(&reference, &resolver, doc.root_element(), 0, false).unwrap();
        assert!(matches!(result.status, DsigStatus::Valid));
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
        let result =
            process_reference(&reference, &resolver, doc.root_element(), 0, false).unwrap();
        assert!(matches!(result.status, DsigStatus::Valid));
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
        let result = process_reference(&corrected_ref, &resolver, sig_node, 0, true).unwrap();
        assert!(
            matches!(result.status, DsigStatus::Valid),
            "SAML reference should verify"
        );
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
