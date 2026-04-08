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
use roxmltree::{Document, Node, NodeId};
use std::collections::HashSet;

use crate::c14n::canonicalize;

use super::digest::{DigestAlgorithm, compute_digest, constant_time_eq};
use super::parse::{ParseError, Reference, SignatureAlgorithm, XMLDSIG_NS};
use super::parse::{parse_key_info, parse_reference, parse_signed_info};
use super::signature::{
    SignatureVerificationError, verify_ecdsa_signature_pem, verify_rsa_signature_pem,
};
use super::transforms::{
    DEFAULT_IMPLICIT_C14N_URI, Transform, XPATH_TRANSFORM_URI, execute_transforms,
};
use super::uri::{UriReferenceResolver, parse_xpointer_id_fragment};
use super::whitespace::{is_xml_whitespace_only, normalize_xml_base64_text};

const MAX_SIGNATURE_VALUE_LEN: usize = 8192;
const MAX_SIGNATURE_VALUE_TEXT_LEN: usize = 65_536;
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
    ) -> Result<bool, DsigError>;
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
    fn resolve<'a>(&'a self, xml: &str) -> Result<Option<Box<dyn VerifyingKey + 'a>>, DsigError>;
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
    /// When enabled, references in `<ds:Manifest>` elements that are direct
    /// element children of `<ds:Object>` are processed only when the direct-child
    /// `<ds:Object>` or `<ds:Manifest>` itself is referenced from `<SignedInfo>`
    /// by an ID-based same-document fragment URI such as `#id` or
    /// `#xpointer(id('id'))`.
    /// Only those signed Manifest references are returned in
    /// `VerifyResult::manifest_references`.
    /// Nested `<ds:Manifest>` descendants under `<ds:Object>` are not
    /// processed.
    /// Direct-child unsigned/unreferenced Manifests are skipped and do not
    /// appear in `VerifyResult::manifest_references`.
    /// Whole-document same-document references such as `URI=""` or
    /// `URI="#xpointer(/)"` do not mark a specific direct-child
    /// `<ds:Object>`/`<ds:Manifest>` as signed for this option.
    ///
    /// Manifest reference digest mismatches, policy violations, and processing
    /// failures are reported in `VerifyResult::manifest_references` and do not
    /// alter the final `VerifyResult::status`.
    /// Callers that enable `process_manifests(true)` must inspect
    /// `VerifyResult::manifest_references` in addition to `VerifyResult::status`
    /// when interpreting `verify()` results.
    /// Structural/parse errors in Manifest content abort `verify()` and are
    /// returned as `Err(...)`.
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
    pub fn verify(&self, xml: &str) -> Result<VerifyResult, DsigError> {
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
    /// Whether this reference came from `<SignedInfo>` or `<Manifest>`.
    pub reference_set: ReferenceSet,
    /// Zero-based index within `reference_set`.
    pub reference_index: usize,
    /// URI from the `<Reference>` element (for diagnostics).
    pub uri: String,
    /// Digest algorithm used.
    pub digest_algorithm: DigestAlgorithm,
    /// Reference verification status.
    pub status: DsigStatus,
    /// Pre-digest bytes (populated when `store_pre_digest` is enabled).
    pub pre_digest_data: Option<Vec<u8>>,
}

/// Origin of a processed `<Reference>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReferenceSet {
    /// `<Reference>` under `<SignedInfo>`.
    SignedInfo,
    /// `<Reference>` under `<Object>/<Manifest>`.
    Manifest,
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
        /// Zero-based index of the failing `<Reference>` in its processed set.
        ///
        /// On per-reference verification entries, use
        /// `ReferenceResult::reference_set` to distinguish the `<SignedInfo>`
        /// and `<Manifest>` reference sets.
        ///
        /// When this reason appears in `VerifyResult::status` without an
        /// accompanying `ReferenceResult`, `ref_index` always refers to the
        /// `<SignedInfo>` reference set.
        ref_index: usize,
    },
    /// `<Reference>` rejected by URI/transform allowlist policy.
    ReferencePolicyViolation {
        /// Zero-based index of the failing `<Reference>` in its processed set.
        ref_index: usize,
    },
    /// `<Reference>` processing failed (dereference, transform, missing URI).
    ReferenceProcessingFailure {
        /// Zero-based index of the failing `<Reference>` in its processed set.
        ref_index: usize,
    },
    /// `<SignatureValue>` does not match canonicalized `<SignedInfo>`.
    SignatureMismatch,
    /// No verification key was configured or could be resolved.
    KeyNotFound,
}

/// Result of processing all `<Reference>` elements in `<SignedInfo>`.
#[derive(Debug)]
#[non_exhaustive]
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
/// - `reference_set`: Whether this reference belongs to `<SignedInfo>` or `<Manifest>`.
/// - `reference_index`: Zero-based index of this reference inside `reference_set`.
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
    reference_set: ReferenceSet,
    reference_index: usize,
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
        DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch {
            ref_index: reference_index,
        })
    };

    Ok(ReferenceResult {
        reference_set,
        reference_index,
        uri: uri.to_owned(),
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
        let result = process_reference(
            reference,
            resolver,
            signature_node,
            ReferenceSet::SignedInfo,
            i,
            store_pre_digest,
        )?;
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
    UriDereference(#[source] super::types::TransformError),

    /// Transform execution failed.
    #[error("transform failed: {0}")]
    Transform(#[source] super::types::TransformError),
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
    /// `<Manifest>` reference results.
    /// Populated only when `VerifyContext::process_manifests(true)` is enabled.
    /// Includes only references from signed direct-child `<ds:Object>/<ds:Manifest>`
    /// blocks that are referenced from `<SignedInfo>`.
    /// Unsigned/unreferenced direct-child Manifest blocks are skipped, so an
    /// empty list does not imply that no Manifest elements existed in `verify()` input.
    pub manifest_references: Vec<ReferenceResult>,
    /// Canonicalized `<SignedInfo>` bytes when `store_pre_digest` is enabled
    /// and verification reaches SignedInfo canonicalization.
    pub canonicalized_signed_info: Option<Vec<u8>>,
}

/// Errors while running end-to-end XMLDSig verification.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DsigError {
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

    /// `<KeyInfo>` parsing failed.
    #[error("failed to parse KeyInfo: {0}")]
    ParseKeyInfo(#[source] super::parse::ParseError),

    /// `<Object>/<Manifest>/<Reference>` parsing failed.
    #[error("failed to parse Manifest reference: {0}")]
    ParseManifestReference(#[source] ParseError),

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
}

type SignatureVerificationPipelineError = DsigError;

/// Verify one XMLDSig `<Signature>` end-to-end with a PEM public key.
///
/// Pipeline:
/// 1. Parse `<Signature>` children and enforce structural constraints
/// 2. Parse and validate optional `<KeyInfo>` (when present)
/// 3. Parse `<SignedInfo>`
/// 4. Validate all `<Reference>` digests (fail-fast)
/// 5. Canonicalize `<SignedInfo>`
/// 6. Base64-decode `<SignatureValue>`
/// 7. Verify signature bytes against canonicalized `<SignedInfo>`
///
/// If any `<Reference>` digest mismatches, returns `Ok` with
/// `status == Invalid(ReferenceDigestMismatch { .. })`.
///
/// Structural constraints enforced by this API:
/// - The document must contain exactly one XMLDSig `<Signature>` element.
/// - `<SignedInfo>` must be the first element child of `<Signature>` and appear once.
/// - `<SignatureValue>` must be the second element child of `<Signature>` and appear once.
/// - `<KeyInfo>` is optional and, when present, must be the third element child.
/// - Only XMLDSig namespace element children are allowed under `<Signature>`.
/// - Non-whitespace mixed text content under `<Signature>` is rejected.
/// - After `<SignedInfo>`, `<SignatureValue>`, and optional `<KeyInfo>`, only `<Object>` elements are allowed.
/// - `<SignatureValue>` must not contain nested element children.
pub fn verify_signature_with_pem_key(
    xml: &str,
    public_key_pem: &str,
    store_pre_digest: bool,
) -> Result<VerifyResult, DsigError> {
    struct PemVerifyingKey<'a> {
        public_key_pem: &'a str,
    }

    impl VerifyingKey for PemVerifyingKey<'_> {
        fn verify(
            &self,
            algorithm: SignatureAlgorithm,
            signed_data: &[u8],
            signature_value: &[u8],
        ) -> Result<bool, DsigError> {
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
    if ctx.key.is_none()
        && let Some(key_info_node) = signature_children.key_info_node
    {
        // P2-001: validate KeyInfo structure now; key material consumption is deferred.
        parse_key_info(key_info_node).map_err(SignatureVerificationPipelineError::ParseKeyInfo)?;
    }

    let signed_info = parse_signed_info(signed_info_node)?;
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

    let manifest_references = if ctx.process_manifests {
        let signed_info_reference_nodes =
            collect_signed_info_reference_nodes(&signed_info.references, &resolver);
        process_manifest_references(signature_node, &resolver, ctx, &signed_info_reference_nodes)?
    } else {
        Vec::new()
    };

    if let Some(first_failure) = references.first_failure {
        let status = references.results[first_failure].status;
        return Ok(VerifyResult {
            status,
            signed_info_references: references.results,
            manifest_references,
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
            manifest_references,
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
        manifest_references,
        canonicalized_signed_info: if ctx.store_pre_digest {
            Some(canonical_signed_info)
        } else {
            None
        },
    })
}

fn process_manifest_references(
    signature_node: Node<'_, '_>,
    resolver: &UriReferenceResolver<'_>,
    ctx: &VerifyContext<'_>,
    signed_info_reference_nodes: &HashSet<NodeId>,
) -> Result<Vec<ReferenceResult>, SignatureVerificationPipelineError> {
    let manifest_references =
        parse_manifest_references(signature_node, signed_info_reference_nodes)?;
    if manifest_references.is_empty() {
        return Ok(Vec::new());
    }
    let mut results = Vec::with_capacity(manifest_references.len());
    for (index, reference) in manifest_references.iter().enumerate() {
        match enforce_reference_policies(
            std::slice::from_ref(reference),
            ctx.allowed_uri_types,
            ctx.allowed_transform_uris(),
        ) {
            Ok(()) => {}
            Err(
                SignatureVerificationPipelineError::DisallowedUri { .. }
                | SignatureVerificationPipelineError::DisallowedTransform { .. },
            ) => {
                results.push(manifest_reference_invalid_result(
                    reference,
                    index,
                    FailureReason::ReferencePolicyViolation { ref_index: index },
                ));
                continue;
            }
            Err(SignatureVerificationPipelineError::Reference(
                ReferenceProcessingError::MissingUri,
            )) => {
                results.push(manifest_reference_invalid_result(
                    reference,
                    index,
                    FailureReason::ReferenceProcessingFailure { ref_index: index },
                ));
                continue;
            }
            Err(_) => {
                // Defensive fallback for future enforce_reference_policies variants:
                // record as non-fatal per-reference processing failure instead of aborting.
                results.push(manifest_reference_invalid_result(
                    reference,
                    index,
                    FailureReason::ReferenceProcessingFailure { ref_index: index },
                ));
                continue;
            }
        }

        match process_reference(
            reference,
            resolver,
            signature_node,
            ReferenceSet::Manifest,
            index,
            ctx.store_pre_digest,
        ) {
            Ok(result) => results.push(result),
            Err(_) => results.push(manifest_reference_invalid_result(
                reference,
                index,
                FailureReason::ReferenceProcessingFailure { ref_index: index },
            )),
        }
    }
    Ok(results)
}

fn manifest_reference_invalid_result(
    reference: &Reference,
    index: usize,
    reason: FailureReason,
) -> ReferenceResult {
    ReferenceResult {
        reference_set: ReferenceSet::Manifest,
        reference_index: index,
        uri: reference
            .uri
            .clone()
            .unwrap_or_else(|| "<omitted>".to_owned()),
        digest_algorithm: reference.digest_method,
        status: DsigStatus::Invalid(reason),
        pre_digest_data: None,
    }
}

fn parse_manifest_references(
    signature_node: Node<'_, '_>,
    signed_info_reference_nodes: &HashSet<NodeId>,
) -> Result<Vec<Reference>, SignatureVerificationPipelineError> {
    let mut references = Vec::new();
    for object_node in signature_node.children().filter(|node| {
        node.is_element()
            && node.tag_name().namespace() == Some(XMLDSIG_NS)
            && node.tag_name().name() == "Object"
    }) {
        let object_is_signed = signed_info_reference_nodes.contains(&object_node.id());
        for manifest_node in object_node.children().filter(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(XMLDSIG_NS)
                && node.tag_name().name() == "Manifest"
        }) {
            let manifest_is_signed = signed_info_reference_nodes.contains(&manifest_node.id());
            if !object_is_signed && !manifest_is_signed {
                continue;
            }
            let mut manifest_children = Vec::new();
            for child in manifest_node.children() {
                if child.is_text()
                    && child.text().is_some_and(|text| {
                        text.chars().any(|c| !matches!(c, ' ' | '\t' | '\n' | '\r'))
                    })
                {
                    return Err(SignatureVerificationPipelineError::InvalidStructure {
                        reason: "Manifest contains non-whitespace mixed content",
                    });
                }
                if child.is_element() {
                    manifest_children.push(child);
                }
            }
            if manifest_children.is_empty() {
                return Err(SignatureVerificationPipelineError::InvalidStructure {
                    reason: "Manifest must contain at least one ds:Reference element child",
                });
            }
            for child in manifest_children {
                if child.tag_name().namespace() != Some(XMLDSIG_NS)
                    || child.tag_name().name() != "Reference"
                {
                    return Err(SignatureVerificationPipelineError::InvalidStructure {
                        reason: "Manifest must contain only ds:Reference element children",
                    });
                }
                references.push(
                    parse_reference(child)
                        .map_err(SignatureVerificationPipelineError::ParseManifestReference)?,
                );
            }
        }
    }
    Ok(references)
}

fn collect_signed_info_reference_nodes(
    references: &[Reference],
    resolver: &UriReferenceResolver<'_>,
) -> HashSet<NodeId> {
    references
        .iter()
        .filter_map(|reference| reference.uri.as_deref())
        .filter_map(signed_info_reference_id_from_uri)
        .filter_map(|id| resolver.node_id_for_id(id))
        .collect()
}

fn signed_info_reference_id_from_uri(uri: &str) -> Option<&str> {
    let fragment = uri.strip_prefix('#')?;
    if fragment.is_empty() || fragment == "xpointer(/)" {
        return None;
    }
    if let Some(id) = parse_xpointer_id_fragment(fragment) {
        return (!id.is_empty()).then_some(id);
    }
    (!fragment.starts_with("xpointer(")).then_some(fragment)
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
    key_info_node: Option<Node<'a, 'input>>,
}

fn parse_signature_children<'a, 'input>(
    signature_node: Node<'a, 'input>,
) -> Result<SignatureChildNodes<'a, 'input>, SignatureVerificationPipelineError> {
    let mut signed_info_node: Option<Node<'_, '_>> = None;
    let mut signature_value_node: Option<Node<'_, '_>> = None;
    let mut key_info_node: Option<Node<'_, '_>> = None;
    let mut signed_info_index: Option<usize> = None;
    let mut signature_value_index: Option<usize> = None;
    let mut key_info_index: Option<usize> = None;
    let mut first_unexpected_dsig_index: Option<usize> = None;

    let mut element_index = 0usize;
    for child in signature_node.children() {
        if child.is_text() {
            if child
                .text()
                .is_some_and(|text| !is_xml_whitespace_only(text))
            {
                return Err(SignatureVerificationPipelineError::InvalidStructure {
                    reason: "Signature must not contain non-whitespace mixed content",
                });
            }
            continue;
        }
        if !child.is_element() {
            continue;
        }

        element_index += 1;
        if child.tag_name().namespace() != Some(XMLDSIG_NS) {
            return Err(SignatureVerificationPipelineError::InvalidStructure {
                reason: "Signature must contain only XMLDSIG element children",
            });
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
            "KeyInfo" => {
                if key_info_node.is_some() {
                    return Err(SignatureVerificationPipelineError::InvalidStructure {
                        reason: "KeyInfo must appear at most once under Signature",
                    });
                }
                key_info_node = Some(child);
                key_info_index = Some(element_index);
            }
            "Object" => {
                // Valid Object elements are allowed only after SignedInfo, SignatureValue,
                // and optional KeyInfo; this is enforced via first_unexpected_dsig_index.
            }
            _ => {
                if first_unexpected_dsig_index.is_none() {
                    first_unexpected_dsig_index = Some(element_index);
                }
            }
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
    if let Some(index) = key_info_index
        && index != 3
    {
        return Err(SignatureVerificationPipelineError::InvalidStructure {
            reason: "KeyInfo must be the third element child of Signature when present",
        });
    }

    let allowed_prefix_end = key_info_index.unwrap_or(2);
    if let Some(unexpected_index) = first_unexpected_dsig_index {
        return Err(SignatureVerificationPipelineError::InvalidStructure {
            reason: if unexpected_index > allowed_prefix_end {
                "After SignedInfo, SignatureValue, and optional KeyInfo, Signature may contain only Object elements"
            } else {
                "Signature may contain SignedInfo first, SignatureValue second, optional KeyInfo third, and Object elements thereafter"
            },
        });
    }

    Ok(SignatureChildNodes {
        signed_info_node,
        signature_value_node,
        key_info_node,
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
    if raw_text_len.saturating_add(text.len()) > MAX_SIGNATURE_VALUE_TEXT_LEN {
        return Err(SignatureVerificationPipelineError::InvalidStructure {
            reason: "SignatureValue exceeds maximum allowed text length",
        });
    }
    *raw_text_len = raw_text_len.saturating_add(text.len());

    normalize_xml_base64_text(text, normalized).map_err(|err| {
        SignatureVerificationPipelineError::SignatureValueBase64(base64::DecodeError::InvalidByte(
            err.normalized_offset,
            err.invalid_byte,
        ))
    })?;
    if normalized.len() > MAX_SIGNATURE_VALUE_LEN {
        return Err(SignatureVerificationPipelineError::InvalidStructure {
            reason: "SignatureValue exceeds maximum allowed length",
        });
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

    struct AcceptingKey;

    impl VerifyingKey for AcceptingKey {
        fn verify(
            &self,
            _algorithm: SignatureAlgorithm,
            _signed_data: &[u8],
            _signature_value: &[u8],
        ) -> Result<bool, SignatureVerificationPipelineError> {
            Ok(true)
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

    fn signature_with_manifest_xml(valid_manifest_digest: bool) -> String {
        signature_with_manifest_xml_with_manifest_mutation(valid_manifest_digest, |xml| xml)
    }

    fn signature_with_manifest_xml_with_manifest_mutation<F>(
        valid_manifest_digest: bool,
        mutate_manifest: F,
    ) -> String
    where
        F: FnOnce(String) -> String,
    {
        const TMP_SIGNED_INFO_DIGEST: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        const INVALID_MANIFEST_DIGEST: &str = "//////////////////////////8=";
        let xml_template = r##"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <target ID="target">payload</target>
  <ds:Signature>
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#manifest">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <ds:DigestValue>SIGNEDINFO_OBJECT_DIGEST_PLACEHOLDER</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>AQ==</ds:SignatureValue>
    <ds:Object>
      <ds:Manifest ID="manifest">
        <ds:Reference URI="#target">
          <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
          <ds:DigestValue>MANIFEST_DIGEST_PLACEHOLDER</ds:DigestValue>
        </ds:Reference>
      </ds:Manifest>
    </ds:Object>
  </ds:Signature>
</root>"##;
        let seed_xml = xml_template.replace(
            "SIGNEDINFO_OBJECT_DIGEST_PLACEHOLDER",
            TMP_SIGNED_INFO_DIGEST,
        );
        let doc = Document::parse(&seed_xml).unwrap();
        let signature_node = doc
            .descendants()
            .find(|node| {
                node.is_element()
                    && node.tag_name().namespace() == Some(XMLDSIG_NS)
                    && node.tag_name().name() == "Signature"
            })
            .unwrap();
        let resolver = UriReferenceResolver::new(&doc);
        let initial_data = resolver.dereference("#target").unwrap();
        let manifest_pre_digest =
            crate::xmldsig::execute_transforms(signature_node, initial_data, &[]).unwrap();
        let computed_manifest_digest_b64 = base64::engine::general_purpose::STANDARD
            .encode(compute_digest(DigestAlgorithm::Sha1, &manifest_pre_digest));
        let final_manifest_digest_b64 = if valid_manifest_digest {
            computed_manifest_digest_b64.as_str()
        } else {
            INVALID_MANIFEST_DIGEST
        };
        let xml_with_manifest_digest = mutate_manifest(
            seed_xml.replace("MANIFEST_DIGEST_PLACEHOLDER", final_manifest_digest_b64),
        );
        let signed_doc = Document::parse(&xml_with_manifest_digest).unwrap();
        let signed_signature_node = signed_doc
            .descendants()
            .find(|node| {
                node.is_element()
                    && node.tag_name().namespace() == Some(XMLDSIG_NS)
                    && node.tag_name().name() == "Signature"
            })
            .unwrap();
        let signed_info_node = signed_signature_node
            .children()
            .find(|node| {
                node.is_element()
                    && node.tag_name().namespace() == Some(XMLDSIG_NS)
                    && node.tag_name().name() == "SignedInfo"
            })
            .unwrap();
        let signed_info = parse_signed_info(signed_info_node).unwrap();
        let object_reference = &signed_info.references[0];
        let signed_resolver = UriReferenceResolver::new(&signed_doc);
        let signed_initial_data = signed_resolver
            .dereference(object_reference.uri.as_deref().unwrap())
            .unwrap();
        let signed_pre_digest = crate::xmldsig::execute_transforms(
            signed_signature_node,
            signed_initial_data,
            &object_reference.transforms,
        )
        .unwrap();
        let signed_digest_b64 = base64::engine::general_purpose::STANDARD.encode(compute_digest(
            object_reference.digest_method,
            &signed_pre_digest,
        ));

        xml_with_manifest_digest.replacen(TMP_SIGNED_INFO_DIGEST, &signed_digest_b64, 1)
    }

    #[test]
    fn verify_context_processes_manifest_references_when_enabled() {
        let xml = signature_with_manifest_xml(true);

        let result_without_manifests = VerifyContext::new()
            .key(&RejectingKey)
            .verify(&xml)
            .expect("manifest processing disabled should still verify SignedInfo");
        assert!(
            result_without_manifests.manifest_references.is_empty(),
            "manifest results must stay empty when manifest processing is disabled",
        );
        assert!(matches!(
            result_without_manifests.status,
            DsigStatus::Invalid(FailureReason::SignatureMismatch)
        ));

        let malformed_manifest_xml = signature_with_manifest_xml(true).replacen(
            "</ds:Object>",
            "</ds:Object><ds:Object><ds:Manifest><ds:Foo/></ds:Manifest></ds:Object>",
            1,
        );
        let malformed_with_manifests_disabled = VerifyContext::new()
            .key(&RejectingKey)
            .verify(&malformed_manifest_xml)
            .expect("malformed Manifest must be ignored when manifest processing is disabled");
        assert!(
            malformed_with_manifests_disabled
                .manifest_references
                .is_empty(),
            "manifest parser must not run when process_manifests is disabled",
        );
        assert!(matches!(
            malformed_with_manifests_disabled.status,
            DsigStatus::Invalid(FailureReason::SignatureMismatch)
        ));

        let result_with_manifests = VerifyContext::new()
            .key(&RejectingKey)
            .process_manifests(true)
            .verify(&xml)
            .expect("manifest references should be processed when enabled");
        assert_eq!(result_with_manifests.manifest_references.len(), 1);
        assert_eq!(
            result_with_manifests.manifest_references[0].reference_set,
            ReferenceSet::Manifest
        );
        assert_eq!(
            result_with_manifests.manifest_references[0].reference_index,
            0
        );
        assert!(matches!(
            result_with_manifests.manifest_references[0].status,
            DsigStatus::Valid
        ));
        assert!(matches!(
            result_with_manifests.status,
            DsigStatus::Invalid(FailureReason::SignatureMismatch)
        ));
    }

    #[test]
    fn verify_context_processes_manifest_when_signedinfo_references_object() {
        let xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
            xml.replacen("URI=\"#manifest\"", "URI=\"#object-id\"", 1)
                .replacen("<ds:Object>", "<ds:Object ID=\"object-id\">", 1)
                .replacen("<ds:Manifest ID=\"manifest\">", "<ds:Manifest>", 1)
        });

        let result = VerifyContext::new()
            .key(&RejectingKey)
            .process_manifests(true)
            .verify(&xml)
            .expect("manifest references should be processed when SignedInfo references ds:Object");
        assert_eq!(
            result.manifest_references.len(),
            1,
            "signed ds:Object should enable processing of its direct-child ds:Manifest",
        );
        assert_eq!(
            result.manifest_references[0].reference_set,
            ReferenceSet::Manifest
        );
        assert_eq!(result.manifest_references[0].reference_index, 0);
        assert!(matches!(
            result.manifest_references[0].status,
            DsigStatus::Valid
        ));
    }

    #[test]
    fn verify_context_manifest_digest_mismatch_is_non_fatal() {
        let xml = signature_with_manifest_xml(false);
        let result = VerifyContext::new()
            .key(&RejectingKey)
            .process_manifests(true)
            .verify(&xml)
            .expect("manifest digest mismatches should be reported as reference status");
        assert_eq!(result.manifest_references.len(), 1);
        assert_eq!(
            result.manifest_references[0].reference_set,
            ReferenceSet::Manifest
        );
        assert_eq!(result.manifest_references[0].reference_index, 0);
        assert!(matches!(
            result.manifest_references[0].status,
            DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 })
        ));
        assert!(matches!(
            result.status,
            DsigStatus::Invalid(FailureReason::SignatureMismatch)
        ));
    }

    #[test]
    fn verify_context_manifest_digest_mismatch_is_non_fatal_with_accepting_key() {
        let xml = signature_with_manifest_xml(false);
        let result = VerifyContext::new()
            .key(&AcceptingKey)
            .process_manifests(true)
            .verify(&xml)
            .expect("manifest digest mismatches should be recorded while signature stays valid");
        assert_eq!(result.manifest_references.len(), 1);
        assert!(matches!(
            result.manifest_references[0].status,
            DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 })
        ));
        assert!(matches!(result.status, DsigStatus::Valid));
    }

    #[test]
    fn verify_context_keeps_manifest_results_when_signedinfo_reference_fails() {
        let xml = signature_with_manifest_xml(true);
        let (signed_info_prefix, object_suffix) = xml
            .split_once("<ds:Object>")
            .expect("fixture should contain ds:Object");
        let open = "<ds:DigestValue>";
        let close = "</ds:DigestValue>";
        let digest_start = signed_info_prefix
            .find(open)
            .expect("SignedInfo should contain DigestValue");
        let digest_end = signed_info_prefix[digest_start + open.len()..]
            .find(close)
            .map(|offset| digest_start + open.len() + offset)
            .expect("SignedInfo DigestValue must be closed");
        let broken_signed_info_prefix = format!(
            "{}{}AAAAAAAAAAAAAAAAAAAAAAAAAAA={}{}",
            &signed_info_prefix[..digest_start],
            open,
            close,
            &signed_info_prefix[digest_end + close.len()..],
        );
        let broken_xml = format!("{broken_signed_info_prefix}<ds:Object>{object_suffix}");
        let result = VerifyContext::new()
            .key(&RejectingKey)
            .process_manifests(true)
            .verify(&broken_xml)
            .expect("manifest references should still be processed on SignedInfo digest failure");
        assert!(matches!(
            result.status,
            DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 })
        ));
        assert_eq!(
            result.manifest_references.len(),
            1,
            "manifest diagnostics must be preserved even when SignedInfo fails early",
        );
    }

    #[test]
    fn verify_context_records_manifest_policy_violations_without_aborting() {
        let xml = signature_with_manifest_xml(true);
        let (prefix, object_suffix) = xml
            .split_once("<ds:Object>")
            .expect("fixture should contain ds:Object");
        let mutated_object_suffix =
            object_suffix.replacen("URI=\"#target\"", "URI=\"http://example.com/external\"", 1);
        let broken_xml = format!("{prefix}<ds:Object>{mutated_object_suffix}");
        let result = VerifyContext::new()
            .key(&RejectingKey)
            .process_manifests(true)
            .verify(&broken_xml)
            .expect("manifest policy violations should be recorded, not abort verify()");
        assert_eq!(result.manifest_references.len(), 1);
        assert!(matches!(
            result.manifest_references[0].status,
            DsigStatus::Invalid(FailureReason::ReferencePolicyViolation { ref_index: 0 })
        ));
        assert!(matches!(
            result.status,
            DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 })
        ));
    }

    #[test]
    fn verify_context_records_manifest_policy_violations_with_accepting_key() {
        let broken_xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
            xml.replacen("URI=\"#target\"", "URI=\"http://example.com/external\"", 1)
        });
        let result = VerifyContext::new()
            .key(&AcceptingKey)
            .process_manifests(true)
            .verify(&broken_xml)
            .expect("manifest policy violations should be recorded while signature stays valid");
        assert_eq!(result.manifest_references.len(), 1);
        assert!(matches!(
            result.manifest_references[0].status,
            DsigStatus::Invalid(FailureReason::ReferencePolicyViolation { ref_index: 0 })
        ));
        assert!(matches!(result.status, DsigStatus::Valid));
    }

    #[test]
    fn verify_context_records_manifest_missing_uri_as_processing_failure() {
        let xml = signature_with_manifest_xml(true);
        let (prefix, object_suffix) = xml
            .split_once("<ds:Object>")
            .expect("fixture should contain ds:Object");
        let mutated_object_suffix =
            object_suffix.replacen("<ds:Reference URI=\"#target\">", "<ds:Reference>", 1);
        let broken_xml = format!("{prefix}<ds:Object>{mutated_object_suffix}");

        let result = VerifyContext::new()
            .key(&RejectingKey)
            .process_manifests(true)
            .verify(&broken_xml)
            .expect("manifest missing URI should be recorded as non-fatal processing failure");
        assert_eq!(result.manifest_references.len(), 1);
        assert_eq!(result.manifest_references[0].uri, "<omitted>");
        assert!(matches!(
            result.manifest_references[0].status,
            DsigStatus::Invalid(FailureReason::ReferenceProcessingFailure { ref_index: 0 })
        ));
        assert!(matches!(
            result.status,
            DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 })
        ));
    }

    #[test]
    fn verify_context_records_manifest_missing_uri_with_accepting_key() {
        let broken_xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
            xml.replacen("<ds:Reference URI=\"#target\">", "<ds:Reference>", 1)
        });

        let result = VerifyContext::new()
            .key(&AcceptingKey)
            .process_manifests(true)
            .verify(&broken_xml)
            .expect("manifest missing URI should be recorded while signature stays valid");
        assert_eq!(result.manifest_references.len(), 1);
        assert_eq!(result.manifest_references[0].uri, "<omitted>");
        assert!(matches!(
            result.manifest_references[0].status,
            DsigStatus::Invalid(FailureReason::ReferenceProcessingFailure { ref_index: 0 })
        ));
        assert!(matches!(result.status, DsigStatus::Valid));
    }

    #[test]
    fn verify_context_ignores_nested_manifests_in_object() {
        let xml = signature_with_manifest_xml(true)
            .replacen(
                "<ds:Manifest ID=\"manifest\">",
                "<wrapper><ds:Manifest ID=\"manifest\">",
                1,
            )
            .replacen("</ds:Manifest>", "</ds:Manifest></wrapper>", 1);

        let result = VerifyContext::new()
            .key(&RejectingKey)
            .process_manifests(true)
            .verify(&xml)
            .expect("nested Manifest nodes are ignored in strict mode");
        assert!(
            result.manifest_references.is_empty(),
            "only direct ds:Manifest children of ds:Object must be processed"
        );
    }

    #[test]
    fn verify_context_reports_manifest_reference_parse_errors_explicitly() {
        let xml = signature_with_manifest_xml(true);
        let (prefix, object_suffix) = xml
            .split_once("<ds:Object>")
            .expect("fixture should contain ds:Object");
        let open = "<ds:DigestValue>";
        let close = "</ds:DigestValue>";
        let digest_start = object_suffix
            .find(open)
            .expect("manifest should contain DigestValue");
        let digest_end = object_suffix[digest_start + open.len()..]
            .find(close)
            .map(|offset| digest_start + open.len() + offset)
            .expect("manifest DigestValue must be closed");
        let broken_object_suffix = format!(
            "{}{}!!!{}{}",
            &object_suffix[..digest_start],
            open,
            close,
            &object_suffix[digest_end + close.len()..],
        );
        let broken_xml = format!("{prefix}<ds:Object>{broken_object_suffix}");

        let err = VerifyContext::new()
            .key(&RejectingKey)
            .process_manifests(true)
            .verify(&broken_xml)
            .expect_err("invalid Manifest DigestValue must map to ParseManifestReference");
        assert!(matches!(
            err,
            SignatureVerificationPipelineError::ParseManifestReference(_)
        ));
    }

    #[test]
    fn verify_context_rejects_manifest_non_whitespace_mixed_content() {
        let xml = signature_with_manifest_xml(true).replacen(
            "<ds:Manifest ID=\"manifest\">",
            "<ds:Manifest ID=\"manifest\">junk",
            1,
        );

        let err = VerifyContext::new()
            .key(&RejectingKey)
            .process_manifests(true)
            .verify(&xml)
            .expect_err("Manifest mixed content must fail verification");
        assert!(matches!(
            err,
            SignatureVerificationPipelineError::InvalidStructure {
                reason: "Manifest contains non-whitespace mixed content"
            }
        ));
    }

    #[test]
    fn verify_context_rejects_empty_manifest_children() {
        let xml = signature_with_manifest_xml(true);
        let (prefix, rest) = xml
            .split_once("<ds:Manifest ID=\"manifest\">")
            .expect("fixture should contain Manifest");
        let (_, suffix) = rest
            .split_once("</ds:Manifest>")
            .expect("fixture should contain closing Manifest");
        let xml = format!("{prefix}<ds:Manifest ID=\"manifest\"></ds:Manifest>{suffix}");

        let err = VerifyContext::new()
            .key(&RejectingKey)
            .process_manifests(true)
            .verify(&xml)
            .expect_err("empty Manifest must fail verification");
        assert!(matches!(
            err,
            SignatureVerificationPipelineError::InvalidStructure {
                reason: "Manifest must contain at least one ds:Reference element child"
            }
        ));
    }

    #[test]
    fn verify_context_ignores_unsigned_malformed_manifest_blocks() {
        let xml = signature_with_manifest_xml(true).replacen(
            "</ds:Object>",
            "</ds:Object><ds:Object><ds:Manifest>junk<ds:Foo/></ds:Manifest></ds:Object>",
            1,
        );
        let result = VerifyContext::new()
            .key(&AcceptingKey)
            .process_manifests(true)
            .verify(&xml)
            .expect("unsigned malformed Manifest must be ignored");
        assert_eq!(
            result.manifest_references.len(),
            1,
            "only signed Manifest references must be reported",
        );
        assert!(matches!(result.status, DsigStatus::Valid));
    }

    #[test]
    fn verify_context_skips_ambiguous_manifest_id_blocks() {
        let xml = signature_with_manifest_xml(true).replacen(
            "</ds:Object>",
            "</ds:Object><ds:Object><ds:Manifest ID=\"manifest\">junk<ds:Foo/></ds:Manifest></ds:Object>",
            1,
        );
        let err = VerifyContext::new()
            .key(&RejectingKey)
            .process_manifests(true)
            .verify(&xml)
            .expect_err("ambiguous manifest IDs should make SignedInfo #manifest dereference fail");
        assert!(matches!(
            err,
            SignatureVerificationPipelineError::Reference(
                ReferenceProcessingError::UriDereference(
                    crate::xmldsig::types::TransformError::ElementNotFound(id)
                )
            ) if id == "manifest"
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

        let result = process_reference(
            &reference,
            &resolver,
            sig_node,
            ReferenceSet::SignedInfo,
            0,
            false,
        )
        .unwrap();
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

        let result = process_reference(
            &reference,
            &resolver,
            sig_node,
            ReferenceSet::SignedInfo,
            0,
            false,
        )
        .unwrap();
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
        let result = process_reference(
            &reference,
            &resolver,
            sig_node,
            ReferenceSet::SignedInfo,
            7,
            false,
        )
        .unwrap();
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
        let result = process_reference(
            &reference,
            &resolver,
            doc.root_element(),
            ReferenceSet::SignedInfo,
            0,
            true,
        )
        .unwrap();

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
        let result = process_reference(
            &reference,
            &resolver,
            sig_node,
            ReferenceSet::SignedInfo,
            0,
            false,
        )
        .unwrap();
        assert!(matches!(result.status, DsigStatus::Valid));
    }

    #[test]
    fn reference_with_nonexistent_id_fails() {
        let xml = "<root><child/></root>";
        let doc = Document::parse(xml).unwrap();
        let resolver = UriReferenceResolver::new(&doc);

        let reference =
            make_reference("#nonexistent", vec![], DigestAlgorithm::Sha256, vec![0; 32]);
        let result = process_reference(
            &reference,
            &resolver,
            doc.root_element(),
            ReferenceSet::SignedInfo,
            0,
            false,
        );
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

        let result = process_reference(
            &reference,
            &resolver,
            doc.root_element(),
            ReferenceSet::SignedInfo,
            0,
            false,
        );
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
        let result = process_reference(
            &reference,
            &resolver,
            doc.root_element(),
            ReferenceSet::SignedInfo,
            0,
            false,
        )
        .unwrap();
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
        let result = process_reference(
            &reference,
            &resolver,
            doc.root_element(),
            ReferenceSet::SignedInfo,
            0,
            false,
        )
        .unwrap();
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
        let result = process_reference(
            &corrected_ref,
            &resolver,
            sig_node,
            ReferenceSet::SignedInfo,
            0,
            true,
        )
        .unwrap();
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

    #[test]
    fn pipeline_reports_keyinfo_parse_error() {
        let xml = r#"
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
              xmlns:dsig11="http://www.w3.org/2009/xmldsig11#">
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <ds:Reference URI="">
      <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      <ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <ds:SignatureValue>AA==</ds:SignatureValue>
  <ds:KeyInfo>
    <dsig11:DEREncodedKeyValue>%%%invalid%%%</dsig11:DEREncodedKeyValue>
  </ds:KeyInfo>
</ds:Signature>
"#;

        let err = VerifyContext::new().verify(xml).expect_err(
            "invalid KeyInfo must map to ParseKeyInfo when no explicit key is supplied",
        );
        assert!(matches!(
            err,
            SignatureVerificationPipelineError::ParseKeyInfo(_)
        ));
    }

    #[test]
    fn pipeline_ignores_malformed_keyinfo_when_explicit_key_is_supplied() {
        let base_xml = signature_with_target_reference("AQ==");
        let xml = base_xml
            .replace(
                r#"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
                r#"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:dsig11="http://www.w3.org/2009/xmldsig11#">"#,
            )
            .replace(
                "</ds:SignatureValue>\n  </ds:Signature>",
                "</ds:SignatureValue>\n    <ds:KeyInfo><dsig11:DEREncodedKeyValue>%%%invalid%%%</dsig11:DEREncodedKeyValue></ds:KeyInfo>\n  </ds:Signature>",
            );

        let result = VerifyContext::new()
            .key(&RejectingKey)
            .verify(&xml)
            .expect("explicit key path should not fail on malformed KeyInfo");
        assert!(matches!(
            result.status,
            DsigStatus::Invalid(FailureReason::SignatureMismatch)
        ));
    }

    #[test]
    fn pipeline_rejects_foreign_element_children_under_signature() {
        let base_xml = signature_with_target_reference("AQ==");
        let xml = base_xml
            .replace(
                r#"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
                r#"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:foo="urn:example:foo">"#,
            )
            .replace(
                "</ds:SignedInfo>\n    <ds:SignatureValue>",
                "</ds:SignedInfo>\n    <foo:Bar/>\n    <ds:SignatureValue>",
            );

        let err = VerifyContext::new()
            .key(&RejectingKey)
            .verify(&xml)
            .expect_err("foreign element children under Signature must fail closed");
        assert!(matches!(
            err,
            SignatureVerificationPipelineError::InvalidStructure {
                reason: "Signature must contain only XMLDSIG element children",
            }
        ));
    }

    #[test]
    fn pipeline_rejects_non_whitespace_mixed_content_under_signature() {
        let base_xml = signature_with_target_reference("AQ==");
        let xml = base_xml.replace(
            "</ds:SignedInfo>\n    <ds:SignatureValue>",
            "</ds:SignedInfo>\n    oops\n    <ds:SignatureValue>",
        );

        let err = VerifyContext::new()
            .key(&RejectingKey)
            .verify(&xml)
            .expect_err("non-whitespace mixed content under Signature must fail closed");
        assert!(matches!(
            err,
            SignatureVerificationPipelineError::InvalidStructure {
                reason: "Signature must not contain non-whitespace mixed content",
            }
        ));
    }

    #[test]
    fn pipeline_rejects_keyinfo_out_of_order() {
        let base_xml = signature_with_target_reference("AQ==");
        let xml = base_xml.replace(
            "</ds:SignatureValue>\n  </ds:Signature>",
            "</ds:SignatureValue>\n    <ds:Object/>\n    <ds:KeyInfo><ds:KeyName>late</ds:KeyName></ds:KeyInfo>\n  </ds:Signature>",
        );

        let err = VerifyContext::new()
            .key(&RejectingKey)
            .verify(&xml)
            .expect_err("KeyInfo after Object must be rejected by Signature child order checks");
        assert!(matches!(
            err,
            SignatureVerificationPipelineError::InvalidStructure {
                reason: "KeyInfo must be the third element child of Signature when present"
            }
        ));
    }

    #[test]
    fn pipeline_accepts_comments_and_processing_instructions_under_signature() {
        let xml = r#"
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <?dbg keep ?>
  <!-- signature metadata -->
  <ds:SignedInfo>
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <ds:Reference URI="">
      <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      <ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>
  <!-- between required children -->
  <ds:SignatureValue>AA==</ds:SignatureValue>
</ds:Signature>
"#;

        let doc = Document::parse(xml).expect("test XML must parse");
        let signature_node = doc.root_element();
        let parsed = parse_signature_children(signature_node)
            .expect("comment/PI nodes under Signature must be ignored");

        assert_eq!(parsed.signed_info_node.tag_name().name(), "SignedInfo");
        assert_eq!(
            parsed.signature_value_node.tag_name().name(),
            "SignatureValue"
        );
        assert!(parsed.key_info_node.is_none());
    }
}
