//! XMLDSig reference processing and end-to-end signature verification pipeline.
//!
//! Implements [XMLDSig §4.3.3](https://www.w3.org/TR/xmldsig-core1/#sec-CoreValidation):
//! for each `<Reference>` in `<SignedInfo>`, dereference the URI, apply transforms,
//! compute the digest, and compare with the stored `<DigestValue>`.
//!
//! This module wires together:
//! - [`UriReferenceResolver`] for URI dereference
//! - [`super::transforms::execute_transforms`] for the transform pipeline
//! - [`compute_digest`] + [`constant_time_eq`] for digest computation and comparison
//! - [`verify_signature_with_pem_key`] for full pipeline validation (`SignedInfo` + `SignatureValue`)

use base64::Engine;
use roxmltree::{Document, Node, NodeId};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};

use crate::c14n::canonicalize_bounded_with_xml_base_budget;
use crate::hard_limits::CANONICALIZED_SIGNATURE_DATA_BYTE_CEILING;

#[cfg(test)]
use super::digest::compute_digest;
use super::digest::{DigestAlgorithm, constant_time_eq};
#[cfg(test)]
use super::parse::MAX_REFERENCES_PER_SIGNATURE;
#[cfg(test)]
use super::parse::parse_key_info;
use super::parse::{
    KeyInfo, MAX_X509_DATA_TOTAL_BINARY_LEN, MAX_X509_DECODED_BINARY_LEN, ParseError, Reference,
    RetrievalMethodTransforms, SignatureAlgorithm, XMLDSIG_NS,
};
use super::parse::{
    parse_key_info_with_provider_and_xml_base_budget, parse_reference_with_xpath_budget,
    parse_signed_info_with_xpath_budget, parse_x509_certificate,
    parse_x509_data_dispatch_with_budget_and_provider, reference_digest_method,
};
use super::signature::{
    SignatureVerificationError, verify_dsa_signature_spki, verify_ecdsa_signature_pem,
    verify_rsa_signature_pem,
};
#[cfg(test)]
use super::transforms::BASE64_TRANSFORM_URI;
use super::transforms::{
    DEFAULT_IMPLICIT_C14N_URI, Transform, TransformExecutionBudget, TransformOptions,
    XPATH_TRANSFORM_URI, XPathHereSemantics, XPathSignatureParseBudget,
    execute_transforms_with_options_and_budget, map_c14n_resource_policy_violation,
    transform_chain_produces_binary,
};
use super::uri::{UriReferenceResolver, same_document_reference_id};
use super::whitespace::{is_xml_whitespace_only, normalize_xml_base64_bytes};

const MAX_SIGNATURE_VALUE_LEN: usize = 8192;
const MAX_SIGNATURE_VALUE_TEXT_LEN: usize = 65_536;
const MAX_RETRIEVAL_METHOD_COUNT: usize = 64;
/// Cryptographic verifier used by [`VerifyContext`].
///
/// This trait intentionally has no `Send + Sync` supertraits so lightweight
/// single-threaded verifiers can be used without additional bounds.
pub trait VerifyingKey {
    /// Validate this key against the operation's immutable trust policy.
    ///
    /// Built-in keys override this hook so pre-resolved and resolver-produced
    /// keys enforce identical strength constraints. Custom opaque keys may
    /// retain their own policy enforcement by accepting the default no-op.
    fn validate_policy(
        &self,
        _policy: &crate::policy::VerificationPolicy,
    ) -> Result<(), DsigError> {
        Ok(())
    }

    /// Check that `signature_value` has the wire framing required by the
    /// declared algorithm and this key before provider dispatch.
    ///
    /// Key implementations with key-size-dependent framing should override
    /// this method. The default enforces the algorithm-wide XMLDSig envelope.
    fn validate_signature_value(
        &self,
        algorithm: SignatureAlgorithm,
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        Ok(super::signature::signature_value_matches_algorithm(
            algorithm,
            signature_value,
        ))
    }

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
    /// Resolve a verification key from parsed `<KeyInfo>` sources.
    ///
    /// Return `Ok(None)` when no suitable key could be resolved from available
    /// key material (for example, missing `<KeyInfo>` candidates). `VerifyContext`
    /// maps `Ok(None)` to `DsigStatus::Invalid(FailureReason::KeyNotFound)`;
    /// reserve `Err(...)` for resolver failures.
    fn resolve<'a>(
        &'a self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
    ) -> Result<Option<Box<dyn VerifyingKey + 'a>>, DsigError>;

    /// Resolve under the operation's immutable policy snapshot.
    ///
    /// Implementations that make trust or key-source decisions must override
    /// this method. Resolver implementations that inspect multiple candidates
    /// must enforce [`crate::policy::ResourcePolicy::max_key_candidates`] across
    /// that internal search. The verification pipeline separately requires
    /// capacity for the single candidate returned by any resolver. The default
    /// preserves source-only custom resolvers whose behavior is independent of
    /// other policy fields.
    fn resolve_with_policy<'a>(
        &'a self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
        _policy: &crate::policy::VerificationPolicy,
    ) -> Result<Option<Box<dyn VerifyingKey + 'a>>, DsigError> {
        self.resolve(key_info, algorithm)
    }

    /// Resolve under both the operation policy and cryptographic provider.
    ///
    /// Resolvers that evaluate cryptographic key metadata, such as
    /// `X509Digest`, must override this hook. The default keeps existing
    /// policy-aware custom resolvers source-compatible.
    fn resolve_with_policy_and_provider<'a>(
        &'a self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
        policy: &crate::policy::VerificationPolicy,
        _provider: &dyn crate::provider::CryptoProvider,
    ) -> Result<Option<Box<dyn VerifyingKey + 'a>>, DsigError> {
        self.resolve_with_policy(key_info, algorithm, policy)
    }

    /// Return `true` when this resolver consumes document `<KeyInfo>` material.
    ///
    /// The verification pipeline uses this to decide whether malformed
    /// `<KeyInfo>` should raise `DsigError::ParseKeyInfo` before resolver
    /// execution. Resolvers that ignore document key material can keep the
    /// default `false` to avoid fail-closed parsing on advisory `<KeyInfo>`.
    fn consumes_document_key_info(&self) -> bool {
        false
    }
}

/// Allowed URI classes for `<Reference URI="...">`.
///
/// External URIs resolve only from bytes supplied through
/// [`VerifyContext::external_resources`]; allowing them never enables I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "pass the policy to VerifyContext::allowed_uri_types(), or store it for reuse"]
pub struct UriTypeSet {
    allow_empty: bool,
    allow_same_document: bool,
    allow_external: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UriClass {
    Empty,
    SameDocument,
    External,
}

fn classify_uri(uri: &str) -> UriClass {
    if uri.is_empty() {
        UriClass::Empty
    } else if uri.starts_with('#') {
        UriClass::SameDocument
    } else {
        UriClass::External
    }
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
    /// External URIs still require an explicit caller-owned resource map.
    pub const ALL: Self = Self {
        allow_empty: true,
        allow_same_document: true,
        allow_external: true,
    };

    pub(crate) fn allows(self, uri: &str) -> bool {
        match classify_uri(uri) {
            UriClass::Empty => self.allow_empty,
            UriClass::SameDocument => self.allow_same_document,
            UriClass::External => self.allow_external,
        }
    }
}

impl Default for UriTypeSet {
    fn default() -> Self {
        Self::SAME_DOCUMENT
    }
}

/// Request-scoped selection of the XMLDSig operation node.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SignatureSelection<'a> {
    /// Require exactly one `Signature` in the complete document.
    #[default]
    UniqueDocumentSignature,
    /// Select the first descendant `Signature` from the document root.
    FirstDocumentSignature,
    /// Select the first descendant `Signature` below the element with this ID.
    FirstSignatureUnderId(&'a str),
}

/// Verification builder/configuration.
#[must_use = "configure the context and call verify(), or store it for reuse"]
pub struct VerifyContext<'a> {
    key: Option<&'a dyn VerifyingKey>,
    key_resolver: Option<&'a dyn KeyResolver>,
    policy: crate::policy::VerificationPolicy,
    provider: &'a dyn crate::provider::CryptoProvider,
    store_pre_digest: bool,
    external_resources: Option<&'a HashMap<String, Vec<u8>>>,
    signature_selection: SignatureSelection<'a>,
    id_attributes: &'a [crate::IdAttributeRegistration],
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
            policy: crate::policy::VerificationPolicy::default(),
            provider: crate::provider::default_provider(),
            store_pre_digest: false,
            external_resources: None,
            signature_selection: SignatureSelection::UniqueDocumentSignature,
            id_attributes: &[],
        }
    }

    /// Set a pre-resolved verification key.
    ///
    /// Built-in [`super::VerificationKey`] values are validated against the
    /// same operation key-strength policy as resolver-produced keys. Custom
    /// opaque [`VerifyingKey`] implementations retain responsibility for any
    /// key metadata that the core cannot inspect.
    pub fn key(mut self, key: &'a dyn VerifyingKey) -> Self {
        self.key = Some(key);
        self
    }

    /// Set a key resolver fallback used when `key()` is not provided.
    pub fn key_resolver(mut self, resolver: &'a dyn KeyResolver) -> Self {
        self.key_resolver = Some(resolver);
        self
    }

    /// Replace the complete immutable verification policy snapshot.
    pub fn policy(mut self, policy: crate::policy::VerificationPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Select the cryptographic provider for this verification operation.
    pub fn provider(mut self, provider: &'a dyn crate::provider::CryptoProvider) -> Self {
        self.provider = provider;
        self
    }

    /// Enable or disable `<Manifest>` processing.
    ///
    /// When enabled, references in `<ds:Manifest>` elements that are direct
    /// element children of `<ds:Object>` are processed only when the direct-child
    /// `<ds:Object>` or `<ds:Manifest>` itself is referenced from `<SignedInfo>`
    /// by an ID-based same-document fragment URI such as `#id` or
    /// `#xpointer(id('id'))`, and that reference uses only canonicalization
    /// transforms (or implicit canonicalization). Filtering or binary transforms
    /// do not prove that the complete Manifest structure was authenticated.
    /// Only those signed Manifest references are returned in
    /// `VerifyResult::manifest_references`.
    /// Manifest parsing begins only after every `<SignedInfo>` reference digest
    /// validates; a failure returns immediately with no Manifest results.
    /// Nested `<ds:Manifest>` descendants under `<ds:Object>` are not
    /// processed.
    /// Direct-child unsigned/unreferenced Manifests are skipped and do not
    /// appear in `VerifyResult::manifest_references`.
    /// Whole-document same-document references such as `URI=""` or
    /// `URI="#xpointer(/)"` do not mark a specific direct-child
    /// `<ds:Object>`/`<ds:Manifest>` as signed for this option.
    ///
    /// Manifests are parsed and processed only after the SignedInfo references
    /// and SignatureValue both validate. Their digest mismatches, policy
    /// violations, and processing failures are then reported independently in
    /// `VerifyResult::manifest_references` and do not alter `VerifyResult::status`.
    /// Callers that enable `process_manifests(true)` must inspect
    /// `VerifyResult::manifest_references` in addition to `VerifyResult::status`
    /// when interpreting `verify()` results.
    /// Structural/parse errors in Manifest content abort `verify()` and are
    /// returned as `Err(...)`.
    pub fn process_manifests(mut self, enabled: bool) -> Self {
        self.policy.manifest_processing = if enabled {
            crate::policy::ManifestProcessing::Process
        } else {
            crate::policy::ManifestProcessing::Ignore
        };
        self
    }

    /// Restrict allowed reference URI classes.
    pub fn allowed_uri_types(mut self, types: UriTypeSet) -> Self {
        self.policy.uris.references = types;
        self
    }

    /// Restrict URI classes used to retrieve key material from `<KeyInfo>`.
    ///
    /// This policy is independent from [`Self::allowed_uri_types`]: allowing an
    /// external signed payload does not implicitly allow external key retrieval.
    /// Same-document retrieval is enabled by default; external retrieval requires
    /// an explicit opt-in and still uses only caller-supplied resources.
    pub fn allowed_retrieval_method_uri_types(mut self, types: UriTypeSet) -> Self {
        self.policy.uris.retrieval_methods = types;
        self
    }

    /// Provide external URI payloads explicitly.
    ///
    /// The map is the complete external I/O boundary: verification never
    /// performs network or filesystem access. External URIs must also be
    /// enabled through [`UriTypeSet`]. Map keys are RFC 3986 resolved URI
    /// identities: use normalized paths with dot segments removed and retain
    /// query or fragment suffixes.
    pub fn external_resources(mut self, resources: &'a HashMap<String, Vec<u8>>) -> Self {
        self.external_resources = Some(resources);
        self
    }

    /// Select the operation start node by its XML ID value.
    ///
    /// Verification selects the first descendant `<Signature>` in document
    /// order. This is request context, not a policy decision, and mirrors
    /// libxmlsec1's depth-first `xmlSecFindNode` start-node contract.
    pub fn start_node_id(mut self, id: &'a str) -> Self {
        self.signature_selection = SignatureSelection::FirstSignatureUnderId(id);
        self
    }

    /// Select the first descendant `<Signature>` from the document root.
    ///
    /// This is the libxmlsec1 command-line operation-root contract. The library
    /// default remains fail-closed and requires a unique document signature.
    pub fn first_document_signature(mut self) -> Self {
        self.signature_selection = SignatureSelection::FirstDocumentSignature;
        self
    }

    /// Add caller-declared ID attributes for start-node and Reference lookup.
    pub fn id_attributes(mut self, registrations: &'a [crate::IdAttributeRegistration]) -> Self {
        self.id_attributes = registrations;
        self
    }

    /// Allow bounded internal DTD declarations while keeping external entity
    /// resolution disabled. This is off by default.
    pub fn allow_internal_dtd(mut self, enabled: bool) -> Self {
        self.policy.xml.allow_internal_dtd = enabled;
        self
    }

    /// Restrict allowed transform and canonicalization algorithms by URI.
    ///
    /// Example values:
    /// - `http://www.w3.org/2000/09/xmldsig#enveloped-signature`
    /// - `http://www.w3.org/2001/10/xml-exc-c14n#`
    ///
    /// The allowlist covers explicit Reference and RetrievalMethod transforms,
    /// the declared SignedInfo canonicalization method, and implicit default
    /// C14N (`http://www.w3.org/TR/2001/REC-xml-c14n-20010315`) when a Reference
    /// transform chain ends as a node set.
    pub fn allowed_transforms<I, S>(mut self, transforms: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.policy.transforms.allowed_algorithms =
            Some(transforms.into_iter().map(Into::into).collect());
        self
    }

    /// Store pre-digest buffers for diagnostics.
    ///
    /// Retained reference buffers and canonicalized `<SignedInfo>` share a
    /// non-configurable 32 MiB safety ceiling. Canonicalized `<SignedInfo>` is
    /// charged even when diagnostic retention is disabled because signature
    /// verification always materializes it. Overflow remains a typed policy
    /// violation at both low-level and end-to-end entry points.
    pub fn store_pre_digest(mut self, enabled: bool) -> Self {
        self.store_pre_digest = enabled;
        self
    }

    /// Select the node returned by XPath's `here()` extension function.
    ///
    /// The default follows XMLDSig and returns the `<XPath>` parameter.
    /// Use [`XPathHereSemantics::XmlSecLegacy`] only for documents known to
    /// have been generated with libxmlsec1's `<Transform>` interpretation.
    pub fn xpath_here_semantics(mut self, semantics: XPathHereSemantics) -> Self {
        self.policy.transforms.xpath_here_semantics = semantics;
        self
    }

    fn allowed_transform_uris(&self) -> Option<&HashSet<String>> {
        self.policy.transforms.allowed_algorithms.as_ref()
    }

    fn transform_options(&self) -> TransformOptions {
        TransformOptions::default()
            .allow_internal_dtd(self.policy.xml.allow_internal_dtd)
            .xpath_here_semantics(self.policy.transforms.xpath_here_semantics)
    }

    /// Verify one XMLDSig signature using this context.
    ///
    /// Returns `Ok(VerifyResult)` for both valid and invalid signatures; inspect
    /// `VerifyResult::status` for the core `<SignedInfo>` and signature-value
    /// outcome. When Manifest processing is enabled, inspect every
    /// `VerifyResult::manifest_references` entry separately. `Err(...)` is
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
/// - `store_pre_digest`: If true, store the pre-digest bytes in the result,
///   subject to the signature-wide diagnostic retention ceiling.
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
    let execution_budget = TransformExecutionBudget::default();
    let canonicalized_data_budget = CanonicalizedDataBudget::default();
    let execution = ReferenceExecutionContext {
        store_pre_digest,
        transform_options: TransformOptions::default(),
        transform_budget: &execution_budget,
        canonicalized_data_budget: &canonicalized_data_budget,
        provider: crate::provider::default_provider(),
    };
    process_reference_with_options(
        reference,
        resolver,
        signature_node,
        reference_set,
        reference_index,
        reference_origin_node(signature_node, reference_set, reference_index),
        &execution,
    )
}

fn reference_origin_node<'a, 'input>(
    signature_node: Node<'a, 'input>,
    reference_set: ReferenceSet,
    reference_index: usize,
) -> Option<Node<'a, 'input>> {
    let is_reference = |node: &Node<'_, '_>| {
        node.is_element()
            && node.tag_name().namespace() == Some(XMLDSIG_NS)
            && node.tag_name().name() == "Reference"
    };
    match reference_set {
        ReferenceSet::SignedInfo => signature_node
            .children()
            .find(|node| {
                node.is_element()
                    && node.tag_name().namespace() == Some(XMLDSIG_NS)
                    && node.tag_name().name() == "SignedInfo"
            })?
            .children()
            .filter(is_reference)
            .nth(reference_index),
        ReferenceSet::Manifest => signature_node
            .children()
            .filter(|node| {
                node.is_element()
                    && node.tag_name().namespace() == Some(XMLDSIG_NS)
                    && node.tag_name().name() == "Object"
            })
            .flat_map(|object| {
                object.children().filter(|node| {
                    node.is_element()
                        && node.tag_name().namespace() == Some(XMLDSIG_NS)
                        && node.tag_name().name() == "Manifest"
                })
            })
            .flat_map(|manifest| manifest.children().filter(is_reference))
            .nth(reference_index),
    }
}

struct ReferenceExecutionContext<'a> {
    store_pre_digest: bool,
    transform_options: TransformOptions,
    transform_budget: &'a TransformExecutionBudget,
    canonicalized_data_budget: &'a CanonicalizedDataBudget,
    provider: &'a dyn crate::provider::CryptoProvider,
}

struct CanonicalizedDataBudget {
    remaining: Cell<usize>,
    max_bytes: usize,
}

impl Default for CanonicalizedDataBudget {
    fn default() -> Self {
        Self {
            remaining: Cell::new(CANONICALIZED_SIGNATURE_DATA_BYTE_CEILING),
            max_bytes: CANONICALIZED_SIGNATURE_DATA_BYTE_CEILING,
        }
    }
}

impl CanonicalizedDataBudget {
    fn remaining(&self) -> usize {
        self.remaining.get()
    }

    fn charge(&self, bytes: usize) -> Result<(), ReferenceProcessingError> {
        let available = self.remaining.get();
        let Some(remaining) = available.checked_sub(bytes) else {
            self.remaining.set(0);
            return Err(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::CANONICALIZED_BYTES,
                maximum: self.max_bytes,
                actual: self
                    .max_bytes
                    .saturating_add(bytes.saturating_sub(available)),
            }
            .into());
        };
        self.remaining.set(remaining);
        Ok(())
    }

    fn with_limit(max_bytes: usize) -> Self {
        Self {
            remaining: Cell::new(max_bytes),
            max_bytes,
        }
    }
}

fn process_reference_with_options(
    reference: &Reference,
    resolver: &UriReferenceResolver<'_>,
    signature_node: Node<'_, '_>,
    reference_set: ReferenceSet,
    reference_index: usize,
    reference_node: Option<Node<'_, '_>>,
    execution: &ReferenceExecutionContext<'_>,
) -> Result<ReferenceResult, ReferenceProcessingError> {
    // 1. Dereference URI. Omitted URI is distinct from URI="" in XMLDSig and
    // must be rejected until caller-provided external object resolution exists.
    let uri = reference
        .uri
        .as_deref()
        .ok_or(ReferenceProcessingError::MissingUri)?;
    let initial_data = reference_node
        .map_or_else(
            || {
                resolver.dereference_with_budget(
                    uri,
                    execution.transform_budget.node_set_materialization(),
                )
            },
            |node| {
                resolver.dereference_from_with_budget(
                    uri,
                    node,
                    execution.transform_budget.node_set_materialization(),
                    execution.transform_budget.xml_base_resolution(),
                )
            },
        )
        .map_err(ReferenceProcessingError::UriDereference)?;

    // 2. Apply transform chain
    let pre_digest_bytes = execute_transforms_with_options_and_budget(
        signature_node,
        initial_data,
        &reference.transforms,
        execution.transform_options,
        execution.transform_budget,
    )
    .map_err(ReferenceProcessingError::Transform)?;

    // 3. Compute digest
    let computed_digest = super::compute_digest_with_provider(
        execution.provider,
        reference.digest_method,
        &pre_digest_bytes,
    )?;

    // 4. Compare with stored DigestValue (constant-time)
    let status = if constant_time_eq(&computed_digest, &reference.digest_value) {
        DsigStatus::Valid
    } else {
        DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch {
            ref_index: reference_index,
        })
    };

    let pre_digest_data = if execution.store_pre_digest {
        execution
            .canonicalized_data_budget
            .charge(pre_digest_bytes.len())?;
        Some(pre_digest_bytes)
    } else {
        None
    };

    Ok(ReferenceResult {
        reference_set,
        reference_index,
        uri: uri.to_owned(),
        digest_algorithm: reference.digest_method,
        status,
        pre_digest_data,
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
    let execution_budget = TransformExecutionBudget::default();
    let canonicalized_data_budget = CanonicalizedDataBudget::default();
    let execution = ReferenceExecutionContext {
        store_pre_digest,
        transform_options: TransformOptions::default(),
        transform_budget: &execution_budget,
        canonicalized_data_budget: &canonicalized_data_budget,
        provider: crate::provider::default_provider(),
    };
    process_all_references_with_options(references, resolver, signature_node, &execution)
}

fn process_all_references_with_options(
    references: &[Reference],
    resolver: &UriReferenceResolver<'_>,
    signature_node: Node<'_, '_>,
    execution: &ReferenceExecutionContext<'_>,
) -> Result<ReferencesResult, ReferenceProcessingError> {
    let mut results = Vec::with_capacity(references.len());

    for (i, reference) in references.iter().enumerate() {
        let result = process_reference_with_options(
            reference,
            resolver,
            signature_node,
            ReferenceSet::SignedInfo,
            i,
            reference_origin_node(signature_node, ReferenceSet::SignedInfo, i),
            execution,
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
    /// The immutable verification policy rejected reference processing.
    #[error("verification policy violation: {0}")]
    Policy(#[from] crate::policy::PolicyViolation),

    /// The selected provider could not compute the declared digest.
    #[error("cryptographic provider error: {0}")]
    Provider(#[from] crate::provider::ProviderError),

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
    /// Core XMLDSig status for the `<SignedInfo>` references and signature value.
    ///
    /// Manifest reference failures do not alter this field; inspect
    /// [`Self::manifest_references`] before accepting Manifest-backed data.
    pub status: DsigStatus,
    /// `<Reference>` verification results from `<SignedInfo>`.
    /// On fail-fast, this includes references up to and including
    /// the first digest mismatch only.
    pub signed_info_references: Vec<ReferenceResult>,
    /// `<Manifest>` reference results.
    /// Populated only when `VerifyContext::process_manifests(true)` is enabled
    /// and core signature validation succeeds.
    /// Includes only references from signed direct-child `<ds:Object>/<ds:Manifest>`
    /// blocks that are referenced from `<SignedInfo>`.
    /// Each entry has an independent status that does not alter [`Self::status`].
    /// Callers must inspect every entry before accepting Manifest-backed data.
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
    /// The compiled verification policy rejected an operation input.
    #[error("verification policy violation: {0}")]
    Policy(#[from] crate::policy::PolicyViolation),

    /// The selected provider cannot execute the requested operation.
    #[error("cryptographic provider error: {0}")]
    Provider(#[from] crate::provider::ProviderError),

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

    /// The requested operation start node is absent or has a duplicate ID.
    #[error("selected node ID is missing or ambiguous: {id}")]
    SelectedNodeUnavailable {
        /// Caller-provided XML ID value.
        id: String,
    },

    /// `<SignedInfo>` parsing failed.
    #[error("failed to parse SignedInfo: {0}")]
    ParseSignedInfo(super::parse::ParseError),

    /// `<KeyInfo>` parsing failed.
    #[error("failed to parse KeyInfo: {0}")]
    ParseKeyInfo(#[source] super::parse::ParseError),

    /// Configuration-driven key resolution failed.
    #[error("key resolution failed: {0}")]
    KeyResolution(#[from] super::keys::KeyResolutionError),

    /// `<Object>/<Manifest>/<Reference>` parsing failed.
    #[error("failed to parse Manifest reference: {0}")]
    ParseManifestReference(#[source] ParseError),

    /// Reference processing failed.
    #[error("reference processing failed: {0}")]
    Reference(ReferenceProcessingError),

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

impl From<super::parse::ParseError> for DsigError {
    fn from(error: super::parse::ParseError) -> Self {
        match error {
            super::parse::ParseError::Policy(error) => Self::Policy(error),
            super::parse::ParseError::Transform(super::TransformError::Policy(error)) => {
                Self::Policy(error)
            }
            error => Self::ParseSignedInfo(error),
        }
    }
}

fn map_key_info_parse_error(error: super::parse::ParseError) -> DsigError {
    match error {
        super::parse::ParseError::Policy(error)
        | super::parse::ParseError::Transform(super::TransformError::Policy(error)) => {
            DsigError::Policy(error)
        }
        error => DsigError::ParseKeyInfo(error),
    }
}

fn map_manifest_parse_error(error: super::parse::ParseError) -> DsigError {
    match error {
        super::parse::ParseError::Policy(error)
        | super::parse::ParseError::Transform(super::TransformError::Policy(error)) => {
            DsigError::Policy(error)
        }
        error => DsigError::ParseManifestReference(error),
    }
}

impl From<ReferenceProcessingError> for DsigError {
    fn from(error: ReferenceProcessingError) -> Self {
        match error {
            ReferenceProcessingError::Policy(error) => Self::Policy(error),
            ReferenceProcessingError::UriDereference(super::TransformError::Policy(error))
            | ReferenceProcessingError::Transform(super::TransformError::Policy(error)) => {
                Self::Policy(error)
            }
            error => Self::Reference(error),
        }
    }
}

type SignatureVerificationPipelineError = DsigError;

/// Verify one XMLDSig `<Signature>` end-to-end with a PEM public key.
///
/// Pipeline:
/// 1. Parse `<Signature>` children and enforce structural constraints
/// 2. Parse `<SignedInfo>`
/// 3. Validate all `<Reference>` digests (fail-fast)
/// 4. Canonicalize `<SignedInfo>`
/// 5. Base64-decode `<SignatureValue>`
/// 6. Verify signature bytes against canonicalized `<SignedInfo>` using the provided PEM key
///
/// If any `<Reference>` digest mismatches, returns `Ok` with
/// `status == Invalid(ReferenceDigestMismatch { .. })`.
///
/// This API uses only the provided PEM key and does not parse embedded
/// `<KeyInfo>` key material for key selection/validation. Consequently,
/// malformed optional `<KeyInfo>` does not produce `DsigError::ParseKeyInfo`
/// on this API path.
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
    ctx.policy.validate()?;
    ctx.policy.resources.validate_xml_document_len(xml.len())?;
    let doc = Document::parse_with_options(
        xml,
        roxmltree::ParsingOptions {
            allow_dtd: ctx.policy.xml.allow_internal_dtd,
            nodes_limit: ctx.policy.resources.effective_xml_nodes(),
            entity_resolver: None,
        },
    )?;
    let resolver = UriReferenceResolver::with_id_registrations(&doc, ctx.id_attributes)
        .with_external_resource_limits(
            ctx.policy.resources.max_external_resource_bytes,
            ctx.policy.resources.max_external_resource_total_bytes,
        );
    let resolver = match ctx.external_resources {
        Some(resources) => resolver.with_external_resources(resources),
        None => resolver,
    };
    let execution_budget = TransformExecutionBudget::from_resources(&ctx.policy.resources);
    let start_node = match ctx.signature_selection {
        SignatureSelection::FirstSignatureUnderId(id) => {
            resolver.node_for_id(id).ok_or_else(|| {
                SignatureVerificationPipelineError::SelectedNodeUnavailable { id: id.to_owned() }
            })?
        }
        SignatureSelection::UniqueDocumentSignature
        | SignatureSelection::FirstDocumentSignature => doc.root(),
    };
    let mut signatures = start_node.descendants().filter(|node| {
        node.is_element()
            && node.tag_name().name() == "Signature"
            && node.tag_name().namespace() == Some(XMLDSIG_NS)
    });
    let signature_node = match (signatures.next(), ctx.signature_selection) {
        (None, _) => {
            return Err(SignatureVerificationPipelineError::MissingElement {
                element: "Signature",
            });
        }
        // libxmlsec1 treats --node-id as an operation start node and performs
        // a depth-first xmlSecFindNode lookup from there. Without a selector,
        // the library API retains its fail-closed document-wide cardinality.
        (
            Some(node),
            SignatureSelection::FirstDocumentSignature
            | SignatureSelection::FirstSignatureUnderId(_),
        ) => node,
        (Some(node), SignatureSelection::UniqueDocumentSignature)
            if signatures.next().is_none() =>
        {
            node
        }
        (Some(_), SignatureSelection::UniqueDocumentSignature) => {
            return Err(SignatureVerificationPipelineError::InvalidStructure {
                reason: "Signature must appear exactly once in document",
            });
        }
    };

    let signature_children = parse_signature_children(signature_node)?;
    let signed_info_node = signature_children.signed_info_node;
    let should_parse_key_info = match (ctx.key, ctx.key_resolver) {
        (Some(_), _) => false,
        (None, Some(resolver)) => resolver.consumes_document_key_info(),
        (None, None) => true,
    };
    let mut key_info = if should_parse_key_info {
        signature_children
            .key_info_node
            .map(|node| {
                parse_key_info_with_provider_and_xml_base_budget(
                    node,
                    ctx.provider,
                    execution_budget.xml_base_resolution(),
                )
            })
            .transpose()
            .map_err(map_key_info_parse_error)?
    } else {
        None
    };

    let mut xpath_parse_budget = XPathSignatureParseBudget::from_resources(&ctx.policy.resources);
    let signed_info =
        parse_signed_info_with_xpath_budget(signed_info_node, &mut xpath_parse_budget)?;
    if signed_info.references.len() > ctx.policy.resources.max_references {
        return Err(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::SIGNATURE_REFERENCES,
            maximum: ctx.policy.resources.max_references,
            actual: signed_info.references.len(),
        }
        .into());
    }
    for reference in &signed_info.references {
        if reference.transforms.len() > ctx.policy.resources.max_transforms_per_reference {
            return Err(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::REFERENCE_TRANSFORMS,
                maximum: ctx.policy.resources.max_transforms_per_reference,
                actual: reference.transforms.len(),
            }
            .into());
        }
    }
    ctx.policy
        .check_signature_algorithm(signed_info.signature_method)?;
    for reference in &signed_info.references {
        if ctx
            .policy
            .digest_algorithms
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(&reference.digest_method))
        {
            return Err(crate::policy::PolicyViolation::Algorithm {
                operation: "verification",
                algorithm: reference.digest_method.uri().to_string(),
            }
            .into());
        }
    }
    enforce_reference_policies(
        &signed_info.references,
        ctx.policy.uris.references,
        ctx.allowed_transform_uris(),
    )?;
    enforce_transform_allowed(ctx.allowed_transform_uris(), signed_info.c14n_method.uri())?;

    if let Some(resources) = ctx.external_resources {
        let mut total = 0usize;
        for bytes in resources.values() {
            if bytes.len() > ctx.policy.resources.max_external_resource_bytes {
                return Err(crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::EXTERNAL_RESOURCE_BYTES,
                    maximum: ctx.policy.resources.max_external_resource_bytes,
                    actual: bytes.len(),
                }
                .into());
            }
            total = total.checked_add(bytes.len()).ok_or(
                SignatureVerificationPipelineError::InvalidStructure {
                    reason: "external resource total length overflow",
                },
            )?;
        }
        if total > ctx.policy.resources.max_external_resource_total_bytes {
            return Err(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::AGGREGATE_EXTERNAL_RESOURCE_BYTES,
                maximum: ctx.policy.resources.max_external_resource_total_bytes,
                actual: total,
            }
            .into());
        }
    }
    let retrieval_materialization = if let Some(info) = key_info.as_mut() {
        materialize_retrieval_methods_with_budgets(
            info,
            &resolver,
            ctx.policy.uris.retrieval_methods,
            ctx.allowed_transform_uris(),
            ctx.provider,
            &mut xpath_parse_budget,
            &execution_budget,
        )?
    } else {
        RetrievalMaterialization::default()
    };
    let canonicalized_data_budget =
        CanonicalizedDataBudget::with_limit(ctx.policy.resources.effective_canonicalized_bytes());
    let execution = ReferenceExecutionContext {
        store_pre_digest: ctx.store_pre_digest,
        transform_options: ctx.transform_options(),
        transform_budget: &execution_budget,
        canonicalized_data_budget: &canonicalized_data_budget,
        provider: ctx.provider,
    };
    let references = process_all_references_with_options(
        &signed_info.references,
        &resolver,
        signature_node,
        &execution,
    )?;

    if let Some(first_failure) = references.first_failure {
        let status = references.results[first_failure].status;
        return Ok(VerifyResult {
            status,
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
    let signed_info_limit = canonicalized_data_budget
        .remaining()
        .min(execution_budget.remaining_c14n_output());
    canonicalize_bounded_with_xml_base_budget(
        &doc,
        Some(&|node| signed_info_subtree.contains(&node.id())),
        &signed_info.c14n_method,
        signed_info_limit,
        execution_budget.xml_base_resolution(),
        &mut canonical_signed_info,
    )
    .map_err(|error| {
        if let Some(violation) = map_c14n_resource_policy_violation(
            &error,
            crate::policy::resource_name::CANONICALIZED_BYTES,
            canonicalized_data_budget.max_bytes,
        ) {
            SignatureVerificationPipelineError::Policy(violation)
        } else {
            SignatureVerificationPipelineError::Canonicalization(error)
        }
    })?;
    execution_budget
        .charge_c14n_output(canonical_signed_info.len())
        .map_err(ReferenceProcessingError::Transform)?;
    canonicalized_data_budget.charge(canonical_signed_info.len())?;

    let signature_value = decode_signature_value(signature_children.signature_value_node)?;
    if signed_info.signature_method == SignatureAlgorithm::HmacSha1 {
        let expected_bits = signed_info.hmac_output_length_bits.unwrap_or(160);
        if signature_value.len() != expected_bits / 8 {
            return Err(SignatureVerificationPipelineError::InvalidStructure {
                reason: "SignatureValue length does not match HMACOutputLength",
            });
        }
    }
    let Some(resolved_key) =
        resolve_verifying_key(ctx, key_info.as_ref(), signed_info.signature_method)?
    else {
        if let Some(error) = retrieval_materialization.deferred_error {
            return Err(error);
        }
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
    verifier.validate_policy(&ctx.policy)?;
    if !verifier.validate_signature_value(signed_info.signature_method, &signature_value)? {
        return Ok(VerifyResult {
            status: DsigStatus::Invalid(FailureReason::SignatureMismatch),
            signed_info_references: references.results,
            manifest_references: Vec::new(),
            canonicalized_signed_info: if ctx.store_pre_digest {
                Some(canonical_signed_info)
            } else {
                None
            },
        });
    }
    ctx.provider
        .require_capability(crate::provider::ProviderCapability::Verify(
            signed_info.signature_method,
        ))?;
    let signature_valid = ctx.provider.verify(
        verifier,
        signed_info.signature_method,
        &canonical_signed_info,
        &signature_value,
    )?;

    if !signature_valid {
        return Ok(VerifyResult {
            status: DsigStatus::Invalid(FailureReason::SignatureMismatch),
            signed_info_references: references.results,
            manifest_references: Vec::new(),
            canonicalized_signed_info: if ctx.store_pre_digest {
                Some(canonical_signed_info)
            } else {
                None
            },
        });
    }

    let manifest_references = if ctx.policy.manifest_processing
        == crate::policy::ManifestProcessing::Process
    {
        let signed_info_reference_nodes =
            collect_authenticated_signed_info_reference_nodes(&signed_info.references, &resolver);
        let remaining_reference_capacity = ctx
            .policy
            .resources
            .max_references
            .checked_sub(signed_info.references.len())
            .ok_or(SignatureVerificationPipelineError::InvalidStructure {
                reason: "SignedInfo exceeds the per-signature Reference limit",
            })?;
        process_manifest_references(
            signature_node,
            &resolver,
            ctx,
            &signed_info_reference_nodes,
            remaining_reference_capacity,
            &execution,
            &mut xpath_parse_budget,
        )?
    } else {
        Vec::new()
    };

    Ok(VerifyResult {
        status: DsigStatus::Valid,
        signed_info_references: references.results,
        manifest_references,
        canonicalized_signed_info: if ctx.store_pre_digest {
            Some(canonical_signed_info)
        } else {
            None
        },
    })
}

#[derive(Debug, Default)]
struct RetrievalMaterialization {
    deferred_error: Option<SignatureVerificationPipelineError>,
}

fn materialize_retrieval_methods_with_budgets(
    key_info: &mut KeyInfo,
    resolver: &UriReferenceResolver<'_>,
    allowed_uri_types: UriTypeSet,
    allowed_transforms: Option<&HashSet<String>>,
    provider: &dyn crate::provider::CryptoProvider,
    xpath_parse_budget: &mut XPathSignatureParseBudget,
    execution_budget: &TransformExecutionBudget,
) -> Result<RetrievalMaterialization, SignatureVerificationPipelineError> {
    let retrieval_count = key_info
        .sources
        .iter()
        .filter(|source| matches!(source, super::parse::KeyInfoSource::RetrievalMethod { .. }))
        .count();
    if retrieval_count > MAX_RETRIEVAL_METHOD_COUNT {
        return Err(SignatureVerificationPipelineError::InvalidStructure {
            reason: "KeyInfo contains too many RetrievalMethod elements",
        });
    }

    let mut total_binary_len = existing_x509_binary_len(key_info)?;
    let mut seen = HashSet::new();
    let mut materialized = Vec::with_capacity(key_info.sources.len());
    let mut outcome = RetrievalMaterialization::default();
    for source in std::mem::take(&mut key_info.sources) {
        let super::parse::KeyInfoSource::RetrievalMethod {
            uri: resolved_uri,
            resource_type,
            transforms,
        } = source
        else {
            materialized.push(source);
            continue;
        };

        let identity = (
            resolved_uri.clone(),
            resource_type.clone(),
            transforms.clone(),
        );
        if !seen.insert(identity) {
            continue;
        }

        if resource_type.as_deref() == Some("http://www.w3.org/2000/09/xmldsig#rawX509Certificate")
        {
            if transforms != RetrievalMethodTransforms::None
                || classify_uri(&resolved_uri) != UriClass::External
            {
                return Err(SignatureVerificationPipelineError::InvalidStructure {
                    reason: "raw X509 RetrievalMethod requires an untransformed external URI",
                });
            }
            if !allowed_uri_types.allows(&resolved_uri) {
                return Err(crate::policy::PolicyViolation::Uri {
                    operation: "verification",
                    reason: "retrieval method URI class is not permitted",
                }
                .into());
            }
            let certificate = resolver.external_resource(&resolved_uri).map_err(|error| {
                SignatureVerificationPipelineError::from(ReferenceProcessingError::Transform(error))
            })?;
            let Some(certificate) = certificate else {
                outcome.deferred_error.get_or_insert_with(|| {
                    SignatureVerificationPipelineError::Reference(
                        ReferenceProcessingError::Transform(super::TransformError::UnsupportedUri(
                            resolved_uri.clone(),
                        )),
                    )
                });
                materialized.push(super::parse::KeyInfoSource::RetrievalMethod {
                    uri: resolved_uri,
                    resource_type,
                    transforms,
                });
                continue;
            };
            if certificate.len() > MAX_X509_DECODED_BINARY_LEN {
                return Err(SignatureVerificationPipelineError::InvalidStructure {
                    reason: "raw X509 RetrievalMethod certificate exceeds maximum allowed length",
                });
            }
            add_retrieval_binary_usage(&mut total_binary_len, certificate.len())?;
            let parsed = match parse_x509_certificate(certificate) {
                Ok(parsed) => parsed,
                Err(error) => {
                    let error = map_key_info_parse_error(error);
                    if matches!(error, SignatureVerificationPipelineError::Policy(_)) {
                        return Err(error);
                    }
                    outcome.deferred_error.get_or_insert(error);
                    materialized.push(super::parse::KeyInfoSource::RetrievalMethod {
                        uri: resolved_uri,
                        resource_type,
                        transforms,
                    });
                    continue;
                }
            };
            materialized.push(super::parse::KeyInfoSource::X509Data(
                super::parse::X509DataInfo {
                    certificates: vec![certificate.to_vec()],
                    parsed_certificates: vec![parsed],
                    certificate_chain: vec![0],
                    ..super::parse::X509DataInfo::default()
                },
            ));
        } else if resource_type.as_deref() == Some("http://www.w3.org/2000/09/xmldsig#X509Data") {
            if !allowed_uri_types.allows(&resolved_uri) {
                return Err(crate::policy::PolicyViolation::Uri {
                    operation: "verification",
                    reason: "retrieval method URI class is not permitted",
                }
                .into());
            }
            let id = same_document_reference_id(&resolved_uri).ok_or(
                SignatureVerificationPipelineError::InvalidStructure {
                    reason: "X509Data RetrievalMethod requires a same-document URI",
                },
            )?;
            let target = resolver.node_for_id(id).ok_or(
                SignatureVerificationPipelineError::InvalidStructure {
                    reason: "X509Data RetrievalMethod target is missing or ambiguous",
                },
            )?;
            let node = match transforms {
                RetrievalMethodTransforms::None
                    if target.has_tag_name((XMLDSIG_NS, "X509Data")) =>
                {
                    target
                }
                RetrievalMethodTransforms::None => {
                    return Err(SignatureVerificationPipelineError::InvalidStructure {
                        reason: "untransformed X509Data RetrievalMethod must target X509Data directly",
                    });
                }
                RetrievalMethodTransforms::X509DataNodeSetFilter {
                    expression,
                    namespaces,
                } => {
                    enforce_transform_allowed(allowed_transforms, XPATH_TRANSFORM_URI)?;
                    xpath_parse_budget
                        .validate_expression(&expression)
                        .map_err(ReferenceProcessingError::Transform)?;
                    xpath_parse_budget
                        .validate_namespaces(&namespaces)
                        .map_err(ReferenceProcessingError::Transform)?;
                    select_retrieved_x509_data_root(target, execution_budget)?
                }
                RetrievalMethodTransforms::Unsupported => {
                    return Err(SignatureVerificationPipelineError::InvalidStructure {
                        reason: "X509Data RetrievalMethod contains unsupported transforms",
                    });
                }
            };
            let data = parse_x509_data_dispatch_with_budget_and_provider(
                node,
                &mut total_binary_len,
                provider,
            )
            .map_err(SignatureVerificationPipelineError::ParseKeyInfo)?;
            materialized.push(super::parse::KeyInfoSource::X509Data(data));
        } else {
            materialized.push(super::parse::KeyInfoSource::RetrievalMethod {
                uri: resolved_uri,
                resource_type,
                transforms,
            });
        }
    }
    key_info.sources = materialized;
    Ok(outcome)
}

fn select_retrieved_x509_data_root<'a, 'input>(
    target: Node<'a, 'input>,
    execution_budget: &TransformExecutionBudget,
) -> Result<Node<'a, 'input>, SignatureVerificationPipelineError> {
    // XMLDSig XPath filtering evaluates the predicate for every node in the
    // dereferenced node-set. `ancestor-or-self::ds:X509Data` therefore retains
    // one X509Data descendant and its subtree; it cannot import an ancestor
    // that was outside the URI target's node-set.
    execution_budget
        .validate_xpath_context_evaluations(target.descendants().count())
        .map_err(ReferenceProcessingError::Transform)?;
    let mut root = None;
    for candidate in target.descendants() {
        execution_budget
            .charge_xpath_work(1)
            .map_err(ReferenceProcessingError::Transform)?;
        execution_budget
            .charge_node_filter_work(1)
            .map_err(ReferenceProcessingError::Transform)?;
        if !candidate.is_element()
            || candidate.tag_name().namespace() != Some(XMLDSIG_NS)
            || candidate.tag_name().name() != "X509Data"
        {
            continue;
        }
        if root.replace(candidate).is_some() {
            return Err(SignatureVerificationPipelineError::InvalidStructure {
                reason: "X509Data RetrievalMethod selected multiple X509Data elements",
            });
        }
    }
    root.ok_or(SignatureVerificationPipelineError::InvalidStructure {
        reason: "X509Data RetrievalMethod selected no X509Data element",
    })
}

#[cfg(test)]
fn materialize_retrieval_methods(
    key_info: &mut KeyInfo,
    resolver: &UriReferenceResolver<'_>,
    allowed_uri_types: UriTypeSet,
    allowed_transforms: Option<&HashSet<String>>,
    provider: &dyn crate::provider::CryptoProvider,
) -> Result<RetrievalMaterialization, SignatureVerificationPipelineError> {
    materialize_retrieval_methods_with_budgets(
        key_info,
        resolver,
        allowed_uri_types,
        allowed_transforms,
        provider,
        &mut XPathSignatureParseBudget::default(),
        &TransformExecutionBudget::default(),
    )
}

fn existing_x509_binary_len(
    key_info: &KeyInfo,
) -> Result<usize, SignatureVerificationPipelineError> {
    let mut total = 0usize;
    for source in &key_info.sources {
        if let super::parse::KeyInfoSource::X509Data(info) = source {
            for len in info
                .certificates
                .iter()
                .chain(&info.skis)
                .chain(&info.crls)
                .map(Vec::len)
                .chain(info.digests.iter().map(|(_, digest)| digest.len()))
            {
                add_retrieval_binary_usage(&mut total, len)?;
            }
        }
    }
    Ok(total)
}

fn add_retrieval_binary_usage(
    total: &mut usize,
    delta: usize,
) -> Result<(), SignatureVerificationPipelineError> {
    *total =
        total
            .checked_add(delta)
            .ok_or(SignatureVerificationPipelineError::InvalidStructure {
                reason: "RetrievalMethod X509Data binary length overflow",
            })?;
    if *total > MAX_X509_DATA_TOTAL_BINARY_LEN {
        return Err(SignatureVerificationPipelineError::InvalidStructure {
            reason: "RetrievalMethod X509Data exceeds maximum aggregate binary length",
        });
    }
    Ok(())
}

fn process_manifest_references(
    signature_node: Node<'_, '_>,
    resolver: &UriReferenceResolver<'_>,
    ctx: &VerifyContext<'_>,
    signed_info_reference_nodes: &HashSet<NodeId>,
    remaining_reference_capacity: usize,
    execution: &ReferenceExecutionContext<'_>,
    xpath_parse_budget: &mut XPathSignatureParseBudget,
) -> Result<Vec<ReferenceResult>, SignatureVerificationPipelineError> {
    let mut authenticated_nodes = signed_info_reference_nodes.clone();
    let mut processed_manifests = HashSet::new();
    let mut remaining_reference_capacity = remaining_reference_capacity;
    let mut next_reference_index = 0usize;
    let mut results = Vec::new();
    loop {
        let parsed = parse_manifest_references(
            signature_node,
            &authenticated_nodes,
            &mut processed_manifests,
            &mut remaining_reference_capacity,
            &mut next_reference_index,
            xpath_parse_budget,
        )?;
        let manifest_references = parsed.references;
        results.extend(parsed.invalid_results);
        if manifest_references.is_empty() {
            break;
        }
        results.reserve(manifest_references.len());
        for (index, reference, reference_node_id) in &manifest_references {
            let result = if execution.transform_budget.remaining_c14n_output() == 0 {
                manifest_reference_invalid_result(
                    reference,
                    *index,
                    FailureReason::ReferenceProcessingFailure { ref_index: *index },
                )
            } else if reference.transforms.len() > ctx.policy.resources.max_transforms_per_reference
                || ctx
                    .policy
                    .digest_algorithms
                    .as_ref()
                    .is_some_and(|allowed| !allowed.contains(&reference.digest_method))
            {
                manifest_reference_invalid_result(
                    reference,
                    *index,
                    FailureReason::ReferencePolicyViolation { ref_index: *index },
                )
            } else {
                match enforce_reference_policies(
                    std::slice::from_ref(reference),
                    ctx.policy.uris.references,
                    ctx.allowed_transform_uris(),
                ) {
                    Ok(()) => process_reference_with_options(
                        reference,
                        resolver,
                        signature_node,
                        ReferenceSet::Manifest,
                        *index,
                        resolver.node_for_node_id(*reference_node_id),
                        execution,
                    )
                    .unwrap_or_else(|_| {
                        manifest_reference_invalid_result(
                            reference,
                            *index,
                            FailureReason::ReferenceProcessingFailure { ref_index: *index },
                        )
                    }),
                    Err(SignatureVerificationPipelineError::Policy(_)) => {
                        manifest_reference_invalid_result(
                            reference,
                            *index,
                            FailureReason::ReferencePolicyViolation { ref_index: *index },
                        )
                    }
                    Err(_) => manifest_reference_invalid_result(
                        reference,
                        *index,
                        FailureReason::ReferenceProcessingFailure { ref_index: *index },
                    ),
                }
            };
            if result.status == DsigStatus::Valid
                && reference
                    .transforms
                    .iter()
                    .all(transform_preserves_manifest_structure)
                && let Some(target_id) = reference
                    .uri
                    .as_deref()
                    .and_then(same_document_reference_id)
                    .and_then(|id| resolver.node_id_for_id(id))
            {
                // A valid Manifest digest extends trust only to the exact
                // same-document structure preserved by its transform chain.
                authenticated_nodes.insert(target_id);
            }
            results.push(result);
        }
    }
    results.sort_by_key(|result| result.reference_index);
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
    authenticated_nodes: &HashSet<NodeId>,
    processed_manifests: &mut HashSet<NodeId>,
    remaining_reference_capacity: &mut usize,
    next_reference_index: &mut usize,
    xpath_parse_budget: &mut XPathSignatureParseBudget,
) -> Result<ParsedManifestReferences, SignatureVerificationPipelineError> {
    let mut references = Vec::new();
    let mut invalid = Vec::new();
    for object_node in signature_node.children().filter(|node| {
        node.is_element()
            && node.tag_name().namespace() == Some(XMLDSIG_NS)
            && node.tag_name().name() == "Object"
    }) {
        let object_is_signed = authenticated_nodes.contains(&object_node.id());
        for manifest_node in object_node.children().filter(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(XMLDSIG_NS)
                && node.tag_name().name() == "Manifest"
        }) {
            let manifest_is_signed = authenticated_nodes.contains(&manifest_node.id());
            // Leave unauthenticated Manifests unmarked so a verified outer
            // Manifest can make them eligible on the next discovery pass.
            if !object_is_signed && !manifest_is_signed {
                continue;
            }
            if !processed_manifests.insert(manifest_node.id()) {
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
                if *remaining_reference_capacity == 0 {
                    return Err(SignatureVerificationPipelineError::InvalidStructure {
                        reason: "signed Manifests exceed the per-signature Reference limit",
                    });
                }
                *remaining_reference_capacity -= 1;
                let reference_index = *next_reference_index;
                *next_reference_index += 1;
                match parse_reference_with_xpath_budget(child, xpath_parse_budget) {
                    Ok(reference) => references.push((reference_index, reference, child.id())),
                    Err(ParseError::Transform(super::TransformError::UnsupportedTransform(_))) => {
                        let digest_algorithm =
                            reference_digest_method(child).map_err(map_manifest_parse_error)?;
                        invalid.push(ReferenceResult {
                            reference_set: ReferenceSet::Manifest,
                            reference_index,
                            uri: child.attribute("URI").unwrap_or("<omitted>").to_owned(),
                            digest_algorithm,
                            status: DsigStatus::Invalid(
                                FailureReason::ReferenceProcessingFailure {
                                    ref_index: reference_index,
                                },
                            ),
                            pre_digest_data: None,
                        });
                    }
                    Err(error) => return Err(map_manifest_parse_error(error)),
                }
            }
        }
    }
    Ok(ParsedManifestReferences {
        references,
        invalid_results: invalid,
    })
}

struct ParsedManifestReferences {
    references: Vec<(usize, Reference, NodeId)>,
    invalid_results: Vec<ReferenceResult>,
}

fn collect_authenticated_signed_info_reference_nodes(
    references: &[Reference],
    resolver: &UriReferenceResolver<'_>,
) -> HashSet<NodeId> {
    references
        .iter()
        // URI dereference identifies the transform input, not necessarily the
        // bytes authenticated by its digest. Every transform must preserve the
        // complete XML structure needed to trust and process a Manifest.
        .filter(|reference| {
            reference
                .transforms
                .iter()
                .all(transform_preserves_manifest_structure)
        })
        .filter_map(|reference| reference.uri.as_deref())
        .filter_map(same_document_reference_id)
        .filter_map(|id| resolver.node_id_for_id(id))
        .collect()
}

fn transform_preserves_manifest_structure(transform: &Transform) -> bool {
    match transform {
        Transform::C14n(_) => true,
        // Both eligible ID targets are descendants of the owning Signature.
        // Enveloped subtraction therefore removes their intersection with that
        // Signature subtree, even though the Signature node itself is not in the
        // dereferenced node set.
        Transform::Enveloped
        | Transform::XpathExcludeAllSignatures
        | Transform::XPath(_)
        | Transform::XPathFilter2(_)
        | Transform::Base64Decode => false,
    }
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
    key_info: Option<&KeyInfo>,
    algorithm: SignatureAlgorithm,
) -> Result<Option<ResolvedVerifyingKey<'k>>, SignatureVerificationPipelineError> {
    if let Some(key) = ctx.key {
        if !ctx.policy.key_sources.preset_key {
            return Err(crate::policy::PolicyViolation::KeyTrust {
                reason: "pre-resolved verification keys are disabled",
            }
            .into());
        }
        require_verifying_key_candidate_capacity(&ctx.policy)?;
        return Ok(Some(ResolvedVerifyingKey::Borrowed(key)));
    }
    if let Some(resolver) = ctx.key_resolver {
        require_verifying_key_candidate_capacity(&ctx.policy)?;
        let resolved = resolver.resolve_with_policy_and_provider(
            key_info,
            algorithm,
            &ctx.policy,
            ctx.provider,
        )?;
        return Ok(resolved.map(ResolvedVerifyingKey::Owned));
    }
    Ok(None)
}

fn require_verifying_key_candidate_capacity(
    policy: &crate::policy::VerificationPolicy,
) -> Result<(), SignatureVerificationPipelineError> {
    if policy.resources.max_key_candidates == 0 {
        return Err(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::KEY_CANDIDATES,
            maximum: 0,
            actual: 1,
        }
        .into());
    }
    Ok(())
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
            return Err(crate::policy::PolicyViolation::Uri {
                operation: "verification",
                reason: "reference URI class is not permitted",
            }
            .into());
        }

        if let Some(allowed) = allowed_transforms {
            for transform in &reference.transforms {
                let transform_uri = transform.algorithm_uri();
                enforce_transform_allowed(Some(allowed), transform_uri)?;
            }

            // External dereference has an octet-stream data type independent of
            // whether the caller supplied the resource. Every transform then
            // determines the next type, including implicit binary-to-node-set
            // adapters before XML-level transforms.
            let produces_binary = transform_chain_produces_binary(
                classify_uri(uri) == UriClass::External,
                &reference.transforms,
            );
            if !produces_binary {
                enforce_transform_allowed(Some(allowed), DEFAULT_IMPLICIT_C14N_URI)?;
            }
        }
    }
    Ok(())
}

fn enforce_transform_allowed(
    allowed_transforms: Option<&HashSet<String>>,
    algorithm: &str,
) -> Result<(), SignatureVerificationPipelineError> {
    if allowed_transforms.is_some_and(|allowed| !allowed.contains(algorithm)) {
        return Err(crate::policy::PolicyViolation::Algorithm {
            operation: "verification transform",
            algorithm: algorithm.to_owned(),
        }
        .into());
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub(super) struct SignatureChildNodes<'a, 'input> {
    signed_info_node: Node<'a, 'input>,
    signature_value_node: Node<'a, 'input>,
    key_info_node: Option<Node<'a, 'input>>,
}

pub(super) fn parse_signature_children<'a, 'input>(
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

    let mut normalized = Vec::new();
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
    normalized: &mut Vec<u8>,
) -> Result<(), SignatureVerificationPipelineError> {
    if raw_text_len.saturating_add(text.len()) > MAX_SIGNATURE_VALUE_TEXT_LEN {
        return Err(SignatureVerificationPipelineError::InvalidStructure {
            reason: "SignatureValue exceeds maximum allowed text length",
        });
    }
    *raw_text_len = raw_text_len.saturating_add(text.len());

    normalize_xml_base64_bytes(text.as_bytes(), normalized, |_| true).map_err(|err| {
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
        SignatureAlgorithm::DsaSha1 => {
            let (rest, pem) = x509_parser::pem::parse_x509_pem(public_key_pem.as_bytes())
                .map_err(|_| SignatureVerificationError::InvalidKeyPem)?;
            if !rest.iter().all(|byte| byte.is_ascii_whitespace()) || pem.label != "PUBLIC KEY" {
                return Err(SignatureVerificationError::InvalidKeyPem.into());
            }
            Ok(verify_dsa_signature_spki(
                algorithm,
                &pem.contents,
                signed_data,
                signature_value,
            )?)
        }
        SignatureAlgorithm::HmacSha1 => Err(SignatureVerificationError::UnsupportedAlgorithm {
            uri: algorithm.uri().to_string(),
        }
        .into()),
        SignatureAlgorithm::RsaSha1
        | SignatureAlgorithm::RsaSha256
        | SignatureAlgorithm::RsaSha384
        | SignatureAlgorithm::RsaSha512 => Ok(verify_rsa_signature_pem(
            algorithm,
            public_key_pem,
            signed_data,
            signature_value,
        )?),
        SignatureAlgorithm::EcdsaSha256 | SignatureAlgorithm::EcdsaSha384 => {
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
    use crate::c14n::C14nAlgorithm;
    use crate::xmldsig::TransformError;
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

    #[test]
    fn reference_resolution_uses_each_elements_effective_xml_base() {
        // Equal lexical URIs under different xml:base values identify distinct
        // caller-owned resources and must not collide in the resolver.
        let first = b"first payload";
        let second = b"second payload";
        let first_digest = base64::engine::general_purpose::STANDARD
            .encode(compute_digest(DigestAlgorithm::Sha256, first));
        let second_digest = base64::engine::general_purpose::STANDARD
            .encode(compute_digest(DigestAlgorithm::Sha256, second));
        let xml = format!(
            r#"<root xml:base="https://example.test/base/" xmlns:ds="{XMLDSIG_NS}">
                <ds:Signature><ds:SignedInfo>
                    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                    <ds:Reference xml:base="one/" URI="payload.bin">
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>{first_digest}</ds:DigestValue>
                    </ds:Reference>
                    <ds:Reference xml:base="../two/" URI="payload.bin">
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>{second_digest}</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo><ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature>
            </root>"#
        );
        let document = Document::parse(&xml).unwrap();
        let signature = document
            .descendants()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "Signature")))
            .unwrap();
        let signed_info_node = signature
            .children()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "SignedInfo")))
            .unwrap();
        let signed_info = parse_signed_info(signed_info_node).unwrap();
        let resources = HashMap::from([
            (
                "https://example.test/base/one/payload.bin".into(),
                first.to_vec(),
            ),
            (
                "https://example.test/two/payload.bin".into(),
                second.to_vec(),
            ),
        ]);
        let resolver = UriReferenceResolver::new(&document).with_external_resources(&resources);

        let result = process_all_references(&signed_info.references, &resolver, signature, false)
            .expect("each Reference should resolve against its own effective base");

        assert!(result.all_valid());
    }

    #[test]
    fn internal_dtd_opt_in_applies_to_detached_xml_transforms() {
        // The parse policy covers every XML document in one verification
        // pipeline, including caller-owned octets converted to a node-set.
        let detached = b"<!DOCTYPE payload [<!ELEMENT payload (#PCDATA)>]><payload>ok</payload>";
        let digest = base64::engine::general_purpose::STANDARD.encode(compute_digest(
            DigestAlgorithm::Sha256,
            b"<payload>ok</payload>",
        ));
        let xml = format!(
            r#"<root xmlns:ds="{XMLDSIG_NS}">
  <ds:Signature>
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="urn:detached-dtd">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>{digest}</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>AQ==</ds:SignatureValue>
  </ds:Signature>
</root>"#
        );
        let resources = HashMap::from([("urn:detached-dtd".to_owned(), detached.to_vec())]);
        let key = AcceptingKey;

        let default_error = VerifyContext::new()
            .key(&key)
            .allowed_uri_types(UriTypeSet::ALL)
            .external_resources(&resources)
            .verify(&xml)
            .expect_err("internal DTD parsing must remain disabled by default");
        assert!(matches!(
            default_error,
            SignatureVerificationPipelineError::Reference(ReferenceProcessingError::Transform(
                crate::xmldsig::TransformError::XmlParse(_)
            ))
        ));

        let result = VerifyContext::new()
            .key(&key)
            .allowed_uri_types(UriTypeSet::ALL)
            .external_resources(&resources)
            .allow_internal_dtd(true)
            .verify(&xml)
            .expect("the explicit DTD opt-in must cover detached XML transforms");

        assert_eq!(result.status, DsigStatus::Valid);

        let external_entity = br#"<!DOCTYPE payload [
            <!ENTITY ext SYSTEM "file:///etc/passwd">
        ]><payload>&ext;</payload>"#;
        let external_entity_resources =
            HashMap::from([("urn:detached-dtd".to_owned(), external_entity.to_vec())]);
        let external_entity_error = VerifyContext::new()
            .key(&key)
            .allowed_uri_types(UriTypeSet::ALL)
            .external_resources(&external_entity_resources)
            .allow_internal_dtd(true)
            .verify(&xml)
            .expect_err("the internal-DTD opt-in must not resolve external entities");
        assert!(matches!(
            external_entity_error,
            SignatureVerificationPipelineError::Reference(ReferenceProcessingError::Transform(
                crate::xmldsig::TransformError::XmlParse(_)
            ))
        ));
    }

    #[test]
    fn verification_policy_bounds_reference_canonicalization() {
        // Reference transforms and SignedInfo canonicalization are one operation;
        // references must not fall back to the transform hard-limit budget.
        let digest = base64::engine::general_purpose::STANDARD.encode([0_u8; 32]);
        let xml = format!(
            r#"<root xmlns:ds="{XMLDSIG_NS}"><payload>{}</payload><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AQ==</ds:SignatureValue></ds:Signature></root>"#,
            "payload".repeat(16)
        );
        let policy = crate::policy::VerificationPolicy {
            resources: crate::policy::ResourcePolicy {
                max_canonicalized_bytes: 64,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::VerificationPolicy::default()
        };

        let error = VerifyContext::new()
            .key(&AcceptingKey)
            .policy(policy)
            .verify(&xml)
            .expect_err("reference canonicalization must consume the policy budget");

        assert!(
            matches!(
                error,
                SignatureVerificationPipelineError::Policy(
                    crate::policy::PolicyViolation::ResourceLimit {
                        resource: crate::policy::resource_name::CANONICALIZED_BYTES,
                        maximum: 64,
                        ..
                    }
                )
            ),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn verification_policy_bounds_document_bytes_before_parsing() {
        // A small node count does not bound parser work when one text node is
        // large, so the byte ceiling must reject before structural inspection.
        let xml = format!("<root>{}</root>", "x".repeat(1_024));
        let policy = crate::policy::VerificationPolicy {
            resources: crate::policy::ResourcePolicy {
                max_xml_document_bytes: xml.len() - 1,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::VerificationPolicy::default()
        };

        assert!(matches!(
            VerifyContext::new().policy(policy).verify(&xml),
            Err(SignatureVerificationPipelineError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_DOCUMENT,
                    maximum,
                    actual,
                }
            )) if maximum == xml.len() - 1 && actual == xml.len()
        ));
    }

    #[test]
    fn verification_policy_bounds_base64_transform_input() {
        // The operation snapshot must reach the transform executor rather than
        // silently falling back to its implementation-wide default budget.
        let digest = base64::engine::general_purpose::STANDARD.encode([0_u8; 32]);
        let xml = format!(
            r##"<root xmlns:ds="{XMLDSIG_NS}"><payload ID="payload">QUJDRA==</payload><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#payload"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#base64"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AQ==</ds:SignatureValue></ds:Signature></root>"##
        );
        let policy = crate::policy::VerificationPolicy {
            resources: crate::policy::ResourcePolicy {
                max_base64_transform_input_bytes: 4,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::VerificationPolicy::default()
        };

        let error = VerifyContext::new()
            .key(&AcceptingKey)
            .policy(policy)
            .verify(&xml)
            .expect_err("Base64 input must use the operation policy ceiling");

        assert!(matches!(
            error,
            SignatureVerificationPipelineError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::BASE64_TRANSFORM_INPUT_BYTES,
                    maximum: 4,
                    ..
                }
            )
        ));
    }

    #[test]
    fn verification_policy_bounds_xpath_source_before_compilation() {
        // XPath parser limits are part of the same operation snapshot as the
        // evaluator limits; parsing cannot use a separate hard-coded budget.
        let digest = base64::engine::general_purpose::STANDARD.encode([0_u8; 32]);
        let xml = format!(
            r#"<root xmlns:ds="{XMLDSIG_NS}"><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>true()</ds:XPath></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AQ==</ds:SignatureValue></ds:Signature></root>"#
        );
        let policy = crate::policy::VerificationPolicy {
            resources: crate::policy::ResourcePolicy {
                max_xpath_expression_bytes: 4,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::VerificationPolicy::default()
        };

        let error = VerifyContext::new()
            .key(&AcceptingKey)
            .policy(policy)
            .verify(&xml)
            .expect_err("XPath source must use the operation policy ceiling");

        assert!(matches!(
            error,
            SignatureVerificationPipelineError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XPATH_EXPRESSION_BYTES,
                    maximum: 4,
                    ..
                }
            )
        ));
    }

    #[test]
    fn verification_policy_shares_canonicalization_budget_with_signed_info() {
        // Reference transforms and SignedInfo canonicalization are one operation.
        // Each output fits independently, but their aggregate must not receive
        // two separate copies of the configured canonicalization allowance.
        let payload_text = "x".repeat(700);
        let canonical_payload = format!("<payload ID=\"payload\">{payload_text}</payload>");
        let digest = base64::engine::general_purpose::STANDARD.encode(compute_digest(
            DigestAlgorithm::Sha256,
            canonical_payload.as_bytes(),
        ));
        let xml = format!(
            r##"<root xmlns:ds="{XMLDSIG_NS}">{canonical_payload}<ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#payload"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AQ==</ds:SignatureValue></ds:Signature></root>"##
        );
        let policy = crate::policy::VerificationPolicy {
            resources: crate::policy::ResourcePolicy {
                max_canonicalized_bytes: 1_024,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::VerificationPolicy::default()
        };

        let error = VerifyContext::new()
            .key(&AcceptingKey)
            .policy(policy)
            .verify(&xml)
            .expect_err("SignedInfo must consume the remaining operation C14N budget");

        assert!(
            matches!(
                &error,
                SignatureVerificationPipelineError::Policy(
                    crate::policy::PolicyViolation::ResourceLimit {
                        resource: "canonicalized bytes",
                        maximum: 1_024,
                        ..
                    }
                )
            ),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn manifest_processing_stops_after_c14n_budget_exhaustion() {
        // A failed bounded render consumes the remaining operation allowance.
        // Later Manifest references, including cheap binary ones, must not run.
        let digest = base64::engine::general_purpose::STANDARD.encode([0_u8; 32]);
        let xml = format!(
            r##"<root xmlns:ds="{XMLDSIG_NS}"><payload Id="payload">too large</payload><ds:Signature><ds:Object Id="signed-object"><ds:Manifest><ds:Reference URI="#payload"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference><ds:Reference URI="urn:small"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:Manifest></ds:Object></ds:Signature></root>"##
        );
        let document = Document::parse(&xml).expect("test signature must parse");
        let signature = document
            .descendants()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "Signature")))
            .expect("test signature must contain Signature");
        let object = signature
            .children()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "Object")))
            .expect("test signature must contain Object");
        let resources = HashMap::from([("urn:small".to_owned(), b"small".to_vec())]);
        let resolver = UriReferenceResolver::new(&document).with_external_resources(&resources);
        let transform_budget = TransformExecutionBudget::with_c14n_limit(8);
        let canonicalized_data_budget = CanonicalizedDataBudget::default();
        let execution = ReferenceExecutionContext {
            store_pre_digest: false,
            transform_options: TransformOptions::default(),
            transform_budget: &transform_budget,
            canonicalized_data_budget: &canonicalized_data_budget,
            provider: crate::provider::default_provider(),
        };
        let ctx = VerifyContext::new()
            .allowed_uri_types(UriTypeSet::ALL)
            .external_resources(&resources);
        let authenticated = HashSet::from([object.id()]);
        let mut xpath_budget = XPathSignatureParseBudget::default();

        let results = process_manifest_references(
            signature,
            &resolver,
            &ctx,
            &authenticated,
            2,
            &execution,
            &mut xpath_budget,
        )
        .expect("resource exhaustion is reported per Manifest reference");

        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|result| {
            matches!(
                result.status,
                DsigStatus::Invalid(FailureReason::ReferenceProcessingFailure { .. })
            )
        }));
    }

    #[test]
    fn verification_policy_bounds_detached_xml_nodes() {
        // Caller-owned detached octets become a second XML document during a
        // node-set transform and must inherit the same operation node ceiling.
        let detached = format!("<payload>{}</payload>", "<n/>".repeat(32));
        let digest = base64::engine::general_purpose::STANDARD.encode([0_u8; 32]);
        let xml = format!(
            r#"<root xmlns:ds="{XMLDSIG_NS}"><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="urn:detached-nodes"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>true()</ds:XPath></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AQ==</ds:SignatureValue></ds:Signature></root>"#
        );
        let resources = HashMap::from([("urn:detached-nodes".to_owned(), detached.into_bytes())]);
        let policy = crate::policy::VerificationPolicy {
            uris: crate::policy::UriPolicy {
                references: UriTypeSet::ALL,
                ..crate::policy::UriPolicy::default()
            },
            resources: crate::policy::ResourcePolicy {
                max_xml_nodes: 24,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::VerificationPolicy::default()
        };

        let error = VerifyContext::new()
            .key(&AcceptingKey)
            .policy(policy)
            .external_resources(&resources)
            .verify(&xml)
            .expect_err("detached XML must inherit the policy node ceiling");

        assert!(
            matches!(
                error,
                SignatureVerificationPipelineError::Policy(
                    crate::policy::PolicyViolation::ResourceLimit {
                        resource: crate::policy::resource_name::XML_NODES,
                        maximum: 24,
                        ..
                    }
                )
            ),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn query_only_reference_resolves_against_relative_xml_base() {
        // A query-only URI replaces the inherited base query without changing
        // its relative path; no absolute document base is required by XML Base.
        let payload = b"query-selected payload";
        let digest = base64::engine::general_purpose::STANDARD
            .encode(compute_digest(DigestAlgorithm::Sha256, payload));
        let xml = format!(
            r#"<ds:Signature xmlns:ds="{XMLDSIG_NS}"><ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference xml:base="a/b?old" URI="?new">
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue>{digest}</ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo><ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature>"#
        );
        let document = Document::parse(&xml).unwrap();
        let signature = document.root_element();
        let signed_info_node = signature
            .children()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "SignedInfo")))
            .unwrap();
        let signed_info = parse_signed_info(signed_info_node).unwrap();
        let resources = HashMap::from([("a/b?new".to_string(), payload.to_vec())]);
        let resolver = UriReferenceResolver::new(&document).with_external_resources(&resources);

        let result = process_all_references(&signed_info.references, &resolver, signature, false)
            .expect("query-only URI must resolve against the complete relative base path");

        assert!(result.all_valid());
    }

    #[test]
    fn manifest_reference_resolution_uses_its_effective_xml_base() {
        // Manifest references carry their own XML Base context and must not
        // accidentally reuse the SignedInfo or Signature element context.
        let payload = b"manifest payload";
        let digest = base64::engine::general_purpose::STANDARD
            .encode(compute_digest(DigestAlgorithm::Sha256, payload));
        let xml = format!(
            r#"<ds:Signature xmlns:ds="{XMLDSIG_NS}" xml:base="https://example.test/">
                <ds:Object><ds:Manifest xml:base="manifests/">
                    <ds:Reference URI="payload.bin">
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>{digest}</ds:DigestValue>
                    </ds:Reference>
                </ds:Manifest></ds:Object>
            </ds:Signature>"#
        );
        let document = Document::parse(&xml).unwrap();
        let signature = document.root_element();
        let reference_node = signature
            .descendants()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "Reference")))
            .unwrap();
        let reference = super::super::parse::parse_reference(reference_node).unwrap();
        let resources = HashMap::from([(
            "https://example.test/manifests/payload.bin".to_string(),
            payload.to_vec(),
        )]);
        let resolver = UriReferenceResolver::new(&document).with_external_resources(&resources);

        let result = process_reference(
            &reference,
            &resolver,
            signature,
            ReferenceSet::Manifest,
            0,
            false,
        )
        .expect("Manifest Reference should inherit its own XML Base context");

        assert_eq!(result.status, DsigStatus::Valid);
    }

    #[test]
    fn manifest_reference_index_ignores_nested_manifest_descendants() {
        // The public Manifest index follows Signature/Object/Manifest structure;
        // wrapper descendants must not steal an index and supply another base URI.
        let payload = b"direct manifest payload";
        let digest = base64::engine::general_purpose::STANDARD
            .encode(compute_digest(DigestAlgorithm::Sha256, payload));
        let xml = format!(
            r#"<ds:Signature xmlns:ds="{XMLDSIG_NS}" xml:base="https://example.test/">
                <ds:Object><wrapper><ds:Manifest xml:base="nested/">
                    <ds:Reference URI="payload.bin">
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>{digest}</ds:DigestValue>
                    </ds:Reference>
                </ds:Manifest></wrapper></ds:Object>
                <ds:Object><ds:Manifest xml:base="direct/">
                    <ds:Reference URI="payload.bin">
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>{digest}</ds:DigestValue>
                    </ds:Reference>
                </ds:Manifest></ds:Object>
            </ds:Signature>"#
        );
        let document = Document::parse(&xml).unwrap();
        let signature = document.root_element();
        let direct_reference_node = signature
            .children()
            .filter(|node| node.has_tag_name((XMLDSIG_NS, "Object")))
            .nth(1)
            .unwrap()
            .children()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "Manifest")))
            .unwrap()
            .children()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "Reference")))
            .unwrap();
        let reference = super::super::parse::parse_reference(direct_reference_node).unwrap();
        let resources = HashMap::from([(
            "https://example.test/direct/payload.bin".to_string(),
            payload.to_vec(),
        )]);
        let resolver = UriReferenceResolver::new(&document).with_external_resources(&resources);

        let result = process_reference(
            &reference,
            &resolver,
            signature,
            ReferenceSet::Manifest,
            0,
            false,
        )
        .expect("Manifest index must select the direct Object/Manifest reference");

        assert_eq!(result.status, DsigStatus::Valid);
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
            _key_info: Option<&KeyInfo>,
            _algorithm: SignatureAlgorithm,
        ) -> Result<Option<Box<dyn VerifyingKey + 'a>>, SignatureVerificationPipelineError>
        {
            panic!("resolver should not be called when references already fail");
        }
    }

    struct MissingKeyResolver;

    impl KeyResolver for MissingKeyResolver {
        fn resolve<'a>(
            &'a self,
            _key_info: Option<&KeyInfo>,
            _algorithm: SignatureAlgorithm,
        ) -> Result<Option<Box<dyn VerifyingKey + 'a>>, SignatureVerificationPipelineError>
        {
            Ok(None)
        }
    }

    struct ConsumingKeyInfoResolver;

    impl KeyResolver for ConsumingKeyInfoResolver {
        fn resolve<'a>(
            &'a self,
            _key_info: Option<&KeyInfo>,
            _algorithm: SignatureAlgorithm,
        ) -> Result<Option<Box<dyn VerifyingKey + 'a>>, SignatureVerificationPipelineError>
        {
            Ok(None)
        }

        fn consumes_document_key_info(&self) -> bool {
            true
        }
    }

    struct FallbackKeyInfoResolver;

    impl KeyResolver for FallbackKeyInfoResolver {
        fn resolve<'a>(
            &'a self,
            key_info: Option<&KeyInfo>,
            _algorithm: SignatureAlgorithm,
        ) -> Result<Option<Box<dyn VerifyingKey + 'a>>, SignatureVerificationPipelineError>
        {
            let sources = &key_info.expect("KeyInfo must be parsed").sources;
            assert!(matches!(
                sources.as_slice(),
                [
                    super::super::parse::KeyInfoSource::RetrievalMethod { .. },
                    super::super::parse::KeyInfoSource::KeyName(name),
                ] if name == "fallback"
            ));
            Ok(Some(Box::new(AcceptingKey)))
        }

        fn consumes_document_key_info(&self) -> bool {
            true
        }
    }

    struct EarlyKeyInfoResolver;

    impl KeyResolver for EarlyKeyInfoResolver {
        fn resolve<'a>(
            &'a self,
            key_info: Option<&KeyInfo>,
            _algorithm: SignatureAlgorithm,
        ) -> Result<Option<Box<dyn VerifyingKey + 'a>>, SignatureVerificationPipelineError>
        {
            let sources = &key_info.expect("KeyInfo must be parsed").sources;
            assert!(matches!(
                sources.as_slice(),
                [
                    super::super::parse::KeyInfoSource::KeyName(name),
                    super::super::parse::KeyInfoSource::RetrievalMethod { .. },
                ] if name == "primary"
            ));
            Ok(Some(Box::new(AcceptingKey)))
        }

        fn consumes_document_key_info(&self) -> bool {
            true
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
            SignatureVerificationPipelineError::Policy(crate::policy::PolicyViolation::Uri {
                operation: "verification",
                ..
            })
        ));
    }

    #[test]
    fn verify_context_bounds_effective_xml_base_components() {
        // External URI resolution must stop before repeatedly copying an
        // attacker-controlled chain of effective XML Base values.
        let mut xml = minimal_signature_xml("payload", "");
        for _ in 0..65 {
            xml = format!(r#"<n xml:base="segment/">{xml}</n>"#);
        }
        let resources = HashMap::new();
        let error = VerifyContext::new()
            .key(&AcceptingKey)
            .allowed_uri_types(UriTypeSet::ALL)
            .external_resources(&resources)
            .verify(&xml)
            .expect_err("XML Base component work must be bounded before lookup");

        assert!(matches!(
            error,
            SignatureVerificationPipelineError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_BASE_COMPONENTS,
                    maximum: 64,
                    actual: 65,
                }
            )
        ));
    }

    #[test]
    fn verify_context_bounds_cumulative_xml_base_resolution_bytes() {
        // The operation-wide byte budget charges intermediate URI copies, not
        // merely the small final external resource returned by the caller map.
        let mut xml = minimal_signature_xml("payload", "");
        for _ in 0..2 {
            xml = format!(r#"<n xml:base="segment/">{xml}</n>"#);
        }
        let resources = HashMap::new();
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.resources.max_xml_base_resolution_bytes = 32;
        let error = VerifyContext::new()
            .policy(policy)
            .key(&AcceptingKey)
            .allowed_uri_types(UriTypeSet::ALL)
            .external_resources(&resources)
            .verify(&xml)
            .expect_err("cumulative XML Base copies must obey the operation budget");

        assert!(matches!(
            error,
            SignatureVerificationPipelineError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_BASE_RESOLUTION_BYTES,
                    maximum: 32,
                    ..
                }
            )
        ));
    }

    #[test]
    fn verify_context_applies_xml_base_policy_to_signed_info_c14n() {
        // The SignedInfo node-set excludes its ancestors, so C14N 1.1 must
        // resolve their inherited xml:base values through the same operation
        // budget already used by Reference processing.
        let xml = signature_with_target_reference("AQ==")
            .replacen(
                "http://www.w3.org/2001/10/xml-exc-c14n#",
                "http://www.w3.org/2006/12/xml-c14n11",
                1,
            )
            .replace(
                "  <ds:Signature>",
                "  <outer xml:base=\"one/\"><inner xml:base=\"two/\"><ds:Signature>",
            )
            .replace("  </ds:Signature>", "  </ds:Signature></inner></outer>");
        let policy = crate::policy::VerificationPolicy {
            resources: crate::policy::ResourcePolicy {
                max_xml_base_components: 1,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::VerificationPolicy::default()
        };

        let error = VerifyContext::new()
            .key(&AcceptingKey)
            .policy(policy)
            .verify(&xml)
            .expect_err("SignedInfo C14N must use the operation XML Base budget");

        assert!(matches!(
            error,
            SignatureVerificationPipelineError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_BASE_COMPONENTS,
                    maximum: 1,
                    actual: 2,
                }
            )
        ));
    }

    #[test]
    fn verify_context_classifies_signed_info_xml_base_byte_limit_as_policy() {
        // SignedInfo C14N 1.1 XML Base work is policy enforcement, not a
        // malformed canonicalization request, and must retain typed diagnostics.
        let xml = signature_with_target_reference("AQ==")
            .replacen(
                "http://www.w3.org/2001/10/xml-exc-c14n#",
                "http://www.w3.org/2006/12/xml-c14n11",
                1,
            )
            .replace(
                "  <ds:Signature>",
                "  <outer xml:base=\"segment/\"><ds:Signature>",
            )
            .replace("  </ds:Signature>", "  </ds:Signature></outer>");
        let policy = crate::policy::VerificationPolicy {
            resources: crate::policy::ResourcePolicy {
                max_xml_base_resolution_bytes: 1,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::VerificationPolicy::default()
        };

        let error = VerifyContext::new()
            .key(&AcceptingKey)
            .policy(policy)
            .verify(&xml)
            .expect_err("SignedInfo XML Base byte exhaustion must be a policy error");

        assert!(matches!(
            error,
            SignatureVerificationPipelineError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_BASE_RESOLUTION_BYTES,
                    maximum: 1,
                    actual,
                }
            ) if actual > 1
        ));
    }

    #[test]
    fn verify_context_meters_repeated_external_dereferences() {
        // One caller-owned entry can be referenced repeatedly. The aggregate
        // ceiling bounds bytes cloned and processed, not just unique map data.
        let payload = b"payload";
        let digest = base64::engine::general_purpose::STANDARD.encode(
            crate::xmldsig::compute_digest(DigestAlgorithm::Sha1, payload),
        );
        let reference = format!(
            r#"<ds:Reference URI="urn:payload"><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference>"#
        );
        let xml = format!(
            r#"<ds:Signature xmlns:ds="{XMLDSIG_NS}"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>{reference}{reference}</ds:SignedInfo><ds:SignatureValue>AQ==</ds:SignatureValue></ds:Signature>"#
        );
        let resources = HashMap::from([("urn:payload".to_owned(), payload.to_vec())]);
        let policy = crate::policy::VerificationPolicy {
            uris: crate::policy::UriPolicy {
                references: UriTypeSet::ALL,
                ..crate::policy::UriPolicy::default()
            },
            resources: crate::policy::ResourcePolicy {
                max_external_resource_bytes: payload.len(),
                max_external_resource_total_bytes: payload.len(),
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::VerificationPolicy::default()
        };

        let error = VerifyContext::new()
            .key(&AcceptingKey)
            .policy(policy)
            .external_resources(&resources)
            .verify(&xml)
            .expect_err("the second dereference must exhaust the aggregate byte ceiling");

        assert!(
            error
                .to_string()
                .contains("aggregate external resource bytes")
        );
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
            SignatureVerificationPipelineError::Policy(crate::policy::PolicyViolation::Uri {
                operation: "verification",
                ..
            })
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
            SignatureVerificationPipelineError::Policy(crate::policy::PolicyViolation::Algorithm {
                operation: "verification transform",
                ..
            })
        ));
    }

    #[test]
    fn verify_context_applies_transform_allowlist_to_signed_info_c14n() {
        // Reference C14N remains allowlisted; only the distinct SignedInfo
        // canonicalization method should trigger this policy rejection.
        let xml = signature_with_target_reference("AQ==").replacen(
            "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
            "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>",
            1,
        );
        let error = VerifyContext::new()
            .key(&AcceptingKey)
            .allowed_transforms(["http://www.w3.org/2001/10/xml-exc-c14n#"])
            .verify(&xml)
            .expect_err("SignedInfo C14N must obey the operation transform allowlist");

        assert!(matches!(
            error,
            SignatureVerificationPipelineError::Policy(
                crate::policy::PolicyViolation::Algorithm {
                    operation: "verification transform",
                    ref algorithm,
                }
            )
                if algorithm == "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
        ));
    }

    #[test]
    fn verify_context_applies_transform_allowlist_to_key_retrieval() {
        // The reference and SignedInfo both use exclusive C14N. The only XPath
        // operation is document-selected key retrieval and must be rejected.
        let xml = signature_with_target_reference("AQ==")
            .replacen(
                "</ds:Signature>",
                r##"<ds:KeyInfo><ds:RetrievalMethod URI="#keys" Type="http://www.w3.org/2000/09/xmldsig#X509Data"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>ancestor-or-self::ds:X509Data</ds:XPath></ds:Transform></ds:Transforms></ds:RetrievalMethod></ds:KeyInfo></ds:Signature>"##,
                1,
            )
            .replacen(
                "</root>",
                r#"<holder ID="keys"><ds:X509Data><ds:X509SubjectName>CN=leaf</ds:X509SubjectName></ds:X509Data></holder></root>"#,
                1,
            );
        let error = VerifyContext::new()
            .key_resolver(&ConsumingKeyInfoResolver)
            .allowed_transforms(["http://www.w3.org/2001/10/xml-exc-c14n#"])
            .verify(&xml)
            .expect_err("RetrievalMethod XPath must obey the operation transform allowlist");

        assert!(matches!(
            error,
            SignatureVerificationPipelineError::Policy(
                crate::policy::PolicyViolation::Algorithm {
                    operation: "verification transform",
                    ref algorithm,
                }
            )
                if algorithm == XPATH_TRANSFORM_URI
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

    fn replace_fixture_manifest_digest(xml: &str, replacement: &str) -> String {
        let object_marker = "<ds:Object>";
        let object_start = xml
            .find(object_marker)
            .expect("fixture should contain ds:Object")
            + object_marker.len();
        let open = "<ds:DigestValue>";
        let close = "</ds:DigestValue>";
        let value_start = xml[object_start..]
            .find(open)
            .map(|offset| object_start + offset + open.len())
            .expect("Manifest should contain DigestValue");
        let value_end = xml[value_start..]
            .find(close)
            .map(|offset| value_start + offset)
            .expect("Manifest DigestValue must be closed");

        format!("{}{replacement}{}", &xml[..value_start], &xml[value_end..])
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
            .key(&AcceptingKey)
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
        assert!(matches!(result_with_manifests.status, DsigStatus::Valid));
    }

    #[test]
    fn verify_context_skips_manifest_work_when_signature_value_is_invalid() {
        // SignedInfo authenticates the Manifest bytes only after SignatureValue
        // succeeds. Malformed nested content must not consume parsing work when
        // the cryptographic signature itself is invalid.
        let xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
            replace_fixture_manifest_digest(&xml, "!!!")
        });
        assert!(
            xml.split_once("<ds:Object>")
                .is_some_and(|(_, object)| object.contains("<ds:DigestValue>!!!</ds:DigestValue>")),
            "fixture mutation must corrupt the nested Manifest DigestValue",
        );

        let result = VerifyContext::new()
            .key(&RejectingKey)
            .process_manifests(true)
            .verify(&xml)
            .expect("invalid SignatureValue must short-circuit Manifest parsing");

        assert!(matches!(
            result.status,
            DsigStatus::Invalid(FailureReason::SignatureMismatch)
        ));
        assert!(result.manifest_references.is_empty());
    }

    #[test]
    fn verify_context_shares_xpath_parse_budget_with_manifest_references() {
        // SignedInfo and every Manifest form one attacker-controlled parse unit:
        // splitting expressions across Reference sets must not reset the ceiling.
        let filters = r#"<XPath xmlns="http://www.w3.org/2002/06/xmldsig-filter2" Filter="intersect">true()</XPath>"#
            .repeat(64);
        let transform = format!(
            r#"<ds:Transform Algorithm="http://www.w3.org/2002/06/xmldsig-filter2">{filters}</ds:Transform>"#
        );
        let max_transforms = transform.repeat(16);
        let max_manifest_reference = format!(
            r##"<ds:Reference URI="#target"><ds:Transforms>{max_transforms}</ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue></ds:Reference>"##
        );
        let xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
            xml.replacen(
                r##"<ds:Reference URI="#target">"##,
                &format!(
                    r##"<ds:Reference URI="#target"><ds:Transforms>{}</ds:Transforms>"##,
                    max_transforms
                ),
                1,
            )
            .replacen(
                "</ds:SignedInfo>",
                r##"<ds:Reference URI="#target"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>false()</ds:XPath></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>2jmj7l5rSw0yVb/vlWAYkK/YBwk=</ds:DigestValue></ds:Reference></ds:SignedInfo>"##,
                1,
            )
            .replacen(
                "</ds:Manifest>",
                &format!("{}</ds:Manifest>", max_manifest_reference.repeat(3)),
                1,
            )
        });

        let error = VerifyContext::new()
            .key(&AcceptingKey)
            .process_manifests(true)
            .verify(&xml)
            .expect_err("SignedInfo and Manifest References must share one XPath parse budget");

        assert!(
            matches!(
                &error,
                SignatureVerificationPipelineError::Policy(
                    crate::policy::PolicyViolation::ResourceLimit {
                        resource: "XPath expressions",
                        ..
                    }
                )
            ),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn verify_context_processes_manifest_when_signedinfo_references_object() {
        let xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
            xml.replacen("URI=\"#manifest\"", "URI=\"#object-id\"", 1)
                .replacen("<ds:Object>", "<ds:Object ID=\"object-id\">", 1)
                .replacen("<ds:Manifest ID=\"manifest\">", "<ds:Manifest>", 1)
        });

        let result = VerifyContext::new()
            .key(&AcceptingKey)
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
    fn verify_context_skips_manifest_removed_by_enveloped_transform() {
        // The owning Signature contains both eligible ID targets. Subtracting
        // its subtree therefore removes every target node from the digest input,
        // so neither form authenticates the Manifest structure for processing.
        for target_object in [false, true] {
            let xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
                let xml = xml.replacen(
                    r#"<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
                    r#"<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
                    1,
                );
                if target_object {
                    xml.replacen("URI=\"#manifest\"", "URI=\"#object-id\"", 1)
                        .replacen("<ds:Object>", "<ds:Object ID=\"object-id\">", 1)
                        .replacen("<ds:Manifest ID=\"manifest\">", "<ds:Manifest>", 1)
                } else {
                    xml
                }
            });

            let result = VerifyContext::new()
                .key(&AcceptingKey)
                .process_manifests(true)
                .store_pre_digest(true)
                .verify(&xml)
                .expect("an emptied reference remains a valid core digest input");

            assert!(matches!(result.status, DsigStatus::Valid));
            assert_eq!(
                result.signed_info_references[0].pre_digest_data.as_deref(),
                Some([].as_slice()),
                "target_object={target_object} must have empty transformed bytes",
            );
            assert!(
                result.manifest_references.is_empty(),
                "target_object={target_object} must not authenticate the Manifest",
            );
        }
    }

    #[test]
    fn verify_context_ignores_manifest_excluded_from_signed_object() {
        // A Reference URI authenticates only its post-transform bytes. Excluding
        // the Manifest subtree must not let its independently valid digest chain
        // masquerade as data authenticated by SignedInfo.
        let xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
            xml.replacen("URI=\"#manifest\"", "URI=\"#object-id\"", 1)
                .replacen("<ds:Object>", "<ds:Object ID=\"object-id\">", 1)
                .replacen("<ds:Manifest ID=\"manifest\">", "<ds:Manifest>", 1)
                .replacen(
                    r#"<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
                    r#"<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>not(ancestor-or-self::ds:Manifest)</ds:XPath></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
                    1,
                )
        });

        let result = VerifyContext::new()
            .key(&AcceptingKey)
            .process_manifests(true)
            .verify(&xml)
            .expect("excluded Manifest content must be ignored, not parsed");

        assert!(matches!(result.status, DsigStatus::Valid));
        assert!(
            result.manifest_references.is_empty(),
            "a transform-excluded Manifest is not authenticated by SignedInfo",
        );
    }

    #[test]
    fn verify_context_skips_manifest_digest_work_when_signature_is_invalid() {
        let xml = signature_with_manifest_xml(false);
        let result = VerifyContext::new()
            .key(&RejectingKey)
            .process_manifests(true)
            .verify(&xml)
            .expect("invalid SignatureValue must short-circuit Manifest digest work");
        assert!(result.manifest_references.is_empty());
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
    fn verify_context_skips_manifest_parsing_when_signedinfo_reference_fails() {
        // Manifest content is not authenticated after a SignedInfo reference
        // failure, so parsing it would spend work on untrusted nested input.
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
            .expect("SignedInfo digest failure should return without parsing Manifests");
        assert!(matches!(
            result.status,
            DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { ref_index: 0 })
        ));
        assert!(
            result.manifest_references.is_empty(),
            "unauthenticated Manifest content must not be parsed",
        );
    }

    #[test]
    fn verify_context_skips_manifest_policy_work_when_signature_is_invalid() {
        // A digest-valid SignedInfo reference does not authenticate Manifest
        // policy inputs until SignatureValue also succeeds.
        let broken_xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
            xml.replacen("URI=\"#target\"", "URI=\"http://example.com/external\"", 1)
        });
        let result = VerifyContext::new()
            .key(&RejectingKey)
            .process_manifests(true)
            .verify(&broken_xml)
            .expect("invalid SignatureValue must short-circuit Manifest policy work");
        assert!(result.manifest_references.is_empty());
        assert!(matches!(
            result.status,
            DsigStatus::Invalid(FailureReason::SignatureMismatch)
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
    fn verify_context_applies_digest_policy_to_manifest_references() {
        // Manifest results are authenticated extension data and must obey the
        // same digest allowlist as SignedInfo references.
        let policy = crate::policy::VerificationPolicy {
            manifest_processing: crate::policy::ManifestProcessing::Process,
            digest_algorithms: Some(HashSet::from([DigestAlgorithm::Sha1])),
            ..crate::policy::VerificationPolicy::default()
        };
        let xml = signature_with_manifest_xml_with_manifest_mutation(true, |mut xml| {
            let legacy = "http://www.w3.org/2000/09/xmldsig#sha1";
            let offset = xml
                .rfind(legacy)
                .expect("Manifest DigestMethod must be present");
            xml.replace_range(offset..offset + legacy.len(), DigestAlgorithm::Sha256.uri());
            let value_start = xml[offset..]
                .find("<ds:DigestValue>")
                .map(|relative| offset + relative + "<ds:DigestValue>".len())
                .expect("Manifest DigestValue must be present");
            let value_end = xml[value_start..]
                .find("</ds:DigestValue>")
                .map(|relative| value_start + relative)
                .expect("Manifest DigestValue must be closed");
            xml.replace_range(
                value_start..value_end,
                &base64::engine::general_purpose::STANDARD.encode([0_u8; 32]),
            );
            xml
        });
        let result = VerifyContext::new()
            .key(&AcceptingKey)
            .policy(policy)
            .verify(&xml)
            .expect("a disallowed Manifest digest is a per-reference result");

        assert!(matches!(result.status, DsigStatus::Valid));
        assert!(matches!(
            result.manifest_references[0].status,
            DsigStatus::Invalid(FailureReason::ReferencePolicyViolation { ref_index: 0 })
        ));
    }

    #[test]
    fn verify_context_applies_transform_count_policy_to_manifest_references() {
        // Authenticated Manifest references share the caller's per-reference
        // transform ceiling and fail before transform execution when exceeded.
        let policy = crate::policy::VerificationPolicy {
            manifest_processing: crate::policy::ManifestProcessing::Process,
            resources: crate::policy::ResourcePolicy {
                max_transforms_per_reference: 1,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::VerificationPolicy::default()
        };
        let xml = signature_with_manifest_xml_with_manifest_mutation(true, |mut xml| {
            let manifest_start = xml
                .find("<ds:Manifest")
                .expect("fixture must contain a Manifest");
            let manifest = xml[manifest_start..].replacen(
                "<ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>",
                concat!(
                    "<ds:Transforms>",
                    "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
                    "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
                    "</ds:Transforms>",
                    "<ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>"
                ),
                1,
            );
            xml.replace_range(manifest_start.., &manifest);
            xml
        });
        let result = VerifyContext::new()
            .key(&AcceptingKey)
            .policy(policy)
            .verify(&xml)
            .expect("Manifest transform policy is a per-reference result");

        assert!(matches!(result.status, DsigStatus::Valid));
        assert!(matches!(
            result.manifest_references[0].status,
            DsigStatus::Invalid(FailureReason::ReferencePolicyViolation { ref_index: 0 })
        ));
    }

    #[test]
    fn verify_context_skips_manifest_uri_work_when_signature_is_invalid() {
        // Missing Manifest URIs remain unauthenticated until SignatureValue
        // succeeds, so they cannot trigger Manifest policy processing here.
        let broken_xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
            xml.replacen("<ds:Reference URI=\"#target\">", "<ds:Reference>", 1)
        });

        let result = VerifyContext::new()
            .key(&RejectingKey)
            .process_manifests(true)
            .verify(&broken_xml)
            .expect("invalid SignatureValue must short-circuit Manifest URI processing");
        assert!(result.manifest_references.is_empty());
        assert!(matches!(
            result.status,
            DsigStatus::Invalid(FailureReason::SignatureMismatch)
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
        // A digest-valid Manifest below a wrapper is outside the strict direct-
        // child processing profile and must not appear in diagnostics.
        let xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
            xml.replacen(
                "<ds:Manifest ID=\"manifest\">",
                "<wrapper><ds:Manifest ID=\"manifest\">",
                1,
            )
            .replacen("</ds:Manifest>", "</ds:Manifest></wrapper>", 1)
        });

        let result = VerifyContext::new()
            .key(&AcceptingKey)
            .process_manifests(true)
            .verify(&xml)
            .expect("nested Manifest nodes are ignored in strict mode");
        assert!(
            result.manifest_references.is_empty(),
            "only direct ds:Manifest children of ds:Object must be processed"
        );
        assert!(matches!(result.status, DsigStatus::Valid));
    }

    #[test]
    fn verify_context_reports_manifest_reference_parse_errors_explicitly() {
        // Malformed nested DigestValue is parsed only after the enclosing
        // Manifest structure has been authenticated by SignedInfo.
        let broken_xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
            replace_fixture_manifest_digest(&xml, "!!!")
        });

        let err = VerifyContext::new()
            .key(&AcceptingKey)
            .process_manifests(true)
            .verify(&broken_xml)
            .expect_err("invalid Manifest DigestValue must map to ParseManifestReference");
        assert!(matches!(
            err,
            SignatureVerificationPipelineError::ParseManifestReference(_)
        ));
    }

    #[test]
    fn verify_context_reports_unsupported_manifest_transform_with_declared_digest() {
        // Unsupported optional Manifest transforms do not invalidate core
        // SignedInfo, but their result must preserve the declared digest method.
        let xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
            let xml = xml.replacen(
                "<ds:Reference URI=\"#target\">",
                "<ds:Reference URI=\"#target\"><ds:Transforms><ds:Transform Algorithm=\"urn:unsupported\"/></ds:Transforms>",
                1,
            );
            let xml = xml.replacen(
                "</ds:Transforms>\n          <ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>",
                "</ds:Transforms>\n          <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>",
                1,
            );
            replace_fixture_manifest_digest(&xml, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        });
        assert!(xml.contains("urn:unsupported"));
        assert!(xml.contains("http://www.w3.org/2001/04/xmlenc#sha256"));

        let result = VerifyContext::new()
            .key(&AcceptingKey)
            .process_manifests(true)
            .verify(&xml)
            .expect("unsupported Manifest transform is a per-reference result");
        assert_eq!(result.status, DsigStatus::Valid);
        assert_eq!(result.manifest_references.len(), 1);
        assert_eq!(
            result.manifest_references[0].digest_algorithm,
            DigestAlgorithm::Sha256
        );
        assert!(matches!(
            result.manifest_references[0].status,
            DsigStatus::Invalid(FailureReason::ReferenceProcessingFailure { ref_index: 0 })
        ));
    }

    #[test]
    fn manifest_reference_limit_counts_unsupported_entries() {
        let references = (0..=MAX_REFERENCES_PER_SIGNATURE)
            .map(|index| {
                format!(
                    r##"<ds:Reference URI="#target-{index}"><ds:Transforms><ds:Transform Algorithm="urn:unsupported"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue></ds:Reference>"##
                )
            })
            .collect::<String>();
        let xml = format!(
            r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Object Id="signed"><ds:Manifest>{references}</ds:Manifest></ds:Object></ds:Signature>"#
        );
        let document = Document::parse(&xml).unwrap();
        let signature = document.root_element();
        let object = signature.children().find(|node| node.is_element()).unwrap();
        let authenticated = HashSet::from([object.id()]);
        let mut processed = HashSet::new();
        let mut remaining = MAX_REFERENCES_PER_SIGNATURE;
        let mut next_index = 0;

        let error = match parse_manifest_references(
            signature,
            &authenticated,
            &mut processed,
            &mut remaining,
            &mut next_index,
            &mut XPathSignatureParseBudget::default(),
        ) {
            Ok(_) => panic!("unsupported references must consume the same aggregate limit"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            SignatureVerificationPipelineError::InvalidStructure {
                reason: "signed Manifests exceed the per-signature Reference limit"
            }
        ));
    }

    #[test]
    fn unsigned_manifest_remains_eligible_after_trust_expands() {
        // The second Object is not authenticated during the first discovery
        // pass. It must remain unprocessed so a valid reference from the first
        // Manifest can make its sibling Manifest eligible on the next pass.
        let digest = base64::engine::general_purpose::STANDARD.encode([0_u8; 32]);
        let xml = format!(
            r##"<ds:Signature xmlns:ds="{XMLDSIG_NS}"><ds:Object Id="outer"><ds:Manifest><ds:Reference URI="#inner"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:Manifest></ds:Object><ds:Object Id="inner"><ds:Manifest><ds:Reference URI="#payload"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:Manifest></ds:Object></ds:Signature>"##
        );
        let document = Document::parse(&xml).expect("nested Manifest fixture must parse");
        let signature = document.root_element();
        let mut objects = signature.children().filter(|node| node.is_element());
        let outer = objects.next().expect("outer Object");
        let inner = objects.next().expect("inner Object");
        let mut authenticated = HashSet::from([outer.id()]);
        let mut processed = HashSet::new();
        let mut remaining = 2;
        let mut next_index = 0;
        let mut xpath_budget = XPathSignatureParseBudget::default();

        let first = parse_manifest_references(
            signature,
            &authenticated,
            &mut processed,
            &mut remaining,
            &mut next_index,
            &mut xpath_budget,
        )
        .expect("outer Manifest must be discovered");
        assert_eq!(first.references.len(), 1);
        assert_eq!(first.references[0].1.uri.as_deref(), Some("#inner"));

        authenticated.insert(inner.id());
        let second = parse_manifest_references(
            signature,
            &authenticated,
            &mut processed,
            &mut remaining,
            &mut next_index,
            &mut xpath_budget,
        )
        .expect("newly authenticated sibling Manifest must remain eligible");
        assert_eq!(second.references.len(), 1);
        assert_eq!(second.references[0].1.uri.as_deref(), Some("#payload"));
    }

    #[test]
    fn manifest_reference_limit_includes_signed_info_references() {
        // The per-signature ceiling is shared by core and authenticated
        // Manifest references; enabling Manifest processing must not reset it.
        let xml = signature_with_manifest_xml(true);
        let reference_start = xml
            .find(r##"<ds:Reference URI="#manifest">"##)
            .expect("fixture SignedInfo must reference the Manifest");
        let reference_end = xml[reference_start..]
            .find("</ds:Reference>")
            .map(|offset| reference_start + offset + "</ds:Reference>".len())
            .expect("fixture SignedInfo Reference must be closed");
        let repeated = xml[reference_start..reference_end].repeat(MAX_REFERENCES_PER_SIGNATURE);
        let xml = format!(
            "{}{repeated}{}",
            &xml[..reference_start],
            &xml[reference_end..]
        );

        let error = VerifyContext::new()
            .key(&AcceptingKey)
            .process_manifests(true)
            .verify(&xml)
            .expect_err("one Manifest Reference must exceed the exhausted signature-wide limit");

        assert!(matches!(
            error,
            SignatureVerificationPipelineError::InvalidStructure {
                reason: "signed Manifests exceed the per-signature Reference limit"
            }
        ));
    }

    #[test]
    fn configured_reference_limit_is_shared_with_manifests() {
        // Lowering the operation policy must lower the aggregate SignedInfo and
        // Manifest capacity rather than falling back to the crate hard limit.
        let policy = crate::policy::VerificationPolicy {
            manifest_processing: crate::policy::ManifestProcessing::Process,
            resources: crate::policy::ResourcePolicy {
                max_references: 1,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::VerificationPolicy::default()
        };

        let error = VerifyContext::new()
            .key(&AcceptingKey)
            .policy(policy)
            .verify(&signature_with_manifest_xml(true))
            .expect_err("Manifest must exceed the caller-selected aggregate limit");
        assert!(matches!(
            error,
            SignatureVerificationPipelineError::InvalidStructure {
                reason: "signed Manifests exceed the per-signature Reference limit"
            }
        ));
    }

    #[test]
    fn retrieval_method_materializes_single_x509_data_subtree() {
        for uri in [
            "#target",
            "#xpointer(id('target'))",
            "#xpointer(id(&quot;target&quot;))",
        ] {
            for target_xml in [
                r#"<ds:X509Data Id="target"><ds:X509SubjectName>CN=leaf</ds:X509SubjectName></ds:X509Data>"#,
                r#"<holder Id="target"><ds:X509Data><ds:X509SubjectName>CN=leaf</ds:X509SubjectName></ds:X509Data></holder>"#,
            ] {
                let xml = format!(
                    r#"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:KeyInfo><ds:RetrievalMethod URI="{uri}" Type="http://www.w3.org/2000/09/xmldsig#X509Data"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>ancestor-or-self::ds:X509Data</ds:XPath></ds:Transform></ds:Transforms></ds:RetrievalMethod></ds:KeyInfo>{target_xml}</root>"#
                );
                let document = Document::parse(&xml).unwrap();
                let key_info_node = document
                    .descendants()
                    .find(|node| node.has_tag_name((XMLDSIG_NS, "KeyInfo")))
                    .unwrap();
                let mut key_info = parse_key_info(key_info_node).unwrap();
                let resolver = UriReferenceResolver::new(&document);

                materialize_retrieval_methods(
                    &mut key_info,
                    &resolver,
                    UriTypeSet::SAME_DOCUMENT,
                    None,
                    crate::provider::default_provider(),
                )
                .expect("XPath filter must produce one X509Data-rooted node-set");
                assert!(matches!(
                    key_info.sources.as_slice(),
                    [super::super::parse::KeyInfoSource::X509Data(info)]
                        if info.subject_names == ["CN=leaf"]
                ));
            }
        }
    }

    fn retrieval_method_xpath_signature() -> String {
        format!(
            r##"<root xmlns:ds="{XMLDSIG_NS}">
              <payload Id="payload">ok</payload>
              <ds:Signature>
                <ds:SignedInfo>
                  <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                  <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                  <ds:Reference URI="#payload">
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>
                  </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>AQ==</ds:SignatureValue>
                <ds:KeyInfo>
                  <ds:RetrievalMethod URI="#target" Type="http://www.w3.org/2000/09/xmldsig#X509Data">
                    <ds:Transforms><ds:Transform Algorithm="{XPATH_TRANSFORM_URI}">
                      <ds:XPath>ancestor-or-self::ds:X509Data</ds:XPath>
                    </ds:Transform></ds:Transforms>
                  </ds:RetrievalMethod>
                </ds:KeyInfo>
              </ds:Signature>
              <holder Id="target"><ds:X509Data><ds:X509SubjectName>CN=leaf</ds:X509SubjectName></ds:X509Data></holder>
            </root>"##
        )
    }

    #[test]
    fn retrieval_method_xpath_uses_signature_expression_budget() {
        // RetrievalMethod XPath belongs to the same untrusted Signature as
        // Reference XPath and must not receive a separate parse allowance.
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.resources.max_xpath_expressions = 0;

        let error = VerifyContext::new()
            .policy(policy)
            .verify(&retrieval_method_xpath_signature())
            .expect_err("RetrievalMethod XPath must consume the signature parse budget");

        assert!(
            matches!(
                &error,
                SignatureVerificationPipelineError::Policy(
                    crate::policy::PolicyViolation::ResourceLimit {
                        resource: "XPath expressions",
                        maximum: 0,
                        actual: 1,
                    }
                )
            ),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn retrieval_method_xpath_obeys_expression_byte_limit() {
        // The parser recognizes this restricted XPath shape, but the original
        // untrusted expression still belongs to the operation policy budget.
        let expression = "ancestor-or-self::ds:X509Data";
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.resources.max_xpath_expression_bytes = expression.len() - 1;

        let error = VerifyContext::new()
            .policy(policy)
            .verify(&retrieval_method_xpath_signature())
            .expect_err("RetrievalMethod XPath must obey the expression byte limit");

        assert!(
            matches!(
                &error,
                SignatureVerificationPipelineError::Policy(
                    crate::policy::PolicyViolation::ResourceLimit {
                        resource: "XPath expression bytes",
                        maximum,
                        actual,
                    }
                ) if *maximum == expression.len() - 1 && *actual == expression.len()
            ),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn retrieval_method_xpath_obeys_expression_complexity_limit() {
        // Recognizing a fixed safe predicate must not bypass the common XPath
        // complexity policy applied to every expression in the signature.
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.resources.max_xpath_expression_complexity = 0;

        let error = VerifyContext::new()
            .policy(policy)
            .verify(&retrieval_method_xpath_signature())
            .expect_err("RetrievalMethod XPath must obey the complexity limit");

        assert!(
            matches!(
                &error,
                SignatureVerificationPipelineError::Policy(
                    crate::policy::PolicyViolation::ResourceLimit {
                        resource: "XPath expression complexity",
                        maximum: 0,
                        actual,
                    }
                ) if *actual > 0
            ),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn retrieval_method_xpath_uses_node_filter_work_budget() {
        // The fixed ancestor-or-self predicate scans the dereferenced node-set
        // and therefore consumes the operation-wide node-filter allowance.
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.resources.max_node_set_filter_work = 0;

        let error = VerifyContext::new()
            .policy(policy)
            .verify(&retrieval_method_xpath_signature())
            .expect_err("RetrievalMethod XPath must consume node-filter work");

        assert!(
            matches!(
                &error,
                SignatureVerificationPipelineError::Policy(
                    crate::policy::PolicyViolation::ResourceLimit {
                        resource: crate::policy::resource_name::NODE_SET_FILTER_WORK,
                        maximum: 0,
                        actual,
                    }
                ) if *actual > 0
            ),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn retrieval_method_xpath_obeys_namespace_binding_limit() {
        // The specialized RetrievalMethod path must retain the XPath element's
        // in-scope namespaces and enforce the same limit as ordinary XPath.
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.resources.max_xpath_namespace_bindings = 0;

        let error = VerifyContext::new()
            .policy(policy)
            .verify(&retrieval_method_xpath_signature())
            .expect_err("RetrievalMethod XPath namespaces must obey the binding limit");

        assert!(matches!(
            error,
            SignatureVerificationPipelineError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XPATH_NAMESPACE_BINDINGS,
                    maximum: 0,
                    actual,
                }
            ) if actual > 0
        ));
    }

    #[test]
    fn retrieval_method_xpath_obeys_namespace_byte_limit() {
        // Prefix and URI bytes retained from the XPath namespace axis consume
        // the same per-expression byte budget as an ordinary XPath transform.
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.resources.max_xpath_namespace_bytes = 0;

        let error = VerifyContext::new()
            .policy(policy)
            .verify(&retrieval_method_xpath_signature())
            .expect_err("RetrievalMethod XPath namespaces must obey the byte limit");

        assert!(matches!(
            error,
            SignatureVerificationPipelineError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XPATH_NAMESPACE_BYTES,
                    maximum: 0,
                    actual,
                }
            ) if actual > 0
        ));
    }

    #[test]
    fn retrieval_method_xpath_obeys_context_evaluation_limit() {
        // Even a recognized fixed expression is evaluated once per node in the
        // dereferenced set and must obey the ordinary XPath context ceiling.
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.resources.max_xpath_context_evaluations = 0;

        let error = VerifyContext::new()
            .policy(policy)
            .verify(&retrieval_method_xpath_signature())
            .expect_err("RetrievalMethod XPath contexts must obey the evaluation limit");

        assert!(matches!(
            error,
            SignatureVerificationPipelineError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XPATH_CONTEXT_EVALUATIONS,
                    maximum: 0,
                    actual,
                }
            ) if actual > 0
        ));
    }

    #[test]
    fn retrieval_method_materializes_direct_untransformed_x509_data() {
        // A typed RetrievalMethod may point directly at the XML structure it
        // identifies; no transform is needed when X509Data is the URI root.
        let xml = r##"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
          <ds:KeyInfo><ds:RetrievalMethod URI="#target" Type="http://www.w3.org/2000/09/xmldsig#X509Data"/></ds:KeyInfo>
          <ds:X509Data Id="target"><ds:X509SubjectName>CN=leaf</ds:X509SubjectName></ds:X509Data>
        </root>"##;
        let document = Document::parse(xml).unwrap();
        let key_info_node = document
            .descendants()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "KeyInfo")))
            .unwrap();
        let mut key_info = parse_key_info(key_info_node).unwrap();

        materialize_retrieval_methods(
            &mut key_info,
            &UriReferenceResolver::new(&document),
            UriTypeSet::SAME_DOCUMENT,
            None,
            crate::provider::default_provider(),
        )
        .expect("a direct X509Data target needs no transform");
        assert!(matches!(
            key_info.sources.as_slice(),
            [super::super::parse::KeyInfoSource::X509Data(info)]
                if info.subject_names == ["CN=leaf"]
        ));
    }

    #[test]
    fn raw_x509_retrieval_method_uses_inherited_xml_base() {
        // RetrievalMethod URI is an attribute URI reference, so XML Base uses
        // the effective base of the element bearing that attribute.
        const RAW_X509_TYPE: &str = "http://www.w3.org/2000/09/xmldsig#rawX509Certificate";
        let xml = format!(
            r#"<root xml:base="https://example.test/keys/nested/" xmlns:ds="{XMLDSIG_NS}">
                <ds:KeyInfo><ds:RetrievalMethod URI="../signer.der" Type="{RAW_X509_TYPE}"/></ds:KeyInfo>
            </root>"#
        );
        let document = Document::parse(&xml).unwrap();
        let key_info_node = document
            .descendants()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "KeyInfo")))
            .unwrap();
        let mut key_info = parse_key_info(key_info_node).unwrap();
        let certificate = include_bytes!(
            "../../tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/certs/balor.der"
        )
        .to_vec();
        let resources = HashMap::from([(
            "https://example.test/keys/signer.der".to_string(),
            certificate,
        )]);
        let resolver = UriReferenceResolver::new(&document).with_external_resources(&resources);

        materialize_retrieval_methods(
            &mut key_info,
            &resolver,
            UriTypeSet::ALL,
            None,
            crate::provider::default_provider(),
        )
        .expect("RetrievalMethod should resolve against inherited xml:base");

        assert!(matches!(
            key_info.sources.as_slice(),
            [super::super::parse::KeyInfoSource::X509Data(info)]
                if info.certificates.len() == 1
        ));
    }

    #[test]
    fn retrieval_method_requires_xpath_for_x509_data_below_uri_root() {
        // Without a transform the dereferenced holder, not its descendant,
        // is the result and therefore cannot masquerade as typed X509Data.
        let xml = r##"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
          <ds:KeyInfo><ds:RetrievalMethod URI="#target" Type="http://www.w3.org/2000/09/xmldsig#X509Data"/></ds:KeyInfo>
          <holder Id="target"><ds:X509Data><ds:X509SubjectName>CN=leaf</ds:X509SubjectName></ds:X509Data></holder>
        </root>"##;
        let document = Document::parse(xml).unwrap();
        let key_info_node = document
            .descendants()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "KeyInfo")))
            .unwrap();
        let mut key_info = parse_key_info(key_info_node).unwrap();

        let error = materialize_retrieval_methods(
            &mut key_info,
            &UriReferenceResolver::new(&document),
            UriTypeSet::SAME_DOCUMENT,
            None,
            crate::provider::default_provider(),
        )
        .expect_err("a wrapper target requires an explicit selection transform");
        assert!(matches!(
            error,
            SignatureVerificationPipelineError::InvalidStructure {
                reason: "untransformed X509Data RetrievalMethod must target X509Data directly"
            }
        ));
    }

    #[test]
    fn retrieval_method_rejects_target_inside_external_x509_data_ancestor() {
        // XPath filtering cannot add an ancestor that was outside the URI's
        // dereferenced node-set, so this result is not rooted at X509Data.
        let xml = r##"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
          <ds:KeyInfo><ds:RetrievalMethod URI="#target" Type="http://www.w3.org/2000/09/xmldsig#X509Data"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>ancestor-or-self::ds:X509Data</ds:XPath></ds:Transform></ds:Transforms></ds:RetrievalMethod></ds:KeyInfo>
          <ds:X509Data><ds:X509SubjectName Id="target">CN=leaf</ds:X509SubjectName></ds:X509Data>
        </root>"##;
        let document = Document::parse(xml).unwrap();
        let key_info_node = document
            .descendants()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "KeyInfo")))
            .unwrap();
        let mut key_info = parse_key_info(key_info_node).unwrap();

        let error = materialize_retrieval_methods(
            &mut key_info,
            &UriReferenceResolver::new(&document),
            UriTypeSet::SAME_DOCUMENT,
            None,
            crate::provider::default_provider(),
        )
        .expect_err("filter output without an X509Data root must be rejected");
        assert!(matches!(
            error,
            SignatureVerificationPipelineError::InvalidStructure {
                reason: "X509Data RetrievalMethod selected no X509Data element"
            }
        ));
    }

    #[test]
    fn retrieval_method_rejects_ambiguous_x509_data_relation() {
        // A transformed result with multiple X509Data roots is not one KeyInfo child.
        let xml = r##"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
          <ds:KeyInfo><ds:RetrievalMethod URI="#target" Type="http://www.w3.org/2000/09/xmldsig#X509Data"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>ancestor-or-self::ds:X509Data</ds:XPath></ds:Transform></ds:Transforms></ds:RetrievalMethod></ds:KeyInfo>
          <holder Id="target"><ds:X509Data/><ds:X509Data/></holder>
        </root>"##;
        let document = Document::parse(xml).unwrap();
        let key_info_node = document
            .descendants()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "KeyInfo")))
            .unwrap();
        let mut key_info = parse_key_info(key_info_node).unwrap();

        let error = materialize_retrieval_methods(
            &mut key_info,
            &UriReferenceResolver::new(&document),
            UriTypeSet::SAME_DOCUMENT,
            None,
            crate::provider::default_provider(),
        )
        .expect_err("multiple transformed X509Data roots must be rejected");
        assert!(matches!(
            error,
            SignatureVerificationPipelineError::InvalidStructure {
                reason: "X509Data RetrievalMethod selected multiple X509Data elements"
            }
        ));
    }

    #[test]
    fn retrieval_method_materialization_preserves_key_info_order() {
        // Replacing the source in place keeps a later fallback behind the
        // retrieved key material for first-match resolvers.
        let xml = r##"<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
          <ds:KeyInfo>
            <ds:RetrievalMethod URI="#target" Type="http://www.w3.org/2000/09/xmldsig#X509Data"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>ancestor-or-self::ds:X509Data</ds:XPath></ds:Transform></ds:Transforms></ds:RetrievalMethod>
            <ds:KeyName>fallback</ds:KeyName>
          </ds:KeyInfo>
          <holder Id="target"><ds:X509Data><ds:X509SubjectName>CN=leaf</ds:X509SubjectName></ds:X509Data></holder>
        </root>"##;
        let document = Document::parse(xml).unwrap();
        let key_info_node = document
            .descendants()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "KeyInfo")))
            .unwrap();
        let mut key_info = parse_key_info(key_info_node).unwrap();

        materialize_retrieval_methods(
            &mut key_info,
            &UriReferenceResolver::new(&document),
            UriTypeSet::SAME_DOCUMENT,
            None,
            crate::provider::default_provider(),
        )
        .unwrap();
        assert!(matches!(
            key_info.sources.as_slice(),
            [
                super::super::parse::KeyInfoSource::X509Data(_),
                super::super::parse::KeyInfoSource::KeyName(name)
            ] if name == "fallback"
        ));
    }

    #[test]
    fn retrieval_method_materialization_bounds_repeated_sources() {
        // Repeating one allowed certificate must not multiply parsing and clones
        // before SignatureValue validation.
        const RAW_X509_TYPE: &str = "http://www.w3.org/2000/09/xmldsig#rawX509Certificate";
        let certificate = include_bytes!(
            "../../tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/certs/balor.der"
        )
        .to_vec();
        let resources = HashMap::from([("urn:certificate".to_string(), certificate)]);
        let mut key_info = KeyInfo {
            sources: (0..=64)
                .map(|_| super::super::parse::KeyInfoSource::RetrievalMethod {
                    uri: "urn:certificate".into(),
                    resource_type: Some(RAW_X509_TYPE.into()),
                    transforms: RetrievalMethodTransforms::None,
                })
                .collect(),
        };
        let document = Document::parse("<root/>").unwrap();
        let resolver = UriReferenceResolver::new(&document).with_external_resources(&resources);

        let error = materialize_retrieval_methods(
            &mut key_info,
            &resolver,
            UriTypeSet::ALL,
            None,
            crate::provider::default_provider(),
        )
        .expect_err("retrieval count must be bounded before materialization");
        assert!(matches!(
            error,
            SignatureVerificationPipelineError::InvalidStructure {
                reason: "KeyInfo contains too many RetrievalMethod elements"
            }
        ));
    }

    #[test]
    fn retrieval_method_materialization_deduplicates_within_count_limit() {
        // Repeated references to the same raw certificate produce one parsed
        // key source rather than one certificate clone per XML element.
        const RAW_X509_TYPE: &str = "http://www.w3.org/2000/09/xmldsig#rawX509Certificate";
        let certificate = include_bytes!(
            "../../tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/certs/balor.der"
        )
        .to_vec();
        let resources = HashMap::from([("urn:certificate".to_string(), certificate)]);
        let mut key_info = KeyInfo {
            sources: (0..MAX_RETRIEVAL_METHOD_COUNT)
                .map(|_| super::super::parse::KeyInfoSource::RetrievalMethod {
                    uri: "urn:certificate".into(),
                    resource_type: Some(RAW_X509_TYPE.into()),
                    transforms: RetrievalMethodTransforms::None,
                })
                .collect(),
        };
        let document = Document::parse("<root/>").unwrap();
        let resolver = UriReferenceResolver::new(&document).with_external_resources(&resources);

        materialize_retrieval_methods(
            &mut key_info,
            &resolver,
            UriTypeSet::ALL,
            None,
            crate::provider::default_provider(),
        )
        .unwrap();
        assert!(matches!(
            key_info.sources.as_slice(),
            [super::super::parse::KeyInfoSource::X509Data(info)]
                if info.certificates.len() == 1
        ));
    }

    #[test]
    fn raw_x509_retrieval_rejects_empty_same_document_uri() {
        // rawX509Certificate consumes external DER octets; an empty URI denotes
        // the XML document and must never become a key into the external map.
        const RAW_X509_TYPE: &str = "http://www.w3.org/2000/09/xmldsig#rawX509Certificate";
        let certificate = include_bytes!(
            "../../tests/fixtures/xmldsig/merlin-xmldsig-twenty-three/certs/balor.der"
        )
        .to_vec();
        let resources = HashMap::from([(String::new(), certificate)]);
        let mut key_info = KeyInfo {
            sources: vec![super::super::parse::KeyInfoSource::RetrievalMethod {
                uri: String::new(),
                resource_type: Some(RAW_X509_TYPE.into()),
                transforms: RetrievalMethodTransforms::None,
            }],
        };
        let document = Document::parse("<root/>").unwrap();
        let resolver = UriReferenceResolver::new(&document).with_external_resources(&resources);

        let error = materialize_retrieval_methods(
            &mut key_info,
            &resolver,
            UriTypeSet::ALL,
            None,
            crate::provider::default_provider(),
        )
        .expect_err("empty URI must retain same-document semantics");
        assert!(matches!(
            error,
            SignatureVerificationPipelineError::InvalidStructure {
                reason: "raw X509 RetrievalMethod requires an untransformed external URI"
            }
        ));
    }

    #[test]
    fn verify_context_does_not_hide_malformed_digest_behind_unsupported_transform() {
        // A bad DigestValue remains a parse error even when its transform URI is unsupported.
        let broken_xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
            let xml = xml.replacen(
                "<ds:Reference URI=\"#target\">",
                "<ds:Reference URI=\"#target\"><ds:Transforms><ds:Transform Algorithm=\"urn:unsupported\"/></ds:Transforms>",
                1,
            );
            replace_fixture_manifest_digest(&xml, "!!!")
        });

        let error = VerifyContext::new()
            .key(&AcceptingKey)
            .process_manifests(true)
            .verify(&broken_xml)
            .expect_err("malformed Manifest digest must not become a validity result");
        assert!(matches!(
            error,
            SignatureVerificationPipelineError::ParseManifestReference(_)
        ));
    }

    #[test]
    fn verify_context_rejects_manifest_non_whitespace_mixed_content() {
        // Authenticated mixed content is still structurally invalid under the
        // Manifest element-only grammar.
        let xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
            xml.replacen(
                "<ds:Manifest ID=\"manifest\">",
                "<ds:Manifest ID=\"manifest\">junk",
                1,
            )
        });

        let err = VerifyContext::new()
            .key(&AcceptingKey)
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
        // An authenticated empty Manifest violates the required Reference+
        // content model rather than disappearing as an unsigned block.
        let xml = signature_with_manifest_xml_with_manifest_mutation(true, |xml| {
            let (prefix, rest) = xml
                .split_once("<ds:Manifest ID=\"manifest\">")
                .expect("fixture should contain Manifest");
            let (_, suffix) = rest
                .split_once("</ds:Manifest>")
                .expect("fixture should contain closing Manifest");
            format!("{prefix}<ds:Manifest ID=\"manifest\"></ds:Manifest>{suffix}")
        });

        let err = VerifyContext::new()
            .key(&AcceptingKey)
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
            SignatureVerificationPipelineError::Policy(crate::policy::PolicyViolation::Algorithm {
                operation: "verification transform",
                ..
            })
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
    fn verification_candidate_budget_covers_preset_and_custom_resolver_paths() {
        // Zero is a valid deny-all ceiling. Neither an already-resolved key nor
        // a custom resolver may bypass the operation-wide candidate policy.
        let xml = signature_with_target_reference("AQ==");
        let mut policy = crate::policy::VerificationPolicy::default();
        policy.resources.max_key_candidates = 0;

        let preset_error = VerifyContext::new()
            .key(&RejectingKey)
            .policy(policy.clone())
            .verify(&xml)
            .expect_err("a preset key consumes one candidate");
        assert!(matches!(
            preset_error,
            SignatureVerificationPipelineError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::KEY_CANDIDATES,
                    maximum: 0,
                    actual: 1,
                }
            )
        ));

        let resolver_error = VerifyContext::new()
            .key_resolver(&PanicResolver)
            .policy(policy)
            .verify(&xml)
            .expect_err("a custom resolver requires candidate capacity before dispatch");
        assert!(matches!(
            resolver_error,
            SignatureVerificationPipelineError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::KEY_CANDIDATES,
                    maximum: 0,
                    actual: 1,
                }
            )
        ));
    }

    #[test]
    fn verify_context_resolver_can_ignore_malformed_keyinfo_by_default() {
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
            .key_resolver(&MissingKeyResolver)
            .verify(&xml)
            .expect("resolver path should not hard-fail on advisory malformed KeyInfo by default");
        assert!(matches!(
            result.status,
            DsigStatus::Invalid(FailureReason::KeyNotFound)
        ));
    }

    #[test]
    fn verify_context_resolver_can_opt_in_to_keyinfo_parse_failures() {
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

        let err = VerifyContext::new()
            .key_resolver(&ConsumingKeyInfoResolver)
            .verify(&xml)
            .expect_err("resolver opted into KeyInfo parsing, malformed KeyInfo must fail");
        assert!(matches!(
            err,
            SignatureVerificationPipelineError::ParseKeyInfo(_)
        ));
    }

    #[test]
    fn verify_context_ignores_unsupported_retrieval_before_valid_key_source() {
        // An advisory vendor RetrievalMethod cannot prevent the resolver from
        // reaching a later supported source in document order.
        let xml = signature_with_target_reference("AQ==").replace(
            "</ds:SignatureValue>\n  </ds:Signature>",
            r##"</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:RetrievalMethod URI="#vendor" Type="urn:vendor:key">
        <ds:Transforms><ds:Transform Algorithm="urn:vendor:transform"/></ds:Transforms>
      </ds:RetrievalMethod>
      <ds:KeyName>fallback</ds:KeyName>
    </ds:KeyInfo>
  </ds:Signature>"##,
        );

        let result = VerifyContext::new()
            .key_resolver(&FallbackKeyInfoResolver)
            .verify(&xml)
            .expect("unsupported advisory retrieval must not abort key resolution");
        assert_eq!(result.status, DsigStatus::Valid);
    }

    #[test]
    fn verify_context_does_not_eagerly_fail_unused_retrieval_fallback() {
        // KeyInfo sources are alternatives in document order. Once an earlier
        // source resolves, a missing later RetrievalMethod is irrelevant.
        let xml = signature_with_target_reference("AQ==").replace(
            "</ds:SignatureValue>\n  </ds:Signature>",
            r#"</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:KeyName>primary</ds:KeyName>
      <ds:RetrievalMethod URI="missing.der" Type="http://www.w3.org/2000/09/xmldsig#rawX509Certificate"/>
    </ds:KeyInfo>
  </ds:Signature>"#,
        );

        let result = VerifyContext::new()
            .key_resolver(&EarlyKeyInfoResolver)
            .allowed_retrieval_method_uri_types(UriTypeSet::new(true, true, true))
            .verify(&xml)
            .expect("an unused missing retrieval fallback must not abort verification");

        assert_eq!(result.status, DsigStatus::Valid);
    }

    #[test]
    fn verify_context_does_not_eagerly_parse_unused_retrieval_fallback() {
        // Materialization must preserve ordered fallback semantics even when
        // caller-supplied bytes exist but are not a certificate.
        let xml = signature_with_target_reference("AQ==").replace(
            "</ds:SignatureValue>\n  </ds:Signature>",
            r#"</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:KeyName>primary</ds:KeyName>
      <ds:RetrievalMethod URI="malformed.der" Type="http://www.w3.org/2000/09/xmldsig#rawX509Certificate"/>
    </ds:KeyInfo>
  </ds:Signature>"#,
        );
        let resources = HashMap::from([("malformed.der".to_string(), b"not DER".to_vec())]);

        let result = VerifyContext::new()
            .key_resolver(&EarlyKeyInfoResolver)
            .allowed_retrieval_method_uri_types(UriTypeSet::ALL)
            .external_resources(&resources)
            .verify(&xml)
            .expect("an unused malformed retrieval fallback must not abort verification");

        assert_eq!(result.status, DsigStatus::Valid);
    }

    #[test]
    fn verify_context_reports_missing_retrieval_when_no_key_source_resolves() {
        // Deferral changes ordering, not diagnostics: if no alternative source
        // resolves, the first missing retrieval remains the pipeline failure.
        let xml = signature_with_target_reference("AQ==").replace(
            "</ds:SignatureValue>\n  </ds:Signature>",
            r#"</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:RetrievalMethod URI="missing.der" Type="http://www.w3.org/2000/09/xmldsig#rawX509Certificate"/>
    </ds:KeyInfo>
  </ds:Signature>"#,
        );

        let error = VerifyContext::new()
            .key_resolver(&ConsumingKeyInfoResolver)
            .allowed_retrieval_method_uri_types(UriTypeSet::new(true, true, true))
            .verify(&xml)
            .expect_err("a missing sole RetrievalMethod must remain an explicit error");

        assert!(matches!(
            error,
            SignatureVerificationPipelineError::Reference(ReferenceProcessingError::Transform(
                crate::xmldsig::TransformError::UnsupportedUri(uri)
            )) if uri == "missing.der"
        ));
    }

    #[test]
    fn verify_context_reports_malformed_retrieval_when_no_key_source_resolves() {
        // Deferral must retain the parse error when the malformed certificate
        // is the only candidate rather than degrading it to KeyNotFound.
        let xml = signature_with_target_reference("AQ==").replace(
            "</ds:SignatureValue>\n  </ds:Signature>",
            r#"</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:RetrievalMethod URI="malformed.der" Type="http://www.w3.org/2000/09/xmldsig#rawX509Certificate"/>
    </ds:KeyInfo>
  </ds:Signature>"#,
        );
        let resources = HashMap::from([("malformed.der".to_string(), b"not DER".to_vec())]);

        let error = VerifyContext::new()
            .key_resolver(&ConsumingKeyInfoResolver)
            .allowed_retrieval_method_uri_types(UriTypeSet::ALL)
            .external_resources(&resources)
            .verify(&xml)
            .expect_err("a malformed sole RetrievalMethod must remain a parse error");

        assert!(matches!(
            error,
            SignatureVerificationPipelineError::ParseKeyInfo(_)
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
    fn enforce_reference_policies_checks_only_terminal_binary_output() {
        let c14n = C14nAlgorithm::from_uri(DEFAULT_IMPLICIT_C14N_URI).unwrap();
        let allowed = HashSet::from([
            BASE64_TRANSFORM_URI.to_owned(),
            DEFAULT_IMPLICIT_C14N_URI.to_owned(),
        ]);
        let without_implicit_c14n = HashSet::from([BASE64_TRANSFORM_URI.to_owned()]);

        for transforms in [
            vec![Transform::Base64Decode, Transform::C14n(c14n)],
            vec![Transform::Base64Decode, Transform::Base64Decode],
        ] {
            let reference = make_reference("", transforms, DigestAlgorithm::Sha256, vec![0; 32]);
            enforce_reference_policies(
                std::slice::from_ref(&reference),
                UriTypeSet::default(),
                Some(&allowed),
            )
            .expect("terminal binary output must not require implicit C14N");
        }

        let terminal_base64 = make_reference(
            "",
            vec![Transform::Base64Decode, Transform::Base64Decode],
            DigestAlgorithm::Sha256,
            vec![0; 32],
        );
        enforce_reference_policies(
            std::slice::from_ref(&terminal_base64),
            UriTypeSet::default(),
            Some(&without_implicit_c14n),
        )
        .expect("terminal Base64 output must not require implicit C14N");

        let no_transforms = make_reference("", vec![], DigestAlgorithm::Sha256, vec![0; 32]);
        let error = enforce_reference_policies(
            std::slice::from_ref(&no_transforms),
            UriTypeSet::default(),
            Some(&without_implicit_c14n),
        )
        .expect_err("a node-set result must require allowlisted implicit C14N");
        assert!(matches!(
            error,
            SignatureVerificationPipelineError::Policy(
                crate::policy::PolicyViolation::Algorithm {
                    operation: "verification transform",
                    ref algorithm,
                }
            )
                if algorithm == DEFAULT_IMPLICIT_C14N_URI
        ));

        let detached = make_reference("urn:payload", vec![], DigestAlgorithm::Sha256, vec![0; 32]);
        enforce_reference_policies(
            std::slice::from_ref(&detached),
            UriTypeSet::ALL,
            Some(&without_implicit_c14n),
        )
        .expect("external octets without transforms must not require implicit C14N");

        let external_xpath = make_reference(
            "urn:payload",
            vec![Transform::XPath(
                super::super::transforms::XPathExpression::new("true()"),
            )],
            DigestAlgorithm::Sha256,
            vec![0; 32],
        );
        let error = enforce_reference_policies(
            std::slice::from_ref(&external_xpath),
            UriTypeSet::ALL,
            Some(&HashSet::from([XPATH_TRANSFORM_URI.to_owned()])),
        )
        .expect_err("external XML converted to a node-set must require implicit C14N");
        assert!(matches!(
            error,
            SignatureVerificationPipelineError::Policy(
                crate::policy::PolicyViolation::Algorithm {
                    operation: "verification transform",
                    ref algorithm,
                }
            )
                if algorithm == DEFAULT_IMPLICIT_C14N_URI
        ));
    }

    #[test]
    fn stored_pre_digest_budget_counts_repeated_external_references() {
        // The caller map owns one bounded payload, but diagnostic retention is
        // charged per Reference because every result owns its pre-digest bytes.
        let document =
            Document::parse("<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"/>")
                .unwrap();
        let payload = vec![b'x'; 7];
        let digest = compute_digest(DigestAlgorithm::Sha256, &payload);
        let references = (0..5)
            .map(|_| {
                make_reference(
                    "urn:repeated",
                    Vec::new(),
                    DigestAlgorithm::Sha256,
                    digest.clone(),
                )
            })
            .collect::<Vec<_>>();
        let resources = HashMap::from([("urn:repeated".to_owned(), payload)]);
        let resolver = UriReferenceResolver::new(&document).with_external_resources(&resources);
        let transform_budget = TransformExecutionBudget::default();
        let canonicalized_data_budget = CanonicalizedDataBudget::with_limit(32);
        let execution = ReferenceExecutionContext {
            store_pre_digest: true,
            transform_options: TransformOptions::default(),
            transform_budget: &transform_budget,
            canonicalized_data_budget: &canonicalized_data_budget,
            provider: crate::provider::default_provider(),
        };

        let error = process_all_references_with_options(
            &references,
            &resolver,
            document.root_element(),
            &execution,
        )
        .expect_err(
            "retained diagnostics must not multiply one external allocation past the aggregate cap",
        );
        assert!(matches!(
            error,
            ReferenceProcessingError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: "canonicalized bytes",
                maximum: 32,
                ..
            })
        ));
    }

    #[test]
    fn canonical_signed_info_obeys_policy_without_diagnostic_retention() {
        // SignedInfo is always materialized for crypto verification, so its
        // canonical bytes must consume the configured ceiling even when
        // diagnostics do not retain reference output.
        let xml = signature_with_target_reference("AQ==");
        let marker = "<ds:SignatureMethod";
        let padding = " ".repeat(1_025);
        let xml = xml.replacen(marker, &format!("{padding}{marker}"), 1);
        let policy = crate::policy::VerificationPolicy {
            resources: crate::policy::ResourcePolicy {
                max_canonicalized_bytes: 1_024,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::VerificationPolicy::default()
        };

        let error = VerifyContext::new()
            .key(&AcceptingKey)
            .policy(policy)
            .verify(&xml)
            .expect_err("canonicalized SignedInfo must remain policy-bounded");

        assert!(matches!(
            error,
            SignatureVerificationPipelineError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: "canonicalized bytes",
                    ..
                }
            )
        ));
    }

    #[test]
    fn push_normalized_signature_text_rejects_form_feed() {
        let mut normalized = Vec::new();
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
        let mut normalized = vec![b'A'; MAX_SIGNATURE_VALUE_LEN - 1];
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
    fn reference_processing_shares_xpath_work_across_references() {
        // A signature-wide meter must not reset when processing the next
        // Reference, even though each transform chain is independently valid.
        let document = Document::parse("<root/>").unwrap();
        let resolver = UriReferenceResolver::new(&document);
        let transform = Transform::XPath(super::super::transforms::XPathExpression::new("true()"));
        let initial_data = resolver.dereference("").unwrap();
        let pre_digest = crate::xmldsig::execute_transforms(
            document.root_element(),
            initial_data,
            std::slice::from_ref(&transform),
        )
        .unwrap();
        let digest = compute_digest(DigestAlgorithm::Sha256, &pre_digest);
        let references = vec![
            make_reference(
                "",
                vec![transform.clone()],
                DigestAlgorithm::Sha256,
                digest.clone(),
            ),
            make_reference("", vec![transform], DigestAlgorithm::Sha256, digest),
        ];
        let budget = TransformExecutionBudget::with_xpath_limit(12);
        let canonicalized_data_budget = CanonicalizedDataBudget::default();
        let execution = ReferenceExecutionContext {
            store_pre_digest: false,
            transform_options: TransformOptions::default(),
            transform_budget: &budget,
            canonicalized_data_budget: &canonicalized_data_budget,
            provider: crate::provider::default_provider(),
        };

        let error = process_all_references_with_options(
            &references,
            &resolver,
            document.root_element(),
            &execution,
        )
        .expect_err("the second Reference must consume the first Reference's XPath work");

        assert!(matches!(
            error,
            ReferenceProcessingError::Transform(TransformError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XPATH_EVALUATION_WORK,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn reference_processing_shares_node_set_materialization_across_references() {
        // Repeated references to the same small subtree must share one owned-
        // string budget. Otherwise a large inherited namespace can be cloned
        // once per Reference even when canonicalization emits little output.
        let document = Document::parse(
            r#"<root xmlns:n="urn:0123456789"><target Id="selected">payload</target></root>"#,
        )
        .unwrap();
        let resolver = UriReferenceResolver::new(&document);
        let initial_data = resolver.dereference("#selected").unwrap();
        let pre_digest =
            crate::xmldsig::execute_transforms(document.root_element(), initial_data, &[]).unwrap();
        let digest = compute_digest(DigestAlgorithm::Sha256, &pre_digest);
        let references = vec![
            make_reference("#selected", vec![], DigestAlgorithm::Sha256, digest.clone()),
            make_reference("#selected", vec![], DigestAlgorithm::Sha256, digest),
        ];
        let budget = TransformExecutionBudget::with_node_set_materialization_limit(30);
        let canonicalized_data_budget = CanonicalizedDataBudget::default();
        let execution = ReferenceExecutionContext {
            store_pre_digest: false,
            transform_options: TransformOptions::default(),
            transform_budget: &budget,
            canonicalized_data_budget: &canonicalized_data_budget,
            provider: crate::provider::default_provider(),
        };

        let error = process_all_references_with_options(
            &references,
            &resolver,
            document.root_element(),
            &execution,
        )
        .expect_err("the second Reference must consume the first Reference's materialization work");

        assert!(matches!(
            error,
            ReferenceProcessingError::UriDereference(TransformError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::NODE_SET_CUMULATIVE_OWNED_STRING_BYTES,
                    ..
                }
            ))
        ));
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
    fn pipeline_start_node_limits_signature_cardinality_to_its_subtree() {
        // A start-node selector changes the operation root, not global ID or
        // reference resolution; another Signature outside the subtree is irrelevant.
        let xml = r#"
<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <scope Id="selected"><ds:Signature/></scope>
  <scope Id="other"><ds:Signature/></scope>
</root>
"#;
        let err = VerifyContext::new()
            .start_node_id("selected")
            .verify(xml)
            .expect_err("the selected Signature remains structurally incomplete");
        assert!(matches!(
            err,
            SignatureVerificationPipelineError::MissingElement {
                element: "SignedInfo"
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
