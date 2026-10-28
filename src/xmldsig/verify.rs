//! `XMLDSig` reference processing and end-to-end signature verification pipeline.
//!
//! Implements [XMLDSig §4.3.3](https://www.w3.org/TR/xmldsig-core1/#sec-CoreValidation):
//! for each `<Reference>` in `<SignedInfo>`, dereference the URI, apply transforms,
//! compute the digest, and compare with the stored `<DigestValue>`.
//!
//! This module wires together:
//! - [`UriReferenceResolver`] for URI dereference
//! - [`super::transforms::execute_transforms`] for the transform pipeline
//! - [`compute_digest`](super::digest::compute_digest) + [`constant_time_eq`] for digest
//!   computation and comparison
//! - [`verify_signature_with_pem_key`] for full pipeline validation (`SignedInfo` + `SignatureValue`)

use crate::xml::dom::{Node, NodeId};
use base64::Engine;
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};

use crate::c14n::canonicalize_bounded_with_xml_base_budget;
use crate::document::{
    DocumentParseSettings, DocumentView, NodeIdentity, XmlDocument, XmlDocumentError,
};
use crate::hard_limits::CANONICALIZED_SIGNATURE_DATA_BYTE_CEILING;
use crate::operation::{
    OperationDecisionReason, OperationExecutionContext, OperationNodeId, OperationNodeKind,
    OperationPlanError, OperationResourceIdentity, OperationStage,
};

#[cfg(test)]
use super::digest::compute_digest;
use super::digest::{DigestAlgorithm, constant_time_eq};
#[cfg(test)]
use super::parse::MAX_REFERENCES_PER_SIGNATURE;
#[cfg(test)]
use super::parse::parse_key_info;
use super::parse::{
    KeyInfo, MAX_X509_DATA_TOTAL_BINARY_LEN, MAX_X509_DECODED_BINARY_LEN, ParseError, Reference,
    RetrievalMethodTransforms, SignatureAlgorithm, SourceOrigin, XMLDSIG_NS,
};
use super::parse::{
    parse_reference_with_xpath_budget, parse_signed_info_with_xpath_budget,
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
    map_c14n_resource_policy_violation, transform_chain_uses_implicit_c14n,
};
use super::types::{NodeSet, TransformError, subtree_node_id_range};
use super::uri::{ExternalResourceMapError, UriReferenceResolver, validate_external_resource_map};
use super::whitespace::{is_xml_whitespace_only, normalize_xml_base64_bytes};

mod session;
pub use session::*;
mod capture;
pub use capture::SelectedSignatureMethod;
use capture::{CapturedOperation, ScopedCapture, VerificationCapture};

const MAX_SIGNATURE_VALUE_LEN: usize = 8192;
const MAX_RETRIEVAL_METHOD_COUNT: usize = 64;

/// One verification operation's immutable policy and its key-material account.
///
/// Policy-aware [`VerifyingKey`] hooks receive this scope so that reading a
/// key's public material is charged to the operation's X.509 allowance and
/// reported as a typed policy violation, never to a fresh account.
#[derive(Clone, Copy)]
pub struct VerificationScope<'a> {
    policy: &'a crate::policy::VerificationPolicy,
    certificates: &'a super::pkix::CertificateSession,
}

impl<'a> VerificationScope<'a> {
    pub(crate) fn new(
        policy: &'a crate::policy::VerificationPolicy,
        certificates: &'a super::pkix::CertificateSession,
    ) -> Self {
        Self {
            policy,
            certificates,
        }
    }

    /// The operation's immutable verification policy.
    #[must_use]
    pub fn policy(&self) -> &'a crate::policy::VerificationPolicy {
        self.policy
    }

    pub(crate) fn certificates(&self) -> &'a super::pkix::CertificateSession {
        self.certificates
    }
}

/// Cryptographic verifier used by [`VerifyContext`].
///
/// This trait intentionally has no `Send + Sync` supertraits so lightweight
/// single-threaded verifiers can be used without additional bounds.
pub trait VerifyingKey {
    /// Borrow public SPKI describing this exact key after successful verification.
    /// This is evidence only, never authorization for native verification or
    /// private-key export. Composite handles expose their leaves instead. This
    /// hook only borrows cached public metadata; it must not allocate, parse,
    /// perform I/O or manufacture a different key after the decision.
    fn association_spki(&self, _algorithm: SignatureAlgorithm) -> Option<&[u8]> {
        None
    }
    /// Exact external execution domain; a key cannot be moved between token sessions.
    fn provider_binding(&self) -> Option<&crate::provider::ProviderBinding> {
        None
    }
    /// Composite resolvers may try individual keys through the selected engine.
    /// `None` identifies a leaf handle. Wrappers must preserve per-key policy
    /// when forwarding the visitor; no public/private key copy is required.
    ///
    /// # Errors
    /// Propagates visitor, per-candidate policy and composite-resolution failures.
    fn verify_candidate_keys(
        &self,
        _verify: &mut dyn FnMut(&dyn VerifyingKey) -> Result<bool, DsigError>,
    ) -> Result<Option<bool>, DsigError> {
        Ok(None)
    }
    /// Borrow public SPKI for native verification, validating method/key binding.
    /// Opaque external keys may return `None`; native providers then fail closed.
    ///
    /// # Errors
    /// Returns method/key binding, policy or public-metadata processing failures.
    fn verification_spki(
        &self,
        _algorithm: SignatureAlgorithm,
    ) -> Result<Option<&[u8]>, DsigError> {
        Ok(None)
    }

    /// Wire encoding already selected by the immutable verification policy.
    fn ecdsa_encoding(&self) -> crate::policy::EcdsaSignatureValueEncoding {
        crate::policy::EcdsaSignatureValueEncoding::XmlDsig
    }
    /// Verify with validated domain separation, rejecting unsupported contexts.
    ///
    /// # Errors
    /// Returns an unsupported context or the key's verification-processing
    /// failure. A completed cryptographic mismatch remains `Ok(false)`.
    fn verify_with_context(
        &self,
        algorithm: SignatureAlgorithm,
        context: &super::SignatureContext,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, DsigError> {
        if !context.as_bytes().is_empty() {
            return Err(super::SignatureVerificationError::UnsupportedAlgorithm {
                uri: algorithm.uri().to_owned(),
            }
            .into());
        }
        self.verify(algorithm, data, signature)
    }
    /// Validate this key against the operation's immutable trust policy.
    ///
    /// Built-in keys override this hook so pre-resolved and resolver-produced
    /// keys enforce identical strength constraints, reading their public
    /// material under the scope's account. Custom opaque keys may retain their
    /// own policy enforcement by accepting the default no-op.
    ///
    /// # Errors
    /// Implementations return policy refusals for incompatible key strength,
    /// permitted usage, encoding, trust or resource constraints.
    fn validate_policy(&self, _scope: &VerificationScope<'_>) -> Result<(), DsigError> {
        Ok(())
    }

    /// Check that `signature_value` has the wire framing required by the
    /// declared algorithm and this key before provider dispatch.
    ///
    /// Key implementations with key-size-dependent framing should override
    /// this method. The default enforces the algorithm-wide `XMLDSig` envelope.
    ///
    /// # Errors
    /// Implementations propagate key-metadata processing failures. An ordinary
    /// framing mismatch is `Ok(false)`, not a provider execution failure.
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

    /// Validate wire framing under the operation's immutable compatibility policy.
    ///
    /// The default delegates to [`VerifyingKey::validate_signature_value`] and
    /// therefore implements only the standard `XMLDSig` framing contract. Custom
    /// keys that support policy-selected wire formats, such as
    /// [`crate::policy::EcdsaSignatureValueEncoding::XmlSecAsn1Der`], must
    /// override this hook rather than accepting both formats implicitly.
    ///
    /// # Errors
    /// Propagates policy and key-metadata processing failures; completed framing
    /// mismatches are `Ok(false)` under the selected wire contract.
    fn validate_signature_value_with_policy(
        &self,
        _scope: &VerificationScope<'_>,
        algorithm: SignatureAlgorithm,
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        self.validate_signature_value(algorithm, signature_value)
    }

    /// Verify `signature_value` over `signed_data` with the declared algorithm.
    ///
    /// # Errors
    /// Returns unsupported key/method combinations or verification-processing
    /// failures. A completed cryptographic mismatch is `Ok(false)`.
    fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        signed_data: &[u8],
        signature_value: &[u8],
    ) -> Result<bool, DsigError>;

    /// Verify after applying operation-scoped compatibility semantics.
    ///
    /// The default delegates to [`VerifyingKey::verify_with_context`]. Custom
    /// keys whose provider input depends on compatibility policy must override
    /// this hook consistently with
    /// [`VerifyingKey::validate_signature_value_with_policy`].
    ///
    /// # Errors
    /// Propagates policy, unsupported-method and verification-processing failures;
    /// a completed cryptographic mismatch remains `Ok(false)`.
    fn verify_with_policy(
        &self,
        _scope: &VerificationScope<'_>,
        algorithm: SignatureAlgorithm,
        context: &super::SignatureContext,
        signed_data: &[u8],
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        self.verify_with_context(algorithm, context, signed_data, signature_value)
    }
}

/// Key resolver hook used by [`VerifyContext`] when no pre-set key is provided.
///
/// This trait intentionally has no `Send + Sync` supertraits; callers that need
/// cross-thread sharing can wrap resolvers/keys in their own thread-safe types.
pub trait KeyResolver {
    /// Resolve using the core operation's cumulative candidate and certificate account.
    /// The default charges one custom-resolver dispatch. Implementations searching
    /// multiple candidates override this method, charging each inspection through
    /// `budget` and using its execution account for certificate mechanism work.
    ///
    /// # Errors
    /// Returns invalid policy, cumulative candidate/resource refusal or the
    /// resolver's key/trust processing failure. A complete search miss is `Ok(None)`.
    fn resolve_for_verification_with_budget<'a>(
        &'a self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
        policy: &crate::policy::VerificationPolicy,
        provider: &dyn crate::provider::CryptoProvider,
        budget: &mut super::InspectedKeyCandidateBudget,
    ) -> Result<Option<super::ResolvedVerificationKey<'a>>, DsigError> {
        budget.bind_policy(policy)?;
        budget.charge()?;
        self.resolve_for_verification(key_info, algorithm, policy, provider)
    }

    /// Discover and explicitly authorize a key for an end-to-end operation.
    /// The default preserves discovery only: applications that authorize keys
    /// themselves return `ResolvedVerificationKey::CallerTrusted` explicitly.
    ///
    /// # Errors
    /// Propagates policy/provider-aware key discovery and trust processing
    /// failures; absence of a usable candidate is `Ok(None)`.
    fn resolve_for_verification<'a>(
        &'a self,
        key_info: Option<&KeyInfo>,
        algorithm: SignatureAlgorithm,
        policy: &crate::policy::VerificationPolicy,
        provider: &dyn crate::provider::CryptoProvider,
    ) -> Result<Option<super::ResolvedVerificationKey<'a>>, DsigError> {
        Ok(self
            .resolve_with_policy_and_provider(key_info, algorithm, policy, provider)?
            .map(super::ResolvedVerificationKey::Candidate))
    }
    /// Resolve a verification key from parsed `<KeyInfo>` sources.
    ///
    /// Return `Ok(None)` when no suitable key could be resolved from available
    /// key material (for example, missing `<KeyInfo>` candidates). `VerifyContext`
    /// maps `Ok(None)` to `DsigStatus::Invalid(FailureReason::KeyNotFound)`;
    /// reserve `Err(...)` for resolver failures.
    ///
    /// # Errors
    /// Returns key decoding, unsupported mechanism, policy/resource or resolver
    /// execution failures, rather than a completed search miss.
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
    ///
    /// # Errors
    /// Propagates resolver failures and any implementation-specific policy or
    /// cumulative candidate-budget refusal; a complete miss remains `Ok(None)`.
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
    ///
    /// # Errors
    /// Propagates resolver, policy/resource, key/certificate decoding and
    /// selected-provider processing failures; a complete miss is `Ok(None)`.
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

/// Allowed structural URI classes for `XMLDSig` reference and key-source policy.
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

    /// Return whether this set permits the URI's structural class.
    #[must_use]
    pub fn allows(self, uri: &str) -> bool {
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

/// Request-scoped selection of the `XMLDSig` operation node.
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
#[derive(Clone)]
pub struct VerifyContext<'a> {
    utc_facts: Option<structured_pkix::temporal::LeapTable<'a>>,
    decapsulation_key: Option<&'a dyn crate::provider::KeyDecapsulationKey>,
    key: Option<&'a dyn VerifyingKey>,
    key_resolver: Option<&'a dyn KeyResolver>,
    policy: crate::policy::VerificationPolicy,
    provider: &'a dyn crate::provider::CryptoProvider,
    xml_backend: crate::XmlBackend,
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
            utc_facts: None,
            decapsulation_key: None,
            key: None,
            key_resolver: None,
            policy: crate::policy::VerificationPolicy::default(),
            provider: crate::provider::default_provider(),
            xml_backend: crate::XmlBackend::default(),
            store_pre_digest: false,
            external_resources: None,
            signature_selection: SignatureSelection::UniqueDocumentSignature,
            id_attributes: &[],
        }
    }

    /// Supply application-owned UTC history for certificate evidence. The
    /// context borrows the table; it neither copies it nor discovers updates.
    pub fn utc_facts(mut self, facts: structured_pkix::temporal::LeapTable<'a>) -> Self {
        self.utc_facts = Some(facts);
        self
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

    /// Recover the HMAC secret using an explicit recipient private key.
    /// Policy must grant the exact experimental KEM. A valid KEM/HMAC result
    /// is not evidence of sender identity.
    pub fn decapsulation_key(mut self, key: &'a dyn crate::provider::KeyDecapsulationKey) -> Self {
        self.decapsulation_key = Some(key);
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

    /// Select the compiled XML parser backend for this verification operation.
    pub fn xml_backend(mut self, backend: crate::XmlBackend) -> Self {
        self.xml_backend = backend;
        self
    }

    /// Enable or disable `<Manifest>` processing.
    ///
    /// Process references only when this Signature authenticated the original
    /// Manifest or an ancestor through an ID-based same-document reference
    /// using only canonicalization transforms (or implicit canonicalization).
    /// Such Manifests may be nested or outside Signature; physical ancestry
    /// alone never authenticates them. Authenticated Manifest references can
    /// establish the next discovery frontier through the same operation state.
    /// Filtering or binary transforms do not prove complete original structure.
    /// Unsigned/unreferenced Manifests are skipped.
    /// Whole-document same-document references such as `URI=""` or
    /// `URI="#xpointer(/)"` do not establish an element-specific Manifest
    /// authentication proof for this option.
    ///
    /// Manifests are parsed and processed only after the `SignedInfo` references
    /// and `SignatureValue` both validate. Their digest mismatches, policy
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
    /// The allowlist covers explicit Reference and `RetrievalMethod` transforms,
    /// the declared `SignedInfo` canonicalization method, and implicit default
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

    /// Select the node returned by `XPath`'s `here()` extension function.
    ///
    /// The default follows `XMLDSig` and returns the `<XPath>` parameter.
    /// Use [`XPathHereSemantics::XmlSecLegacy`] only for documents known to
    /// have been generated with libxmlsec1's `<Transform>` interpretation.
    pub fn xpath_here_semantics(mut self, semantics: XPathHereSemantics) -> Self {
        self.policy.transforms.xpath_here_semantics = semantics;
        self
    }

    fn allowed_transform_uris(&self) -> Option<&HashSet<String>> {
        self.policy.transforms.allowed_algorithms.as_ref()
    }

    fn transform_options(&self) -> TransformOptions<'_> {
        TransformOptions::default()
            .id_attributes(self.id_attributes)
            .allow_internal_dtd(self.policy.xml.allow_internal_dtd)
            .xpath_here_semantics(self.policy.transforms.xpath_here_semantics)
            .opc_relationship_edition(self.policy.transforms.opc_relationship_edition)
            .xslt_stylesheet_semantics(self.policy.transforms.xslt_stylesheet_semantics)
    }

    /// Verify one `XMLDSig` signature using this context.
    ///
    /// Returns `Ok(VerifyResult)` for both valid and invalid signatures; inspect
    /// `VerifyResult::status` for the core `<SignedInfo>` and signature-value
    /// outcome. When Manifest processing is enabled, inspect every
    /// `VerifyResult::manifest_references` entry separately. `Err(...)` is
    /// reserved for pipeline failures.
    ///
    /// # Errors
    /// Returns XML/structure, policy/resource, resolution or selected-provider
    /// processing failures; completed invalid signatures remain result statuses.
    pub fn verify(&self, xml: &str) -> Result<VerifyResult, DsigError> {
        verify_signature_with_context(xml, self)
    }

    /// Verify a signature against a retained owned document generation.
    ///
    /// The active XML input policy is revalidated against the document's parse
    /// provenance as well as its current byte and node counts. In particular, a
    /// strict context rejects a document that required internal DTD support.
    ///
    /// # Errors
    /// Returns document provenance/policy mismatch or XML, resource, resolution
    /// and selected-provider processing failures.
    pub fn verify_document(&self, document: &XmlDocument) -> Result<VerifyResult, DsigError> {
        verify_signature_document_with_context(document, self)
    }

    /// Verify every Signature in one retained document generation.
    ///
    /// All signatures share the operation's work and retention budgets. A
    /// malformed or invalid signature is retained as an individual outcome,
    /// never silently skipped. Call [`VerifyEvidence::accepted`] with the
    /// current document before accepting the request; a successful return
    /// alone is not validation. [`VerifyEvidence::all_valid`] is historical
    /// mathematical diagnostics only and does not revalidate document generation.
    ///
    /// # Errors
    /// Returns request/document preparation, provenance, policy or aggregate
    /// resource failures. Individual signature failures remain in the evidence.
    pub fn verify_all(&self, document: &XmlDocument) -> Result<VerifyEvidence, DsigError> {
        verify_all_document(document, self, &VerificationRequest::default())
    }

    /// Discover bounded Signature identities without key or digest work.
    ///
    /// These are untrusted selection handles, not verification evidence. Use
    /// them to authorize request keys even when Signatures have no XML ID.
    ///
    /// # Errors
    /// Returns invalid policy, incompatible document provenance or exhaustion
    /// of the snapshot's signature discovery allowance.
    pub fn signature_identities(
        &self,
        document: &XmlDocument,
    ) -> Result<Vec<NodeIdentity>, DsigError> {
        self.policy.validate()?;
        document.validate_operation_policy(self.policy.xml, &self.policy.resources)?;
        document.with_view(|view| {
            let count = count_signature_nodes(view, self.policy.resources.max_signatures)?;
            let mut identities = Vec::with_capacity(count);
            for node in view.document().descendants() {
                if node.has_tag_name((XMLDSIG_NS, "Signature")) {
                    identities.push(view.node_identity(node));
                }
            }
            Ok(identities)
        })
    }

    /// Verify all signatures against explicit caller-selected targets and keys.
    ///
    /// Requests are not policy: they cannot permit algorithms, URI classes or
    /// XML features forbidden by the immutable policy snapshot.
    ///
    /// # Errors
    /// Returns invalid request identities/requirements, document provenance,
    /// policy or aggregate resource failures. Individual failures remain evidence.
    pub fn verify_request(
        &self,
        document: &XmlDocument,
        request: &VerificationRequest<'_>,
    ) -> Result<VerifyEvidence, DsigError> {
        verify_all_document(document, self, request)
    }
}

/// Application requirement for the independently verified signatures.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SignatureRequirement {
    /// Every discovered signature must pass, and at least one must exist.
    #[default]
    All,
    /// Explicitly tolerate other invalid signatures if this many pass.
    AtLeast(usize),
    /// Require exactly this many discovered signatures, all passing.
    Exactly(usize),
}

/// Explicit key authorization for one stable, caller-selected Signature.
pub struct CallerTrustedSignatureKey<'a> {
    /// Signature that this key is authorized to verify.
    pub signature: NodeIdentity,
    /// Application-owned key; embedded `KeyInfo` cannot override it.
    pub key: &'a dyn VerifyingKey,
}

/// Request data, immutably borrowed for one verification operation.
#[derive(Default)]
pub struct VerificationRequest<'a> {
    /// Elements whose complete expanded content must be authenticated.
    /// Comments and an enveloped Signature are not part of this assertion.
    pub expected_targets: &'a [NodeIdentity],
    /// Per-signature trusted keys. Duplicate/foreign/stale mappings fail closed.
    pub trusted_keys: &'a [CallerTrustedSignatureKey<'a>],
    /// Explicit external bytes; no implicit I/O or configuration discovery.
    pub external_resources: Option<&'a HashMap<String, Vec<u8>>>,
    /// Required multi-signature outcome; zero counts are invalid requests.
    pub signatures: SignatureRequirement,
    /// Opaque caller correlation value, never read from XML or used as trust.
    pub correlation: Option<[u8; 16]>,
}

/// Outcome for one exact Signature, including pipeline failures.
#[derive(Debug)]
pub struct SignatureEvidence {
    identity: NodeIdentity,
    result: Result<VerifyResult, DsigError>,
}

impl SignatureEvidence {
    /// Stable identity of the Signature actually processed.
    #[must_use]
    pub const fn identity(&self) -> NodeIdentity {
        self.identity
    }

    /// Individual outcome. Digest matches do not imply signature validity.
    pub const fn result(&self) -> &Result<VerifyResult, DsigError> {
        &self.result
    }
}

/// Bounded outcomes for all signatures in one document generation.
#[derive(Debug)]
#[must_use = "inspect the individual outcomes before accepting the document"]
pub struct VerifyEvidence<V = Vec<SignatureEvidence>> {
    document: NodeIdentity,
    signatures: V,
    accepted: bool,
    correlation: Option<[u8; 16]>,
}

impl<V: std::ops::Deref<Target = [SignatureEvidence]>> VerifyEvidence<V> {
    /// Whether the explicit request requirements hold for this document.
    /// Foreign documents or any mutation after verification invalidate acceptance.
    ///
    /// # Errors
    /// Returns the document identity/generation refusal for stale or foreign evidence.
    pub fn accepted(&self, document: &XmlDocument) -> Result<bool, DsigError> {
        document.with_view(|view| {
            view.resolve_node(self.document)?;
            Ok(self.accepted)
        })
    }

    /// Uninterpreted correlation value supplied by the caller.
    #[must_use]
    pub const fn correlation(&self) -> Option<[u8; 16]> {
        self.correlation
    }

    /// Prove complete expanded element content under an authorized signature.
    ///
    /// This does not claim source-byte equality, comment coverage or protection
    /// of the owning enveloped Signature. Arbitrary XPath/binary transforms
    /// remain indeterminate rather than falsely covering their original input.
    /// The exact document generation must still exist; wrapping an unsigned
    /// sibling with a matching name cannot satisfy an identity-based assertion.
    ///
    /// # Errors
    /// Returns stale/foreign evidence or target identities, or an invalid
    /// request when the target is not an element.
    pub fn covers_element(
        &self,
        document: &XmlDocument,
        target: NodeIdentity,
    ) -> Result<bool, DsigError> {
        document.with_view(|view| self.covers_element_in(view, target))
    }

    fn covers_element_in(
        &self,
        view: DocumentView<'_>,
        target: NodeIdentity,
    ) -> Result<bool, DsigError> {
        view.resolve_node(self.document)?;
        let target_node = view.resolve_node(target)?;
        if !target_node.is_element() {
            return Err(DsigError::InvalidRequest {
                reason: "coverage target must be an element",
            });
        }
        let target_id = target_node.id().get();
        for signature in self.signatures() {
            let Ok(result) = &signature.result else {
                continue;
            };
            if result.status != DsigStatus::Valid
                || !matches!(
                    result.key_trust,
                    super::KeyTrustEvidence::CallerTrusted
                        | super::KeyTrustEvidence::ValidatedX509(_)
                )
            {
                continue;
            }
            let signature_node = view.resolve_node(signature.identity)?;
            for reference in result
                .signed_info_references
                .iter()
                .chain(&result.manifest_references)
            {
                if reference.status != DsigStatus::Valid {
                    continue;
                }
                let Some(root) = reference.target_identity else {
                    continue;
                };
                if reference.coverage == ReferenceCoverage::TransformedData {
                    continue;
                }
                let root = view.resolve_node(root)?;
                // The normalized arena assigns contiguous preorder IDs;
                // reuse the same subtree contract as node-set subtraction,
                // rather than walking depth for every report/target pair.
                if !subtree_node_id_range(root).contains(&target_id) {
                    continue;
                }
                if reference.coverage == ReferenceCoverage::EnvelopedElementContent
                    && subtree_node_id_range(signature_node).contains(&target_id)
                {
                    continue;
                }
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Outcomes in document order, including malformed signatures.
    #[must_use]
    pub fn signatures(&self) -> &[SignatureEvidence] {
        &self.signatures
    }

    /// Whether a nonempty set of signatures and their processed Manifests passed.
    ///
    /// This is a historical mathematical outcome, not current-document
    /// authorization. Use `accepted(document)` for generation-bound acceptance.
    #[must_use]
    pub fn all_valid(&self) -> bool {
        !self.signatures.is_empty()
            && self.signatures.iter().all(|entry| {
                entry.result.as_ref().is_ok_and(|result| {
                    result.status == DsigStatus::Valid
                        && result
                            .manifest_references
                            .iter()
                            .all(|reference| reference.status == DsigStatus::Valid)
                })
            })
    }
}

impl Default for VerifyContext<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-reference verification result.
#[derive(Debug, Clone)]
#[non_exhaustive]
#[must_use = "inspect status before accepting the reference result"]
pub struct ReferenceResult {
    /// Exact Reference node when processing a retained document.
    pub reference_identity: Option<NodeIdentity>,
    /// Resolved same-document target, not an untrusted URI claim.
    pub target_identity: Option<NodeIdentity>,
    /// SHA-256 identity of resolved external bytes before transforms. This is
    /// provenance, not signer authorization or an original-element proof.
    pub external_resource_fingerprint: Option<[u8; 32]>,
    /// How the bytes of an external Reference reached this result; `None` for
    /// a same-document Reference or one without completed external bytes.
    pub external_payload: Option<ExternalPayload>,
    /// What can be proven about original element-content coverage.
    pub coverage: ReferenceCoverage,
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

/// Provenance of an external Reference's bytes. A report must not present an
/// attested digest as bytes this library hashed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExternalPayload {
    /// Resident bytes from the caller's external resource map.
    Resident,
    /// Bytes the caller streamed through a verified session and the selected
    /// provider digested; `external_resource_fingerprint` covers them.
    Streamed,
    /// A digest the caller computed over the payload it paired with this
    /// Reference. No byte passed through this library.
    Attested,
}

/// Conservative coverage classification for the original semantic document.
///
/// `XMLDSig` 1.1 §8.1.1 protects only transformed data. Unknown projection is
/// deliberately not promoted to complete original-element coverage.
/// <https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-Signed>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReferenceCoverage {
    /// No complete original-element coverage proof (binary or arbitrary filter).
    TransformedData,
    /// Expanded element names, attributes and content, excluding comments.
    ElementContent,
    /// Element content except the owning Signature subtree and comments.
    EnvelopedElementContent,
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
    /// A `<Reference>` was not dereferenced or transformed because the
    /// signature over `<SignedInfo>` did not verify. Never an overall status.
    NotProcessed,
}

/// Why `XMLDSig` verification failed.
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
    /// External `<Reference>` whose bytes the caller has not supplied.
    ReferenceUnavailable {
        /// Zero-based index of the unavailable `<Reference>` in its processed set.
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
    /// Per-reference results, one per `<Reference>` in order.
    pub results: Vec<ReferenceResult>,
    /// Index of the first reference that did not pass, if any.
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
/// Digest mismatch is NOT an error; it produces
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
        transform_options: TransformOptions::default().id_attributes(resolver.id_registrations()),
        transform_budget: &execution_budget,
        canonicalized_data_budget: &canonicalized_data_budget,
        provider: crate::provider::default_provider(),
        capture: &(),
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

fn bind_reference_evidence(
    result: &mut ReferenceResult,
    reference: &Reference,
    view: DocumentView<'_>,
    origin: Option<Node<'_, '_>>,
    observed: &OperationResourceIdentity,
) {
    result.reference_identity = origin.map(|node| view.node_identity(node));
    if let OperationResourceIdentity::External { fingerprint, .. } = observed {
        result.external_resource_fingerprint = Some(*fingerprint);
        result.external_payload = Some(ExternalPayload::Resident);
    }
    if let OperationResourceIdentity::DocumentNode(target) = observed {
        result.target_identity = Some(*target);
        // A later node-set transform can reparse C14N output, so arbitrary
        // chains cannot retain an original subtree claim. This classification
        // describes proven element content, never discarded comments or the
        // namespace-declaration spelling normalized by canonicalization.
        let mut enveloped = false;
        let mut canonicalized = false;
        for transform in &reference.transforms {
            match transform {
                Transform::C14n(_) if !canonicalized => canonicalized = true,
                Transform::Enveloped if !canonicalized => enveloped = true,
                _ => return,
            }
        }
        result.coverage = if enveloped {
            ReferenceCoverage::EnvelopedElementContent
        } else {
            ReferenceCoverage::ElementContent
        };
    }
}

struct ReferenceExecutionContext<'a, C = ()> {
    store_pre_digest: bool,
    transform_options: TransformOptions<'a>,
    transform_budget: &'a TransformExecutionBudget,
    canonicalized_data_budget: &'a CanonicalizedDataBudget,
    provider: &'a dyn crate::provider::CryptoProvider,
    capture: &'a C,
}

struct CanonicalizedDataBudget {
    remaining: Cell<usize>,
    max_bytes: usize,
}

struct VerificationOperationBudgets<'a> {
    key_info_parse: RefCell<super::parse::KeyInfoParseUsage>,
    key_candidates: RefCell<super::InspectedKeyCandidateBudget<'a>>,
    key_establishment: RefCell<crate::key_establishment::KeyEstablishmentUsage>,
    transforms: TransformExecutionBudget,
    canonicalized: CanonicalizedDataBudget,
    xpath_parse: RefCell<XPathSignatureParseBudget>,
    key_info_materialization: RefCell<KeyInfoMaterializationState>,
    external_resource_identities: RefCell<HashMap<String, OperationResourceIdentity>>,
    resolved_reference_resources: RefCell<HashMap<NodeId, OperationResourceIdentity>>,
    external_resource_set_identity: RefCell<Option<OperationResourceIdentity>>,
}

impl<'a> VerificationOperationBudgets<'a> {
    fn with_transforms(
        policy: &crate::policy::VerificationPolicy,
        transforms: TransformExecutionBudget,
        utc_facts: Option<structured_pkix::temporal::LeapTable<'a>>,
    ) -> Self {
        let key_info_parse = super::parse::KeyInfoParseUsage::new(&policy.resources);
        let key_candidates = super::InspectedKeyCandidateBudget::with_ingestion(
            policy,
            &key_info_parse.certificates,
            utc_facts,
        );
        let xpath_parse = XPathSignatureParseBudget::for_execution(&policy.resources, &transforms);
        Self {
            key_info_parse: RefCell::new(key_info_parse),
            key_candidates: RefCell::new(key_candidates),
            key_establishment: RefCell::default(),
            transforms,
            canonicalized: CanonicalizedDataBudget::with_limit(
                policy.resources.effective_canonicalized_bytes(),
            ),
            xpath_parse: RefCell::new(xpath_parse),
            key_info_materialization: RefCell::new(KeyInfoMaterializationState::default()),
            external_resource_identities: RefCell::new(HashMap::new()),
            resolved_reference_resources: RefCell::new(HashMap::new()),
            external_resource_set_identity: RefCell::new(None),
        }
    }

    fn external_resource_set_identity(
        &self,
        resolver: &UriReferenceResolver<'_>,
    ) -> OperationResourceIdentity {
        // One resolver borrows the same immutable map for the entire request.
        // Hash/sort it once, not once per graph node or Signature.
        let mut cached = self.external_resource_set_identity.borrow_mut();
        cached
            .get_or_insert_with(|| resolver.external_resource_set_identity())
            .clone()
    }

    fn resource_identity_for_reference(
        &self,
        reference: &Reference,
        index: usize,
        resolver: &UriReferenceResolver<'_>,
        view: DocumentView<'_>,
        origin: Option<Node<'_, '_>>,
    ) -> OperationResourceIdentity {
        let Some(uri) = reference.uri.as_deref() else {
            return OperationResourceIdentity::Generated("omitted-reference", index);
        };
        if uri.is_empty() || uri.starts_with('#') {
            return resolver
                .node_id_for_reference_resource(
                    uri,
                    Some(self.transforms.node_set_materialization()),
                )
                .ok()
                .flatten()
                .map(|node| OperationResourceIdentity::DocumentNode(view.node_identity_by_id(node)))
                .unwrap_or(OperationResourceIdentity::Generated(
                    "missing-document-reference",
                    index,
                ));
        }

        let resolved_uri;
        let uri = if let Some(origin) = origin {
            if let Some(identity) = self.resolved_reference_resources.borrow().get(&origin.id()) {
                return identity.clone();
            }
            // XML Base Second Edition §4.2 resolves the external reference in
            // its owning element's context. Identity and execution must agree.
            // https://www.w3.org/TR/2009/REC-xmlbase-20090128/#resolving
            let Ok(absolute_uri) = crate::c14n::xml_base::resolve_uri_from_node_with_budget(
                origin,
                uri,
                self.transforms.xml_base_resolution(),
            ) else {
                return OperationResourceIdentity::Generated(
                    "unresolved-external-reference",
                    index,
                );
            };
            resolved_uri = absolute_uri;
            resolved_uri.as_str()
        } else {
            uri
        };
        if let Some(identity) = self.external_resource_identities.borrow().get(uri).cloned() {
            if let Some(origin) = origin {
                self.resolved_reference_resources
                    .borrow_mut()
                    .insert(origin.id(), identity.clone());
            }
            return identity;
        }
        let identity = resolver
            .external_resource_identity(uri)
            .unwrap_or(OperationResourceIdentity::MissingExternal);
        if matches!(identity, OperationResourceIdentity::External { .. }) {
            self.external_resource_identities
                .borrow_mut()
                .insert(uri.to_owned(), identity.clone());
        }
        if let Some(origin) = origin {
            self.resolved_reference_resources
                .borrow_mut()
                .insert(origin.id(), identity.clone());
        }
        identity
    }
}

struct VerificationPlanNodes {
    document: OperationNodeId,
    key_materialization: OperationNodeId,
    key: OperationNodeId,
    canonicalization: OperationNodeId,
    crypto: OperationNodeId,
}

/// Plan `SignedInfo` authentication only. Reference digests are added after the
/// signature verifies, as dependencies of the accepted crypto node (W3C XML
/// Signature Best Practices BP1): their URIs are not resolved before that.
/// <https://www.w3.org/TR/xmldsig-bestpractices/#bp-authenticate-signature-first>
fn compile_verification_operation_plan(
    operation: &mut OperationExecutionContext<
        &crate::policy::VerificationPolicy,
        &VerificationOperationBudgets,
    >,
    view: DocumentView<'_>,
    signature_node: Node<'_, '_>,
    resolver: &UriReferenceResolver<'_>,
) -> Result<VerificationPlanNodes, SignatureVerificationPipelineError> {
    operation
        .validate_document_view(view)
        .map_err(map_verification_plan_error)?;
    let document_node = operation.add_node(
        OperationNodeKind::Document,
        OperationStage::Parse,
        Some(OperationResourceIdentity::DocumentNode(
            view.node_identity(signature_node),
        )),
    );
    let key_materialization_resource = operation.budgets().external_resource_set_identity(resolver);
    let key_materialization = operation.add_node(
        OperationNodeKind::Key { index: 0 },
        OperationStage::Resolve,
        Some(key_materialization_resource.clone()),
    );
    let key_node = operation.add_node(
        OperationNodeKind::Key { index: 1 },
        OperationStage::Resolve,
        None,
    );
    operation
        .add_dependency(key_materialization, document_node)
        .map_err(map_verification_plan_error)?;
    operation
        .add_dependency(key_node, key_materialization)
        .map_err(map_verification_plan_error)?;
    let canonicalization = operation.add_node(
        OperationNodeKind::Canonicalization,
        OperationStage::Canonicalization,
        None,
    );
    operation
        .add_dependency(canonicalization, document_node)
        .map_err(map_verification_plan_error)?;
    let crypto = operation.add_node(OperationNodeKind::Crypto, OperationStage::Crypto, None);
    operation
        .add_dependency(crypto, key_node)
        .map_err(map_verification_plan_error)?;
    operation
        .add_dependency(crypto, canonicalization)
        .map_err(map_verification_plan_error)?;
    operation.compile().map_err(map_verification_plan_error)?;
    Ok(VerificationPlanNodes {
        document: document_node,
        key_materialization,
        key: key_node,
        canonicalization,
        crypto,
    })
}

fn map_verification_plan_error(error: OperationPlanError) -> SignatureVerificationPipelineError {
    SignatureVerificationPipelineError::OperationPlan(error.to_string())
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

fn process_reference_with_options<C: VerificationCapture>(
    reference: &Reference,
    resolver: &UriReferenceResolver<'_>,
    signature_node: Node<'_, '_>,
    reference_set: ReferenceSet,
    reference_index: usize,
    reference_node: Option<Node<'_, '_>>,
    execution: &ReferenceExecutionContext<'_, C>,
) -> Result<ReferenceResult, ReferenceProcessingError> {
    execution
        .capture
        .admit_digest(reference_node.map(Node::id), reference.digest_method)?;
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
    let source = reference_node.unwrap_or(signature_node);
    let containing_signature =
        super::transforms::enveloped_signature_for_reference(source, &reference.transforms, || {
            execution.transform_budget.charge_node_filter_work(1)
        })
        .map_err(ReferenceProcessingError::Transform)?;
    // 3. Compute the digest while the final transform output is produced;
    // its bytes are retained only when the caller asked for them.
    let super::transforms::ReferenceDigest {
        digest: computed_digest,
        pre_digest,
    } = super::transforms::digest_reference_transforms_with_budget(
        source,
        containing_signature,
        initial_data,
        &reference.transforms,
        execution.transform_options,
        execution.transform_budget,
        execution.transform_budget.xml_parse_work(),
        super::transforms::DigestRequest {
            provider: execution.provider,
            algorithm: reference.digest_method,
            retain_pre_digest: execution.store_pre_digest,
        },
    )
    .map_err(|error| match error {
        super::transforms::ReferenceDigestError::Transform(error) => {
            ReferenceProcessingError::Transform(error)
        }
        super::transforms::ReferenceDigestError::Provider(error) => error.into(),
    })?;
    execution
        .capture
        .computed_digest(reference_node.map(Node::id))?;

    // 4. Compare with stored DigestValue (constant-time)
    let status = if constant_time_eq(&computed_digest, &reference.digest_value) {
        DsigStatus::Valid
    } else {
        DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch {
            ref_index: reference_index,
        })
    };

    let pre_digest_data = match pre_digest {
        Some(bytes) => {
            execution.canonicalized_data_budget.charge(bytes.len())?;
            Some(bytes)
        }
        None => None,
    };

    Ok(ReferenceResult {
        reference_identity: None,
        target_identity: None,
        external_resource_fingerprint: None,
        external_payload: None,
        coverage: ReferenceCoverage::TransformedData,
        reference_set,
        reference_index,
        uri: uri.to_owned(),
        digest_algorithm: reference.digest_method,
        status,
        pre_digest_data,
    })
}

/// Process every `<Reference>` element in a `<SignedInfo>`, each with its own
/// result (`XMLDSig` 1.1 §3.2.1).
///
/// A digest mismatch, a policy violation, an unavailable external resource
/// and a URI/transform failure are per-reference results;
/// `ReferencesResult::first_failure` names the first of them. This does not
/// verify `SignatureValue`: callers verifying a signature must authenticate
/// `SignedInfo` before trusting these instructions.
///
/// # Errors
///
/// Returns `Err` for a resource refusal or provider failure, which stops all
/// remaining references.
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
        transform_options: TransformOptions::default().id_attributes(resolver.id_registrations()),
        transform_budget: &execution_budget,
        canonicalized_data_budget: &canonicalized_data_budget,
        provider: crate::provider::default_provider(),
        capture: &(),
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
    let mut first_failure = None;
    for (i, reference) in references.iter().enumerate() {
        let result = process_reference_with_options(
            reference,
            resolver,
            signature_node,
            ReferenceSet::SignedInfo,
            i,
            reference_origin_node(signature_node, ReferenceSet::SignedInfo, i),
            execution,
        )
        .or_else(|error| {
            let reason = error.into_reference_failure(i)?;
            Ok::<_, ReferenceProcessingError>(reference_failure_result(
                reference,
                ReferenceSet::SignedInfo,
                i,
                DsigStatus::Invalid(reason),
            ))
        })?;
        if result.status != DsigStatus::Valid && first_failure.is_none() {
            first_failure = Some(i);
        }
        results.push(result);
    }
    Ok(ReferencesResult {
        results,
        first_failure,
    })
}

/// Result of a `<Reference>` that produced no digest, before evidence binding.
fn reference_failure_result(
    reference: &Reference,
    reference_set: ReferenceSet,
    reference_index: usize,
    status: DsigStatus,
) -> ReferenceResult {
    ReferenceResult {
        reference_identity: None,
        target_identity: None,
        external_resource_fingerprint: None,
        external_payload: None,
        coverage: ReferenceCoverage::TransformedData,
        reference_set,
        reference_index,
        uri: reference
            .uri
            .clone()
            .unwrap_or_else(|| "<omitted>".to_owned()),
        digest_algorithm: reference.digest_method,
        status,
        pre_digest_data: None,
    }
}

/// Errors during reference processing.
///
/// Distinct from digest mismatch (which is a validation result, not a processing error).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReferenceProcessingError {
    /// The current shared execution refused original digest-receipt retention.
    #[error("shared reference execution: {0}")]
    SharedExecution(#[from] structured_asn1::memory::MemoryError),
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

impl ReferenceProcessingError {
    fn into_policy_violation(self) -> Result<crate::policy::PolicyViolation, Self> {
        match self {
            Self::Policy(error)
            | Self::UriDereference(TransformError::Policy(error))
            | Self::Transform(TransformError::Policy(error)) => Ok(error),
            error => Err(error),
        }
    }

    /// `Ok` is this Reference's own outcome (`XMLDSig` 1.1 §3.2.1 validates each
    /// Reference independently); `Err` stays terminal for the whole operation.
    fn into_reference_failure(self, ref_index: usize) -> Result<FailureReason, Self> {
        use crate::policy::PolicyViolation;
        match self {
            // Every Reference draws on the same operation budgets, so a later
            // result after an exhausted budget would be a refusal, not a finding.
            Self::Policy(PolicyViolation::ResourceLimit { .. })
            | Self::UriDereference(TransformError::Policy(PolicyViolation::ResourceLimit {
                ..
            }))
            | Self::Transform(TransformError::Policy(PolicyViolation::ResourceLimit { .. }))
            | Self::SharedExecution(_)
            | Self::Provider(_) => Err(self),
            Self::Policy(_)
            | Self::UriDereference(TransformError::Policy(_))
            | Self::Transform(TransformError::Policy(_)) => {
                Ok(FailureReason::ReferencePolicyViolation { ref_index })
            }
            Self::UriDereference(TransformError::ExternalResourceUnavailable(_)) => {
                Ok(FailureReason::ReferenceUnavailable { ref_index })
            }
            Self::MissingUri => Ok(FailureReason::ReferenceProcessingFailure { ref_index }),
            Self::UriDereference(error) | Self::Transform(error)
                if is_reference_local_transform_error(&error) =>
            {
                Ok(FailureReason::ReferenceProcessingFailure { ref_index })
            }
            error => Err(error),
        }
    }
}

/// Failures determined by one Reference's own URI, transforms or content.
/// Anything else, including stringly typed XSLT errors that can carry work
/// exhaustion, stays terminal.
fn is_reference_local_transform_error(error: &TransformError) -> bool {
    use crate::c14n::C14nError;
    use crate::document::XmlDocumentError;
    use crate::encoding::XmlEncodingError;
    // Undecodable content belongs to its Reference; only the decoded-size
    // ceiling is a resource refusal and stays terminal.
    if let TransformError::XmlParse(XmlDocumentError::Encoding(encoding)) = error {
        return !matches!(encoding, XmlEncodingError::DecodedLimit { .. });
    }
    if let TransformError::AccountedXmlEncoding(encoding) = error {
        return !matches!(encoding, XmlEncodingError::DecodedLimit { .. });
    }
    matches!(
        error,
        TransformError::TypeMismatch { .. }
            | TransformError::ElementNotFound(_)
            | TransformError::AccountedElementNotFound(_)
            | TransformError::UnsupportedUri(_)
            | TransformError::AccountedUnsupportedUri(_)
            | TransformError::InvalidFragment
            | TransformError::UnsupportedTransform(_)
            | TransformError::AccountedUnsupportedTransform(_)
            | TransformError::Base64(_)
            | TransformError::XPath(_)
            | TransformError::AccountedXPath(_)
            | TransformError::Relationship(_)
            | TransformError::CrossDocumentSignatureNode
            | TransformError::CrossDocumentNodeSetInput
            | TransformError::C14n(
                C14nError::Parse(_)
                    | C14nError::InvalidNode
                    | C14nError::RelativeNamespace
                    | C14nError::UnsupportedAlgorithm(_)
            )
            | TransformError::XmlParse(XmlDocumentError::Parse(_))
    )
}

/// End-to-end `XMLDSig` verification result for one `<Signature>`.
#[derive(Debug)]
#[non_exhaustive]
#[must_use = "inspect status before accepting the document"]
pub struct VerifyResult {
    /// Key authorization, independent of `status`; neither alone authorizes data.
    pub key_trust: super::KeyTrustEvidence,
    /// Core `XMLDSig` status for the `<SignedInfo>` references and signature value.
    ///
    /// Manifest reference failures do not alter this field; inspect
    /// [`Self::manifest_references`] before accepting Manifest-backed data.
    pub status: DsigStatus,
    /// One result per `<SignedInfo>` `<Reference>`, in order. Each Reference
    /// has its own outcome once `SignatureValue` verifies; before that, none
    /// is dereferenced and each reports [`DsigStatus::NotProcessed`].
    pub signed_info_references: Vec<ReferenceResult>,
    /// `<Manifest>` reference results.
    /// Populated only when `VerifyContext::process_manifests(true)` is enabled
    /// and core signature validation succeeds.
    /// Includes references whose original Manifest or ancestor is authenticated
    /// by this Signature's structure-preserving references. Manifests may be
    /// nested or outside Signature; DOM ancestry alone never authenticates them.
    /// Each entry has an independent status that does not alter [`Self::status`].
    /// Callers must inspect every entry before accepting Manifest-backed data.
    /// Unsigned/unreferenced Manifest blocks are skipped, so an
    /// empty list does not imply that no Manifest elements existed in `verify()` input.
    pub manifest_references: Vec<ReferenceResult>,
    /// Canonicalized `<SignedInfo>` bytes when `store_pre_digest` is enabled
    /// and verification reaches `SignedInfo` canonicalization.
    pub canonicalized_signed_info: Option<Vec<u8>>,
}

/// Errors while running end-to-end `XMLDSig` verification.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DsigError {
    /// The current shared execution refused work or storage admission.
    #[error("shared verification execution: {0}")]
    SharedExecution(#[from] structured_asn1::memory::MemoryError),
    /// Key establishment failed before the consuming MAC.
    #[error(transparent)]
    KeyEstablishment(#[from] crate::key_establishment::KeyEstablishmentError),
    /// Caller-supplied request identities or requirements are inconsistent.
    #[error("invalid verification request: {reason}")]
    InvalidRequest {
        /// Concrete invariant violated before signature execution.
        reason: &'static str,
    },
    /// The compiled verification policy rejected an operation input.
    #[error("verification policy violation: {0}")]
    Policy(#[from] crate::policy::PolicyViolation),

    /// A query-funded algorithm rejection; the URI retains its charge until drop.
    #[error("verification policy violation: {operation} policy rejects algorithm {algorithm}")]
    AccountedPolicyAlgorithm {
        /// Operation evaluating the algorithm.
        operation: &'static str,
        /// Rejected algorithm URI, owned by the current query's account.
        algorithm: structured_asn1::memory::OwnedText,
    },

    /// The selected provider cannot execute the requested operation.
    #[error("cryptographic provider error: {0}")]
    Provider(#[from] crate::provider::ProviderError),

    /// XML parsing failed.
    #[error("XML parse error: {0}")]
    XmlParse(#[from] crate::xml::dom::ParseError),

    /// The owned XML document boundary rejected the document or identity.
    #[error("XML document error: {0}")]
    Document(#[from] crate::document::XmlDocumentError),

    /// Required signature element is missing.
    #[error("missing required element: <{element}>")]
    MissingElement {
        /// Name of the missing element.
        element: &'static str,
    },

    /// Signature element tree shape violates `XMLDSig` structure requirements.
    #[error("invalid Signature structure: {reason}")]
    InvalidStructure {
        /// Validation failure reason.
        reason: &'static str,
    },

    /// The authenticated dependency graph could not be compiled or executed.
    #[error("invalid operation plan: {0}")]
    OperationPlan(String),

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

    /// `SignedInfo` canonicalization failed.
    #[error("SignedInfo canonicalization failed: {0}")]
    Canonicalization(#[from] crate::c14n::C14nError),

    /// `SignatureValue` base64 decoding failed.
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
        match error.into_policy_violation() {
            Ok(error) => Self::Policy(error),
            Err(error) => Self::Reference(error),
        }
    }
}

type SignatureVerificationPipelineError = DsigError;

impl From<OperationPlanError> for DsigError {
    fn from(error: OperationPlanError) -> Self {
        Self::OperationPlan(error.to_string())
    }
}

/// Verify one `XMLDSig` `<Signature>` end-to-end with a PEM public key.
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
/// - The document must contain exactly one `XMLDSig` `<Signature>` element.
/// - `<SignedInfo>` must be the first element child of `<Signature>` and appear once.
/// - `<SignatureValue>` must be the second element child of `<Signature>` and appear once.
/// - `<KeyInfo>` is optional and, when present, must be the third element child.
/// - Only `XMLDSig` namespace element children are allowed under `<Signature>`.
/// - Non-whitespace mixed text content under `<Signature>` is rejected.
/// - After `<SignedInfo>`, `<SignatureValue>`, and optional `<KeyInfo>`, only `<Object>` elements are allowed.
/// - `<SignatureValue>` must not contain nested element children.
///
/// # Errors
/// Returns an error for invalid XML, signature structure, key encoding, denied
/// algorithms, resource exhaustion, or reference-processing failures.
pub fn verify_signature_with_pem_key(
    xml: &str,
    public_key_pem: &str,
    store_pre_digest: bool,
) -> Result<VerifyResult, DsigError> {
    struct PemVerifyingKey<'a> {
        public_key_pem: &'a str,
    }

    impl VerifyingKey for PemVerifyingKey<'_> {
        fn verify_with_context(
            &self,
            algorithm: SignatureAlgorithm,
            context: &super::SignatureContext,
            signed_data: &[u8],
            signature_value: &[u8],
        ) -> Result<bool, DsigError> {
            if context.as_bytes().is_empty() {
                return self.verify(algorithm, signed_data, signature_value);
            }
            if algorithm.context_element().is_none() {
                return Err(SignatureVerificationError::UnsupportedAlgorithm {
                    uri: algorithm.uri().to_owned(),
                }
                .into());
            }
            let pem = super::signature::PemBlock::decode(self.public_key_pem)
                .filter(|pem| pem.label == "PUBLIC KEY")
                .ok_or(SignatureVerificationError::InvalidKeyPem)?;
            // Like any opaque caller key, this PEM key reads its own material.
            Ok(super::modern::verify_with_context(
                algorithm,
                &pem.contents,
                context,
                signed_data,
                signature_value,
                &super::pkix::CertificateSession::standalone(),
            )?)
        }

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
    ctx.policy.signature_constraints.require_targets(false)?;
    ctx.policy.resources.validate_xml_document_len(xml.len())?;
    let execution_budget = TransformExecutionBudget::from_resources(&ctx.policy.resources)
        .with_xml_backend(ctx.xml_backend);
    let settings = DocumentParseSettings::from_policy(ctx.policy.xml, &ctx.policy.resources)
        .with_backend(ctx.xml_backend);
    let document = XmlDocument::parse_with_settings_and_budget(
        xml.to_owned(),
        settings,
        execution_budget.xml_parse_work(),
    )
    .map_err(|error| map_document_parse_error(error, settings))?;
    verify_signature_document_with_context_and_transforms(&document, ctx, execution_budget)
}

fn map_document_parse_error(error: XmlDocumentError, settings: DocumentParseSettings) -> DsigError {
    match error.into_policy_violation(settings) {
        Ok(error) => DsigError::Policy(error),
        Err(XmlDocumentError::Parse(error)) => DsigError::XmlParse(error),
        Err(error) => DsigError::Document(error),
    }
}

#[cfg(test)]
mod xml_parse_budget_tests;

fn verify_signature_document_with_context(
    document: &XmlDocument,
    ctx: &VerifyContext<'_>,
) -> Result<VerifyResult, SignatureVerificationPipelineError> {
    document.validate_operation_policy(ctx.policy.xml, &ctx.policy.resources)?;
    verify_signature_document_with_context_and_transforms(
        document,
        ctx,
        TransformExecutionBudget::from_resources(&ctx.policy.resources)
            .with_xml_backend(ctx.xml_backend),
    )
}

fn count_signature_nodes(view: DocumentView<'_>, maximum: usize) -> Result<usize, DsigError> {
    let mut count = 0;
    for node in view.document().descendants() {
        if !node.has_tag_name((XMLDSIG_NS, "Signature")) {
            continue;
        }
        if count == maximum {
            return Err(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::VERIFICATION_SIGNATURES,
                maximum,
                actual: count + 1,
            }
            .into());
        }
        count += 1;
    }
    Ok(count)
}

trait SignatureBuffer: std::ops::Deref<Target = [SignatureEvidence]> {
    fn push_signature(
        &mut self,
        evidence: SignatureEvidence,
    ) -> Result<(), structured_asn1::memory::MemoryError>;
}

impl SignatureBuffer for Vec<SignatureEvidence> {
    fn push_signature(
        &mut self,
        evidence: SignatureEvidence,
    ) -> Result<(), structured_asn1::memory::MemoryError> {
        self.push(evidence);
        Ok(())
    }
}

impl<W: structured_asn1::memory::Work> SignatureBuffer
    for structured_asn1::memory::OwnedVec<SignatureEvidence, W>
{
    fn push_signature(
        &mut self,
        evidence: SignatureEvidence,
    ) -> Result<(), structured_asn1::memory::MemoryError> {
        self.try_push(evidence)
    }
}

trait OperationRetention<P, B, C> {
    fn retain(
        &mut self,
        operation: OperationExecutionContext<P, B>,
        capture: C,
    ) -> Result<(), structured_asn1::memory::MemoryError>;
}

impl<P, B, C> OperationRetention<P, B, C> for () {
    fn retain(
        &mut self,
        operation: OperationExecutionContext<P, B>,
        _capture: C,
    ) -> Result<(), structured_asn1::memory::MemoryError> {
        drop(operation);
        Ok(())
    }
}

impl<P, B, C, W: structured_asn1::memory::Work> OperationRetention<P, B, C>
    for structured_asn1::memory::OwnedVec<CapturedOperation<P, B, C>, W>
{
    fn retain(
        &mut self,
        operation: OperationExecutionContext<P, B>,
        capture: C,
    ) -> Result<(), structured_asn1::memory::MemoryError> {
        self.try_push(CapturedOperation { operation, capture })
    }
}

trait RequestStorage {
    type Signatures: SignatureBuffer;
    type Capture: VerificationCapture;
    // Actual reference types preserve their lifetimes without the implied
    // 'static bound of a lifetime-GAT projection under the scoped callback.
    type Operations<P, B>: OperationRetention<P, B, Self::Capture>;

    fn capture(&self) -> Self::Capture;

    fn admit_request(
        &self,
        document: &XmlDocument,
    ) -> Result<(), structured_asn1::memory::MemoryError>;
    fn signatures(
        &self,
        count: usize,
    ) -> Result<Self::Signatures, structured_asn1::memory::MemoryError>;
    fn operations<P, B>(
        &self,
        count: usize,
    ) -> Result<Self::Operations<P, B>, structured_asn1::memory::MemoryError>;
}

struct CollectedRequestStorage;

impl RequestStorage for CollectedRequestStorage {
    type Signatures = Vec<SignatureEvidence>;
    type Capture = ();
    type Operations<P, B> = ();

    fn capture(&self) {}

    fn admit_request(
        &self,
        _document: &XmlDocument,
    ) -> Result<(), structured_asn1::memory::MemoryError> {
        Ok(())
    }
    fn signatures(
        &self,
        count: usize,
    ) -> Result<Self::Signatures, structured_asn1::memory::MemoryError> {
        Ok(Vec::with_capacity(count))
    }
    fn operations<P, B>(
        &self,
        _count: usize,
    ) -> Result<Self::Operations<P, B>, structured_asn1::memory::MemoryError> {
        Ok(())
    }
}

struct ScopedRequestStorage<'work, W: structured_asn1::memory::Work>(&'work W);

impl<'work, W: structured_asn1::memory::Work> RequestStorage for ScopedRequestStorage<'work, W> {
    type Signatures = structured_asn1::memory::OwnedVec<SignatureEvidence, W>;
    type Capture = ScopedCapture<'work, W>;
    type Operations<P, B> =
        structured_asn1::memory::OwnedVec<CapturedOperation<P, B, ScopedCapture<'work, W>>, W>;

    fn capture(&self) -> Self::Capture {
        ScopedCapture::new(self.0)
    }

    fn admit_request(
        &self,
        document: &XmlDocument,
    ) -> Result<(), structured_asn1::memory::MemoryError> {
        let units = document
            .with_view(|view| {
                u64::try_from(view.node_count())
                    .ok()
                    .and_then(|count| count.checked_mul(2))
                    .and_then(|count| count.checked_add(1))
            })
            .ok_or(structured_asn1::memory::MemoryError::WorkExceeded)?;
        self.0.charge_work(units)
    }
    fn signatures(
        &self,
        count: usize,
    ) -> Result<Self::Signatures, structured_asn1::memory::MemoryError> {
        let mut values = self.0.vector();
        values.try_reserve_exact(count)?;
        Ok(values)
    }
    fn operations<P, B>(
        &self,
        count: usize,
    ) -> Result<Self::Operations<P, B>, structured_asn1::memory::MemoryError> {
        let mut values = self.0.vector();
        values.try_reserve_exact(count)?;
        Ok(values)
    }
}

fn verify_all_document(
    document: &XmlDocument,
    ctx: &VerifyContext<'_>,
    request: &VerificationRequest<'_>,
) -> Result<VerifyEvidence, DsigError> {
    with_verified_document(
        document,
        ctx,
        request,
        &CollectedRequestStorage,
        |_, _, _, evidence, (), _| Ok(evidence),
    )
}

fn validate_verification_request(
    view: DocumentView<'_>,
    request: &VerificationRequest<'_>,
    policy: &crate::policy::VerificationPolicy,
) -> Result<(), DsigError> {
    match request.signatures {
        SignatureRequirement::AtLeast(0) | SignatureRequirement::Exactly(0) => {
            return Err(DsigError::InvalidRequest {
                reason: "signature requirement must be nonzero",
            });
        }
        _ => {}
    }
    if request.expected_targets.len() > policy.resources.max_references {
        return Err(DsigError::InvalidRequest {
            reason: "too many expected coverage targets",
        });
    }
    if request.trusted_keys.len() > policy.resources.max_signatures {
        return Err(DsigError::InvalidRequest {
            reason: "too many trusted signature keys",
        });
    }
    for (index, target) in request.expected_targets.iter().copied().enumerate() {
        if !view.resolve_node(target)?.is_element() {
            return Err(DsigError::InvalidRequest {
                reason: "coverage target must be an element",
            });
        }
        if request.expected_targets[..index].contains(&target) {
            return Err(DsigError::InvalidRequest {
                reason: "duplicate expected coverage target",
            });
        }
    }
    for (index, entry) in request.trusted_keys.iter().enumerate() {
        if !view
            .resolve_node(entry.signature)?
            .has_tag_name((XMLDSIG_NS, "Signature"))
        {
            return Err(DsigError::InvalidRequest {
                reason: "trusted key target must be a Signature",
            });
        }
        if request.trusted_keys[..index]
            .iter()
            .any(|prior| prior.signature == entry.signature)
        {
            return Err(DsigError::InvalidRequest {
                reason: "ambiguous trusted keys for one Signature",
            });
        }
    }
    Ok(())
}

/// Apply the request's cardinality and target requirements to the outcomes.
/// A verified session calls this again after completing detached References.
fn accept_verification_evidence<V: std::ops::Deref<Target = [SignatureEvidence]>>(
    view: DocumentView<'_>,
    requirement: SignatureRequirement,
    expected_targets: &[NodeIdentity],
    evidence: &mut VerifyEvidence<V>,
) -> Result<(), DsigError> {
    let count = evidence.signatures.len();
    let valid = evidence
        .signatures
        .iter()
        .filter(|entry| {
            entry.result.as_ref().is_ok_and(|result| {
                result.status == DsigStatus::Valid
                    && result
                        .manifest_references
                        .iter()
                        .all(|reference| reference.status == DsigStatus::Valid)
            })
        })
        .count();
    evidence.accepted = match requirement {
        SignatureRequirement::All => valid > 0 && valid == count,
        SignatureRequirement::AtLeast(minimum) => valid >= minimum,
        SignatureRequirement::Exactly(required) => valid == required && count == required,
    };
    for target in expected_targets {
        if !evidence.covers_element_in(view, *target)? {
            evidence.accepted = false;
            break;
        }
    }
    Ok(())
}

fn with_verified_document<'inputs, R, S: RequestStorage>(
    document: &XmlDocument,
    ctx: &VerifyContext<'inputs>,
    request: &VerificationRequest<'inputs>,
    storage: &S,
    continuation: impl for<'view, 'scope> FnOnce(
        DocumentView<'view>,
        &'scope VerifyContext<'inputs>,
        &'scope VerificationOperationBudgets<'inputs>,
        VerifyEvidence<S::Signatures>,
        S::Operations<
            &'scope crate::policy::VerificationPolicy,
            &'scope VerificationOperationBudgets<'inputs>,
        >,
        UriReferenceResolver<'view>,
    ) -> Result<R, DsigError>,
) -> Result<R, DsigError> {
    storage.admit_request(document)?;
    ctx.policy.validate()?;
    document.validate_operation_policy(ctx.policy.xml, &ctx.policy.resources)?;
    ctx.policy
        .signature_constraints
        .require_targets(!request.expected_targets.is_empty())?;
    if request.external_resources.is_some() && ctx.external_resources.is_some() {
        return Err(DsigError::InvalidRequest {
            reason: "external resources configured in both context and request",
        });
    }
    // RFC 5280 §6.1.1: validation time is one operation input, including
    // alternate certification paths and all Signatures in a batch.
    // https://www.rfc-editor.org/rfc/rfc5280#section-6.1.1
    let capture_time =
        ctx.policy.key_trust.verify_x509_chains && ctx.policy.key_trust.verification_time.is_none();
    let captured_context;
    let ctx = if capture_time || request.external_resources.is_some() {
        captured_context = {
            let mut captured = ctx.clone();
            if let Some(resources) = request.external_resources {
                captured.external_resources = Some(resources);
            }
            if capture_time {
                captured.policy.key_trust.verification_time = Some(std::time::SystemTime::now());
            }
            captured
        };
        &captured_context
    } else {
        ctx
    };
    let budgets = VerificationOperationBudgets::with_transforms(
        &ctx.policy,
        TransformExecutionBudget::from_resources(&ctx.policy.resources)
            .with_xml_backend(ctx.xml_backend),
        ctx.utc_facts,
    );
    document.with_view(|view| {
        validate_verification_request(view, request, &ctx.policy)?;
        let is_signature = |node: &Node<'_, '_>| node.has_tag_name((XMLDSIG_NS, "Signature"));
        let count = count_signature_nodes(view, ctx.policy.resources.max_signatures)?;
        // Cardinality is checked before allocating the report or calling a
        // resolver. No Vec of backend handles or cloned XML is needed.
        let mut signatures = storage.signatures(count)?;
        let mut operations = storage.operations(count)?;
        let resolver = UriReferenceResolver::with_document_view(view, ctx.id_attributes)
            .with_same_document_id_semantics(ctx.policy.transforms.same_document_id_semantics)
            .with_external_resource_limits(
                ctx.policy.resources.max_external_resource_bytes,
                ctx.policy.resources.max_external_resource_total_bytes,
            );
        let resolver = match ctx.external_resources {
            Some(resources) => resolver.with_external_resources(resources),
            None => resolver,
        };
        for signature in view.document().descendants().filter(is_signature) {
            // Authentication is signature-local; work accounting is request-
            // wide. A valid first signature cannot authenticate a Manifest
            // belonging to an invalid second signature.
            let mut operation = OperationExecutionContext::new(
                &ctx.policy,
                &budgets,
                Some((view.identity(), view.generation())),
            );
            let signature_identity = view.node_identity(signature);
            let key = request
                .trusted_keys
                .iter()
                .find(|entry| entry.signature == signature_identity)
                .map(|entry| entry.key)
                .or(ctx.key);
            let capture = storage.capture();
            let result = verify_signature_node(
                view,
                ctx,
                key,
                &mut operation,
                &resolver,
                signature,
                &capture,
            );
            signatures.push_signature(SignatureEvidence {
                identity: view.node_identity(signature),
                result,
            })?;
            operations.retain(operation, capture)?;
        }
        let mut evidence = VerifyEvidence {
            document: view.root(),
            signatures,
            accepted: false,
            correlation: request.correlation,
        };
        accept_verification_evidence(
            view,
            request.signatures,
            request.expected_targets,
            &mut evidence,
        )?;
        continuation(view, ctx, &budgets, evidence, operations, resolver)
    })
}

fn verify_signature_document_with_context_and_transforms(
    document: &XmlDocument,
    ctx: &VerifyContext<'_>,
    transforms: TransformExecutionBudget,
) -> Result<VerifyResult, SignatureVerificationPipelineError> {
    // RFC 5280 §6.1.1 makes the validation time an input to path validation.
    // Capture it once, not separately for each source or alternate path:
    // https://www.rfc-editor.org/rfc/rfc5280#section-6.1.1
    let captured_context;
    let ctx = if ctx.policy.key_trust.verify_x509_chains
        && ctx.policy.key_trust.verification_time.is_none()
    {
        captured_context = {
            let mut context = ctx.clone();
            context.policy.key_trust.verification_time = Some(std::time::SystemTime::now());
            context
        };
        &captured_context
    } else {
        ctx
    };
    let budgets =
        VerificationOperationBudgets::with_transforms(&ctx.policy, transforms, ctx.utc_facts);
    let mut operation = OperationExecutionContext::new(
        &ctx.policy,
        &budgets,
        Some((document.identity(), document.generation())),
    );
    document.with_view(|view| verify_signature_view(view, ctx, &mut operation))
}

fn verify_signature_view(
    view: DocumentView<'_>,
    ctx: &VerifyContext<'_>,
    operation: &mut OperationExecutionContext<
        &crate::policy::VerificationPolicy,
        &VerificationOperationBudgets,
    >,
) -> Result<VerifyResult, SignatureVerificationPipelineError> {
    ctx.policy.validate()?;
    ctx.policy.signature_constraints.require_targets(false)?;
    let doc = view.document();
    let resolver = UriReferenceResolver::with_document_view(view, ctx.id_attributes)
        .with_same_document_id_semantics(ctx.policy.transforms.same_document_id_semantics)
        .with_external_resource_limits(
            ctx.policy.resources.max_external_resource_bytes,
            ctx.policy.resources.max_external_resource_total_bytes,
        );
    let resolver = match ctx.external_resources {
        Some(resources) => resolver.with_external_resources(resources),
        None => resolver,
    };
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

    verify_signature_node(
        view,
        ctx,
        ctx.key,
        operation,
        &resolver,
        signature_node,
        &(),
    )
}

fn canonicalize_verification_signed_info(
    signed_info_node: Node<'_, '_>,
    method: &crate::c14n::C14nAlgorithm,
    operation: &OperationExecutionContext<
        &crate::policy::VerificationPolicy,
        &VerificationOperationBudgets,
    >,
) -> Result<Vec<u8>, DsigError> {
    let doc = signed_info_node.document();
    let signed_info_subtree: HashSet<_> = signed_info_node.descendants().map(Node::id).collect();
    let mut canonical_signed_info = Vec::new();
    let signed_info_limit = operation
        .budgets()
        .canonicalized
        .remaining()
        .min(operation.budgets().transforms.remaining_c14n_output());
    canonicalize_bounded_with_xml_base_budget(
        doc,
        Some(&|node| signed_info_subtree.contains(&node.id())),
        method,
        signed_info_limit,
        operation.budgets().transforms.xml_base_resolution(),
        &mut canonical_signed_info,
    )
    .map_err(|error| {
        if let Some(violation) = map_c14n_resource_policy_violation(
            &error,
            crate::policy::resource_name::CANONICALIZED_BYTES,
            operation.budgets().canonicalized.max_bytes,
        ) {
            SignatureVerificationPipelineError::Policy(violation)
        } else {
            SignatureVerificationPipelineError::Canonicalization(error)
        }
    })?;
    operation
        .budgets()
        .transforms
        .charge_c14n_output(canonical_signed_info.len())
        .map_err(ReferenceProcessingError::Transform)?;
    operation
        .budgets()
        .canonicalized
        .charge(canonical_signed_info.len())?;
    Ok::<_, SignatureVerificationPipelineError>(canonical_signed_info)
}

/// The accepted signature authenticates these instructions; only now are
/// their URIs resolved into resource identities and planned.
fn plan_signed_info_digests(
    operation: &mut OperationExecutionContext<
        &crate::policy::VerificationPolicy,
        &VerificationOperationBudgets,
    >,
    view: DocumentView<'_>,
    signature_node: Node<'_, '_>,
    resolver: &UriReferenceResolver<'_>,
    signed_info_references: &[Reference],
    crypto: OperationNodeId,
) -> Result<Vec<OperationNodeId>, DsigError> {
    operation.extend();
    let mut digests = Vec::with_capacity(signed_info_references.len());
    for (index, reference) in signed_info_references.iter().enumerate() {
        let resource = operation.budgets().resource_identity_for_reference(
            reference,
            index,
            resolver,
            view,
            reference_origin_node(signature_node, ReferenceSet::SignedInfo, index),
        );
        let digest = operation.add_node(
            OperationNodeKind::Digest { index },
            OperationStage::AuthenticatedDependency,
            Some(resource),
        );
        operation
            .add_dependency(digest, crypto)
            .map_err(map_verification_plan_error)?;
        digests.push(digest);
    }
    operation.compile().map_err(map_verification_plan_error)?;
    Ok(digests)
}

fn process_signed_info_references<C: VerificationCapture>(
    operation: &mut OperationExecutionContext<
        &crate::policy::VerificationPolicy,
        &VerificationOperationBudgets,
    >,
    view: DocumentView<'_>,
    signature_node: Node<'_, '_>,
    resolver: &UriReferenceResolver<'_>,
    verification: &ManifestVerification<'_, '_, C>,
    signed_info_references: &[Reference],
    crypto: OperationNodeId,
) -> Result<(ReferencesResult, Vec<OperationNodeId>), DsigError> {
    let ctx = verification.context;
    let capture = verification.capture;
    let digests = plan_signed_info_digests(
        operation,
        view,
        signature_node,
        resolver,
        signed_info_references,
        crypto,
    )?;
    let mut reference_results = Vec::with_capacity(signed_info_references.len());
    let mut first_failure = None;
    for (index, (node, reference)) in digests
        .iter()
        .copied()
        .zip(signed_info_references)
        .enumerate()
    {
        let observed = operation.budgets().resource_identity_for_reference(
            reference,
            index,
            resolver,
            view,
            reference_origin_node(signature_node, ReferenceSet::SignedInfo, index),
        );
        let mut result = operation.run_with_resource(node, &observed, || {
            let budgets = operation.budgets();
            let execution = ReferenceExecutionContext {
                store_pre_digest: ctx.store_pre_digest,
                transform_options: ctx.transform_options(),
                transform_budget: &budgets.transforms,
                canonicalized_data_budget: &budgets.canonicalized,
                provider: ctx.provider,
                capture,
            };
            process_reference_with_options(
                reference,
                resolver,
                signature_node,
                ReferenceSet::SignedInfo,
                index,
                reference_origin_node(signature_node, ReferenceSet::SignedInfo, index),
                &execution,
            )
            .or_else(|error| {
                let reason = error.into_reference_failure(index)?;
                Ok::<_, ReferenceProcessingError>(reference_failure_result(
                    reference,
                    ReferenceSet::SignedInfo,
                    index,
                    DsigStatus::Invalid(reason),
                ))
            })
            .map_err(SignatureVerificationPipelineError::from)
        })?;
        bind_reference_evidence(
            &mut result,
            reference,
            view,
            reference_origin_node(signature_node, ReferenceSet::SignedInfo, index),
            &observed,
        );
        let accepted = result.status == DsigStatus::Valid;
        operation.set_outcome(
            node,
            accepted,
            if accepted {
                OperationDecisionReason::ReferenceDigestVerified
            } else {
                OperationDecisionReason::ReferenceDigestRejected
            },
        );
        if result.status == DsigStatus::Valid
            && let Some(reference) = signed_info_references.get(result.reference_index)
            && reference
                .transforms
                .iter()
                .all(transform_preserves_manifest_structure)
            && let Some(uri) = reference.uri.as_deref()
            && let Ok(Some(target)) = resolver.node_id_for_same_document_reference(uri)
        {
            let identity = view.node_identity_by_id(target);
            operation.authenticate(identity);
            debug_assert!(operation.is_authenticated(identity));
        }
        reference_results.push(result);
        if !accepted && first_failure.is_none() {
            first_failure = Some(index);
        }
    }
    Ok((
        ReferencesResult {
            results: reference_results,
            first_failure,
        },
        digests,
    ))
}

/// Result of a signature whose `SignedInfo` was not authenticated.
fn unauthenticated_result(
    view: DocumentView<'_>,
    signature_node: Node<'_, '_>,
    completion: VerificationCompletion<'_>,
    store_pre_digest: bool,
    key_trust: super::KeyTrustEvidence,
    reason: FailureReason,
) -> VerifyResult {
    VerifyResult {
        key_trust,
        status: DsigStatus::Invalid(reason),
        signed_info_references: unprocessed_signed_info_references(
            view,
            signature_node,
            &completion.signed_info.references,
        ),
        manifest_references: Vec::new(),
        canonicalized_signed_info: store_pre_digest.then_some(completion.canonical_signed_info),
    }
}

/// `SignedInfo` References of a signature that did not verify: reported, never
/// dereferenced or transformed (W3C XML Signature Best Practices BP1).
fn unprocessed_signed_info_references(
    view: DocumentView<'_>,
    signature_node: Node<'_, '_>,
    references: &[Reference],
) -> Vec<ReferenceResult> {
    // Parsed references follow the SignedInfo Reference children in order.
    let mut origins = signature_node
        .children()
        .find(|node| node.has_tag_name((XMLDSIG_NS, "SignedInfo")))
        .into_iter()
        .flat_map(Node::children)
        .filter(|node| node.has_tag_name((XMLDSIG_NS, "Reference")));
    references
        .iter()
        .enumerate()
        .map(|(index, reference)| {
            let mut result = reference_failure_result(
                reference,
                ReferenceSet::SignedInfo,
                index,
                DsigStatus::NotProcessed,
            );
            result.reference_identity = origins.next().map(|node| view.node_identity(node));
            result
        })
        .collect()
}

fn materialize_verification_hints(
    key_info_node: Option<Node<'_, '_>>,
    ctx: &VerifyContext<'_>,
    budgets: &VerificationOperationBudgets<'_>,
    resolver: &UriReferenceResolver<'_>,
    should_parse_key_info: bool,
    key_info: &mut Option<KeyInfo>,
    mut origins: Option<&mut Vec<SourceOrigin>>,
) -> Result<RetrievalMaterialization, DsigError> {
    let mut materialization = budgets.key_info_materialization.borrow_mut();
    materialization.collect_encapsulation = true;
    materialization.encapsulation = None;
    if let Some(node) = key_info_node {
        // A pinned key ignores lookup hints, not mechanism instructions.
        // Apply the same bounded reference discovery before key work.
        if ctx.decapsulation_key.is_some() {
            discover_encapsulation_with_budget(
                node,
                resolver,
                &ctx.policy.resources,
                &budgets.transforms,
                Some((&ctx.policy, ctx.xml_backend)),
                Some(&mut materialization),
            )?;
        } else if !should_parse_key_info {
            if has_encapsulation_with_budget(
                node,
                resolver,
                &ctx.policy.resources,
                &budgets.transforms,
                Some((&ctx.policy, ctx.xml_backend)),
            )? {
                return Err(crate::key_establishment::KeyEstablishmentError::Structure(
                    "mechanism and explicit recipient key must be supplied together",
                )
                .into());
            }
        } else {
            materialization.observe_encapsulation(node, resolver, 0)?;
        }
    }
    if let Some(info) = key_info.as_mut() {
        let mut xpath_parse = budgets.xpath_parse.borrow_mut();
        let mut retrieval_budgets = RetrievalMaterializationBudgets {
            key_info_parse: &budgets.key_info_parse,
            xpath_parse: &mut xpath_parse,
            execution: &budgets.transforms,
            resources: &ctx.policy.resources,
            certificate_signature_algorithms: ctx
                .policy
                .key_trust
                .certificate_signature_algorithms
                .as_ref(),
            xml_backend: ctx.xml_backend,
        };
        let mut outcome = materialize_key_info_references_with_budgets(
            info,
            origins.as_deref_mut(),
            resolver,
            &ctx.policy,
            ctx.provider,
            &mut retrieval_budgets,
            &mut materialization,
        )?;
        outcome.merge(materialize_retrieval_methods_with_budgets(
            info,
            origins,
            resolver,
            &ctx.policy,
            ctx.provider,
            &mut retrieval_budgets,
            &mut materialization.candidate_work,
        )?);
        Ok::<_, SignatureVerificationPipelineError>(outcome)
    } else {
        Ok(RetrievalMaterialization::default())
    }
}

fn validate_verification_inputs(
    signed_info: &super::parse::SignedInfo,
    ctx: &VerifyContext<'_>,
) -> Result<(), DsigError> {
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
    // Refuse an inadmissible authenticator before reference resolution/transforms.
    // XMLDSig 1.1 section 4.4.2 explicitly requires max(80, hash_bits/2),
    // independently of data; section 6.3.1 separately requires octet alignment.
    // https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-SignatureMethod
    if let Some(full_output_bits) = signed_info.signature_method.hmac_output_bits() {
        ctx.policy.hmac.validate_output(
            signed_info.signature_method,
            signed_info
                .hmac_output_length_bits
                .unwrap_or(full_output_bits),
        )?;
    }
    for reference in &signed_info.references {
        ctx.policy.check_digest_algorithm(reference.digest_method)?;
        super::transforms::validate_relationship_chain(
            &reference.transforms,
            ctx.policy.transforms.opc_relationship_edition,
        )
        .map_err(ReferenceProcessingError::Transform)?;
    }
    enforce_reference_policies(
        &signed_info.references,
        ctx.policy.uris.references,
        ctx.allowed_transform_uris(),
    )?;
    enforce_transform_allowed(ctx.allowed_transform_uris(), signed_info.c14n_method.uri())?;
    if let Some(resources) = ctx.external_resources {
        validate_external_resource_map(
            resources,
            ctx.policy.resources.max_external_resource_bytes,
            ctx.policy.resources.max_external_resource_total_bytes,
        )
        .map_err(|error| match error {
            ExternalResourceMapError::Policy(error) => error.into(),
            ExternalResourceMapError::TotalLengthOverflow => {
                SignatureVerificationPipelineError::InvalidStructure {
                    reason: "external resource total length overflow",
                }
            }
        })?;
    }
    Ok(())
}

struct PreparedVerificationSignature<'a> {
    children: SignatureChildNodes<'a, 'a>,
    signed_info: super::parse::SignedInfo,
    key_info: Option<KeyInfo>,
    // Source elements of `key_info`, kept only when the capture retains it.
    key_info_origins: Option<Vec<SourceOrigin>>,
    should_parse_key_info: bool,
    remaining_reference_capacity: usize,
}

fn prepare_verification_signature<'a, C: VerificationCapture>(
    view: DocumentView<'a>,
    signature_node: Node<'a, 'a>,
    key: Option<&dyn VerifyingKey>,
    verification: &ManifestVerification<'_, '_, C>,
    operation: &OperationExecutionContext<
        &crate::policy::VerificationPolicy,
        &VerificationOperationBudgets,
    >,
) -> Result<PreparedVerificationSignature<'a>, DsigError> {
    let ctx = verification.context;
    let capture = verification.capture;
    if ctx.policy.resources.max_signatures == 0 {
        return Err(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::VERIFICATION_SIGNATURES,
            maximum: 0,
            actual: 1,
        }
        .into());
    }
    let signature_children = parse_signature_children(signature_node)?;
    ctx.policy
        .signature_constraints
        .check(signature_node, &operation.budgets().transforms)?;
    if ctx.decapsulation_key.is_some() {
        // Public-key encapsulation establishes a recipient secret, not sender
        // identity. Reject an impossible trust requirement before key work.
        if ctx.policy.key_trust.mode != crate::policy::VerificationTrustMode::CryptographicOnly {
            return Err(crate::policy::PolicyViolation::KeyTrust {
                reason: "KEM/HMAC does not authenticate sender identity",
            }
            .into());
        }
    }
    let signed_info_node = signature_children.signed_info;
    let should_parse_key_info = ctx.decapsulation_key.is_none()
        && match (key, ctx.key_resolver) {
            (Some(_), _) => false,
            (None, Some(resolver)) => resolver.consumes_document_key_info(),
            (None, None) => true,
        };
    let mut key_info_origins = C::RETAINS_KEY_INFO.then(Vec::new);
    let key_info = if should_parse_key_info {
        signature_children
            .key_info
            .map(|node| {
                super::parse::validate_x509_digest_policy(node, &|algorithm| {
                    ctx.policy.check_digest_algorithm(algorithm)
                })?;
                super::parse::parse_key_info_in_session(
                    node,
                    ctx.provider,
                    operation.budgets().transforms.xml_base_resolution(),
                    &ctx.policy.resources,
                    super::parse::SourceContext {
                        document_base: None,
                        origins: key_info_origins.as_mut(),
                    },
                    ctx.policy
                        .key_trust
                        .certificate_signature_algorithms
                        .as_ref(),
                    &mut operation.budgets().key_info_parse.borrow_mut(),
                )
            })
            .transpose()
            .map_err(map_key_info_parse_error)?
    } else {
        None
    };
    let key_info_origins = key_info.as_ref().and(key_info_origins);

    let signed_info = parse_signed_info_with_xpath_budget(
        signed_info_node,
        &mut operation.budgets().xpath_parse.borrow_mut(),
        &ctx.policy.resources,
    )?;
    capture.method(view, signed_info_node, signed_info.signature_method)?;
    validate_verification_inputs(&signed_info, ctx)?;
    let remaining_reference_capacity = ctx
        .policy
        .resources
        .max_references
        .checked_sub(signed_info.references.len())
        .ok_or(SignatureVerificationPipelineError::InvalidStructure {
            reason: "SignedInfo exceeds the per-signature Reference limit",
        })?;
    Ok(PreparedVerificationSignature {
        children: signature_children,
        signed_info,
        key_info,
        key_info_origins,
        should_parse_key_info,
        remaining_reference_capacity,
    })
}

fn check_verification_encapsulation(
    encapsulation: Option<&ResolvedEncapsulation>,
    ctx: &VerifyContext<'_>,
) -> Result<(), DsigError> {
    if encapsulation.is_some() != ctx.decapsulation_key.is_some() {
        return Err(crate::key_establishment::KeyEstablishmentError::Structure(
            "mechanism and explicit recipient key must be supplied together",
        )
        .into());
    }
    if let Some(mechanism) = encapsulation {
        ctx.policy
            .key_establishment
            .check_encapsulation(mechanism.algorithm)?;
        if ctx
            .decapsulation_key
            .is_some_and(|key| key.algorithm() != mechanism.algorithm)
        {
            return Err(crate::key_establishment::KeyEstablishmentError::Structure(
                "recipient parameter set mismatch",
            )
            .into());
        }
    }
    Ok(())
}

struct VerificationCompletion<'a> {
    signature_value_node: Node<'a, 'a>,
    signed_info: super::parse::SignedInfo,
    key_info: Option<KeyInfo>,
    key_info_origins: Option<Vec<SourceOrigin>>,
    key_info_reading: KeyInfoReading,
    plan_nodes: VerificationPlanNodes,
    encapsulation: Option<ResolvedEncapsulation>,
    retrieval_materialization: RetrievalMaterialization,
    canonical_signed_info: Vec<u8>,
    remaining_reference_capacity: usize,
}

fn resolve_operation_verification_key<'k>(
    ctx: &VerifyContext<'k>,
    key: Option<&'k dyn VerifyingKey>,
    key_info: Option<&KeyInfo>,
    algorithm: SignatureAlgorithm,
    encapsulation: Option<&ResolvedEncapsulation>,
    operation: &OperationExecutionContext<
        &crate::policy::VerificationPolicy,
        &VerificationOperationBudgets,
    >,
) -> Result<Option<ResolvedVerifyingKey<'k>>, DsigError> {
    if let Some(recipient) = ctx.decapsulation_key {
        if key.is_some() || ctx.key_resolver.is_some() {
            return Err(crate::key_establishment::KeyEstablishmentError::Structure(
                "ambiguous verification key request",
            )
            .into());
        }
        require_verifying_key_candidate_capacity(&ctx.policy)?;
        if !ctx
            .policy
            .key_sources
            .contains(crate::policy::KeySourceKind::PresetKey)
            || algorithm.hmac_output_bits().is_none()
        {
            return Err(crate::key_establishment::KeyEstablishmentError::Structure(
                "encapsulation requires permitted explicit key and HMAC",
            )
            .into());
        }
        ctx.policy.hmac.validate_key_bits(256)?;
        let mechanism = encapsulation.ok_or(
            crate::key_establishment::KeyEstablishmentError::Structure("missing mechanism"),
        )?;
        operation.budgets().key_candidates.borrow_mut().charge()?;
        operation
            .budgets()
            .key_establishment
            .borrow_mut()
            .commit_all(&ctx.policy.key_establishment, 0, 0, 32)?;
        let secret = operation
            .budgets()
            .key_establishment
            .borrow_mut()
            .decapsulate(
                &ctx.policy.key_establishment,
                ctx.provider,
                recipient,
                mechanism.algorithm,
                &mechanism.ciphertext[..mechanism.algorithm.ciphertext_len()],
            )?;
        let hmac = super::HmacVerificationKey::new(secret.to_vec())?;
        return Ok(Some(ResolvedVerifyingKey::Established(hmac)));
    }
    resolve_verifying_key(
        ctx,
        key,
        key_info,
        algorithm,
        &mut operation.budgets().key_candidates.borrow_mut(),
    )
}

fn verify_operation_authenticator<C: VerificationCapture>(
    verifier: &dyn VerifyingKey,
    ctx: &VerifyContext<'_>,
    operation: &OperationExecutionContext<
        &crate::policy::VerificationPolicy,
        &VerificationOperationBudgets,
    >,
    capture: &C,
    input: crate::provider::SignatureVerificationInput<'_>,
) -> Result<bool, DsigError> {
    // A handle on the operation's certificate account: key reads below share
    // its allowance and usage without holding the candidate budget borrowed.
    let certificates = operation
        .budgets()
        .key_candidates
        .borrow()
        .certificates()
        .share();
    let scope = VerificationScope::new(&ctx.policy, &certificates);
    verifier.validate_policy(&scope)?;
    if !verifier.validate_signature_value_with_policy(&scope, input.algorithm, input.signature)? {
        return Ok::<_, SignatureVerificationPipelineError>(false);
    }
    ctx.provider
        .require_capability(crate::provider::ProviderCapability::Verify(input.algorithm))?;
    let candidate_refusal = RefCell::new(None);
    let policy_verifier = PolicyVerifyingKey {
        key: verifier,
        scope,
        candidates: &operation.budgets().key_candidates,
        candidate_refusal: &candidate_refusal,
    };
    #[cfg(feature = "aws-lc-fips")]
    let input = input.with_certificates(&certificates);
    let result = capture.verify(ctx.provider, &policy_verifier, input);
    if let Some(error) = candidate_refusal.into_inner() {
        return Err(error.into());
    }
    result
}

fn finish_authenticated_verification<C: VerificationCapture>(
    operation: &mut OperationExecutionContext<
        &crate::policy::VerificationPolicy,
        &VerificationOperationBudgets,
    >,
    view: DocumentView<'_>,
    signature_node: Node<'_, '_>,
    resolver: &UriReferenceResolver<'_>,
    verification: &ManifestVerification<'_, '_, C>,
    key_trust: super::KeyTrustEvidence,
    completion: VerificationCompletion<'_>,
) -> Result<VerifyResult, DsigError> {
    let ctx = verification.context;
    operation.set_outcome(
        completion.plan_nodes.crypto,
        true,
        OperationDecisionReason::SignatureVerified,
    );
    let (references, signed_info_digests) = process_signed_info_references(
        operation,
        view,
        signature_node,
        resolver,
        verification,
        &completion.signed_info.references,
        completion.plan_nodes.crypto,
    )?;
    let canonicalized_signed_info = ctx
        .store_pre_digest
        .then_some(completion.canonical_signed_info);
    if let Some(first_failure) = references.first_failure {
        // Core validation failed (XMLDSig 1.1 §3.2): Manifest content stays
        // unparsed, while the verified signature keeps its key evidence.
        return Ok(VerifyResult {
            key_trust,
            status: references.results[first_failure].status,
            signed_info_references: references.results,
            manifest_references: Vec::new(),
            canonicalized_signed_info,
        });
    }
    // Every node core validation completed: the evidence and the first
    // Manifest frontier depend on all of them.
    let mut core_validation = signed_info_digests;
    core_validation.push(completion.plan_nodes.crypto);
    let manifest_references = finish_core_validation(
        operation,
        view,
        signature_node,
        resolver,
        verification,
        completion.remaining_reference_capacity,
        core_validation,
    )?;
    Ok(VerifyResult {
        key_trust,
        status: DsigStatus::Valid,
        signed_info_references: references.results,
        manifest_references,
        canonicalized_signed_info,
    })
}

/// Core validation succeeded (`XMLDSig` 1.1 §3.2): process the authenticated
/// Manifests and finalize the evidence node. `core_validation` holds every
/// `SignedInfo` digest node and the accepted crypto node.
fn finish_core_validation<C: VerificationCapture>(
    operation: &mut OperationExecutionContext<
        &crate::policy::VerificationPolicy,
        &VerificationOperationBudgets,
    >,
    view: DocumentView<'_>,
    signature_node: Node<'_, '_>,
    resolver: &UriReferenceResolver<'_>,
    verification: &ManifestVerification<'_, '_, C>,
    remaining_reference_capacity: usize,
    core_validation: Vec<OperationNodeId>,
) -> Result<Vec<ReferenceResult>, SignatureVerificationPipelineError> {
    // Manifest syntax and references are authenticated content. Delay parsing
    // until core validation succeeds, then extend the same operation graph with
    // the newly trusted dependency subgraph and its evidence node.
    let (manifest_references, manifest_digests) = if verification.context.policy.manifest_processing
        == crate::policy::ManifestProcessing::Process
    {
        process_authenticated_manifest_references(
            operation,
            view,
            signature_node,
            resolver,
            verification,
            remaining_reference_capacity,
            &core_validation,
        )?
    } else {
        (Vec::new(), Vec::new())
    };
    operation.extend();
    let evidence = operation.add_node(OperationNodeKind::Evidence, OperationStage::Evidence, None);
    for prerequisite in core_validation.into_iter().chain(manifest_digests) {
        operation
            .add_dependency(evidence, prerequisite)
            .map_err(map_verification_plan_error)?;
    }
    operation.compile().map_err(map_verification_plan_error)?;
    operation.run(evidence, || Ok::<_, SignatureVerificationPipelineError>(()))?;
    Ok(manifest_references)
}

fn verify_signature_authenticator<C: VerificationCapture>(
    operation: &mut OperationExecutionContext<
        &crate::policy::VerificationPolicy,
        &VerificationOperationBudgets,
    >,
    view: DocumentView<'_>,
    signature_node: Node<'_, '_>,
    resolver: &UriReferenceResolver<'_>,
    verification: &ManifestVerification<'_, '_, C>,
    key: Option<&dyn VerifyingKey>,
    mut completion: VerificationCompletion<'_>,
) -> Result<VerifyResult, DsigError> {
    let ctx = verification.context;
    let signature_value = decode_signature_value(
        completion.signature_value_node,
        completion.signed_info.signature_method,
        &ctx.policy.resources,
    )?;
    if let Some(full_output_bits) = completion.signed_info.signature_method.hmac_output_bits() {
        let expected_bits = completion
            .signed_info
            .hmac_output_length_bits
            .unwrap_or(full_output_bits);
        if signature_value.len() != expected_bits / 8 {
            return Err(SignatureVerificationPipelineError::InvalidStructure {
                reason: "SignatureValue length does not match HMACOutputLength",
            });
        }
    }
    let resolved_key = operation.run(completion.plan_nodes.key, || {
        resolve_operation_verification_key(
            ctx,
            key,
            completion.key_info.as_ref(),
            completion.signed_info.signature_method,
            completion.encapsulation.as_ref(),
            operation,
        )
    })?;
    let Some(resolved_key) = resolved_key else {
        operation.set_outcome(
            completion.plan_nodes.key,
            false,
            OperationDecisionReason::KeyUnavailable,
        );
        if let Some(error) = completion.retrieval_materialization.deferred_error {
            return Err(error);
        }
        return Ok(unauthenticated_result(
            view,
            signature_node,
            completion,
            ctx.store_pre_digest,
            super::KeyTrustEvidence::NotEvaluated,
            FailureReason::KeyNotFound,
        ));
    };
    operation.set_outcome(
        completion.plan_nodes.key,
        true,
        OperationDecisionReason::KeyResolved,
    );
    // BP1 establishes trust in the key before SignedInfo or any Reference is
    // validated with it; an unauthorized key costs no crypto or transform work.
    // <https://www.w3.org/TR/xmldsig-bestpractices/#bp-authenticate-signature-first>
    let key_trust = resolved_key.evidence(&ctx.policy)?;
    let verifier = resolved_key.as_ref();
    let signature_valid = operation.run(completion.plan_nodes.crypto, || {
        verify_operation_authenticator(
            verifier,
            ctx,
            operation,
            verification.capture,
            crate::provider::SignatureVerificationInput::new(
                completion.signed_info.signature_method,
                &completion.signed_info.signature_context,
                &completion.canonical_signed_info,
                &signature_value,
            ),
        )
    })?;
    if !signature_valid {
        operation.set_outcome(
            completion.plan_nodes.crypto,
            false,
            OperationDecisionReason::SignatureRejected,
        );
        return Ok(unauthenticated_result(
            view,
            signature_node,
            completion,
            ctx.store_pre_digest,
            key_trust,
            FailureReason::SignatureMismatch,
        ));
    }
    // Only an authenticated Signature's candidates outlive key selection.
    verification.capture.key_info(
        view,
        completion.key_info_reading,
        completion.key_info.take(),
        completion.key_info_origins.take(),
    )?;
    finish_authenticated_verification(
        operation,
        view,
        signature_node,
        resolver,
        verification,
        key_trust,
        completion,
    )
}

fn verify_signature_node<'a, C: VerificationCapture>(
    view: DocumentView<'a>,
    ctx: &VerifyContext<'_>,
    key: Option<&dyn VerifyingKey>,
    operation: &mut OperationExecutionContext<
        &crate::policy::VerificationPolicy,
        &VerificationOperationBudgets,
    >,
    resolver: &UriReferenceResolver<'a>,
    signature_node: Node<'a, 'a>,
    capture: &C,
) -> Result<VerifyResult, DsigError> {
    let verification = ManifestVerification {
        context: ctx,
        capture,
    };
    let PreparedVerificationSignature {
        children: signature_children,
        signed_info,
        mut key_info,
        mut key_info_origins,
        should_parse_key_info,
        remaining_reference_capacity,
    } = prepare_verification_signature(view, signature_node, key, &verification, operation)?;
    let key_info_reading = match (signature_children.key_info, should_parse_key_info) {
        (None, _) => KeyInfoReading::Absent,
        (Some(_), false) => KeyInfoReading::NotRead,
        (Some(_), true) => KeyInfoReading::Read,
    };
    let signed_info_node = signature_children.signed_info;
    let plan_nodes =
        compile_verification_operation_plan(operation, view, signature_node, resolver)?;
    let signature_identity =
        OperationResourceIdentity::DocumentNode(view.node_identity(signature_node));
    operation.run_with_resource(plan_nodes.document, &signature_identity, || {
        operation
            .validate_document_view(view)
            .map_err(map_verification_plan_error)
    })?;
    let observed_key_resources = operation.budgets().external_resource_set_identity(resolver);
    let retrieval_materialization = operation.run_with_resource(
        plan_nodes.key_materialization,
        &observed_key_resources,
        || {
            materialize_verification_hints(
                signature_children.key_info,
                ctx,
                operation.budgets(),
                resolver,
                should_parse_key_info,
                &mut key_info,
                key_info_origins.as_mut(),
            )
        },
    )?;
    let encapsulation = operation
        .budgets()
        .key_info_materialization
        .borrow_mut()
        .encapsulation
        .take();
    check_verification_encapsulation(encapsulation.as_ref(), ctx)?;
    let canonical_signed_info = operation.run(plan_nodes.canonicalization, || {
        canonicalize_verification_signed_info(signed_info_node, &signed_info.c14n_method, operation)
    })?;

    verify_signature_authenticator(
        operation,
        view,
        signature_node,
        resolver,
        &verification,
        key,
        VerificationCompletion {
            signature_value_node: signature_children.signature_value,
            signed_info,
            key_info,
            key_info_origins,
            key_info_reading,
            plan_nodes,
            encapsulation,
            retrieval_materialization,
            canonical_signed_info,
            remaining_reference_capacity,
        },
    )
}

struct PolicyVerifyingKey<'a, 'inputs> {
    key: &'a dyn VerifyingKey,
    scope: VerificationScope<'a>,
    candidates: &'a RefCell<super::InspectedKeyCandidateBudget<'inputs>>,
    candidate_refusal: &'a RefCell<Option<crate::policy::PolicyViolation>>,
}

impl VerifyingKey for PolicyVerifyingKey<'_, '_> {
    fn association_spki(&self, algorithm: SignatureAlgorithm) -> Option<&[u8]> {
        self.key.association_spki(algorithm)
    }
    fn provider_binding(&self) -> Option<&crate::provider::ProviderBinding> {
        self.key.provider_binding()
    }
    fn verify_candidate_keys(
        &self,
        verify: &mut dyn FnMut(&dyn VerifyingKey) -> Result<bool, DsigError>,
    ) -> Result<Option<bool>, DsigError> {
        self.key.verify_candidate_keys(&mut |key| {
            if let Some(error) = self.candidate_refusal.borrow().as_ref() {
                return Err(error.clone().into());
            }
            // The resolver already admitted this handle. Every child exposed
            // by it is another attempt in that same operation-wide budget.
            if let Err(error) = self.candidates.borrow_mut().charge_policy(1) {
                *self.candidate_refusal.borrow_mut() = Some(error.clone());
                return Err(error.into());
            }
            key.validate_policy(&self.scope)?;
            verify(&PolicyVerifyingKey {
                key,
                scope: self.scope,
                candidates: self.candidates,
                candidate_refusal: self.candidate_refusal,
            })
        })
    }
    fn verification_spki(&self, algorithm: SignatureAlgorithm) -> Result<Option<&[u8]>, DsigError> {
        self.key.verification_spki(algorithm)
    }

    fn ecdsa_encoding(&self) -> crate::policy::EcdsaSignatureValueEncoding {
        self.scope.policy().ecdsa_signature_value_encoding
    }
    fn verify_with_context(
        &self,
        algorithm: SignatureAlgorithm,
        context: &super::SignatureContext,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, DsigError> {
        self.key
            .verify_with_policy(&self.scope, algorithm, context, data, signature)
    }
    fn validate_policy(&self, scope: &VerificationScope<'_>) -> Result<(), DsigError> {
        self.key.validate_policy(scope)
    }

    fn validate_signature_value(
        &self,
        algorithm: SignatureAlgorithm,
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        self.key
            .validate_signature_value_with_policy(&self.scope, algorithm, signature_value)
    }

    fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        signed_data: &[u8],
        signature_value: &[u8],
    ) -> Result<bool, DsigError> {
        self.verify_with_context(
            algorithm,
            &super::SignatureContext::default(),
            signed_data,
            signature_value,
        )
    }
}

#[derive(Debug, Default)]
struct RetrievalMaterialization {
    deferred_error: Option<SignatureVerificationPipelineError>,
}

impl RetrievalMaterialization {
    fn merge(&mut self, other: Self) {
        if self.deferred_error.is_none() {
            self.deferred_error = other.deferred_error;
        }
    }
}

struct RetrievalMaterializationBudgets<'a> {
    key_info_parse: &'a RefCell<super::parse::KeyInfoParseUsage>,
    certificate_signature_algorithms: Option<&'a crate::policy::CertificateSignatureAlgorithms>,
    xpath_parse: &'a mut XPathSignatureParseBudget,
    execution: &'a TransformExecutionBudget,
    resources: &'a crate::policy::ResourcePolicy,
    xml_backend: crate::XmlBackend,
}

#[derive(Default)]
struct KeyInfoMaterializationState {
    active: HashSet<(super::uri::TraversalDocumentIdentity, String)>,
    candidate_work: usize,
    collect_encapsulation: bool,
    encapsulation_template: bool,
    retain_encapsulation_target: bool,
    encapsulation_depth: usize,
    reference_depth_base: usize,
    encapsulation_target: Option<(super::uri::TraversalDocumentIdentity, NodeId, NodeId)>,
    encapsulation: Option<ResolvedEncapsulation>,
}

struct ResolvedEncapsulation {
    algorithm: crate::provider::KeyEncapsulationAlgorithm,
    ciphertext: [u8; 1568],
}

impl KeyInfoMaterializationState {
    fn observe_encapsulation(
        &mut self,
        node: Node<'_, '_>,
        resolver: &UriReferenceResolver<'_>,
        depth: usize,
    ) -> Result<(), SignatureVerificationPipelineError> {
        if !self.collect_encapsulation {
            return Ok(());
        }
        // XMLDSig 1.1 §4.5.10 references KeyInfo, including its extension
        // children. Collect metadata in the gated reference traversal, not a
        // separate unbounded scan; external document nodes cannot escape it.
        // https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-KeyInfoReference
        let Some(mechanism) =
            crate::key_establishment::direct_encapsulation(node, self.encapsulation_template)
                .map_err(|_| SignatureVerificationPipelineError::InvalidStructure {
                    reason: "invalid encapsulation mechanism in resolved KeyInfo",
                })?
        else {
            return Ok(());
        };
        self.record_encapsulation(mechanism, resolver, depth)
    }

    fn record_encapsulation(
        &mut self,
        mechanism: crate::key_establishment::ParsedEncapsulation<'_, '_>,
        resolver: &UriReferenceResolver<'_>,
        depth: usize,
    ) -> Result<(), SignatureVerificationPipelineError> {
        if self.encapsulation.is_some() {
            return Err(SignatureVerificationPipelineError::InvalidStructure {
                reason: "multiple encapsulation mechanisms in resolved KeyInfo",
            });
        }
        if self.retain_encapsulation_target {
            self.encapsulation_depth = depth;
            self.encapsulation_target = Some((
                resolver.traversal_document_identity(),
                mechanism.cipher_value.id(),
                mechanism.key_info.id(),
            ));
        }
        self.encapsulation = Some(ResolvedEncapsulation {
            algorithm: mechanism.algorithm,
            ciphertext: mechanism.into_ciphertext(),
        });
        Ok(())
    }
}

trait KeyInfoReferencePolicy {
    fn key_establishment(&self) -> &crate::policy::KeyEstablishmentPolicy;
    fn check_digest_algorithm(
        &self,
        algorithm: DigestAlgorithm,
    ) -> Result<(), crate::policy::PolicyViolation>;
    fn certificate_signature_algorithms(
        &self,
    ) -> Option<&crate::policy::CertificateSignatureAlgorithms>;
    fn resources(&self) -> &crate::policy::ResourcePolicy;
    fn xml(&self) -> &crate::policy::XmlInputPolicy;
    fn key_info_reference_uris(&self) -> UriTypeSet;
    fn retrieval_method_uris(&self) -> UriTypeSet;
    fn key_info_reference_source_enabled(&self) -> bool;
    fn allowed_transforms(&self) -> Option<&HashSet<String>>;
}

impl KeyInfoReferencePolicy for crate::policy::SigningPolicy {
    fn key_establishment(&self) -> &crate::policy::KeyEstablishmentPolicy {
        &self.key_establishment
    }
    fn check_digest_algorithm(
        &self,
        algorithm: DigestAlgorithm,
    ) -> Result<(), crate::policy::PolicyViolation> {
        self.check_digest_algorithm(algorithm)
    }
    fn certificate_signature_algorithms(
        &self,
    ) -> Option<&crate::policy::CertificateSignatureAlgorithms> {
        None
    }
    fn resources(&self) -> &crate::policy::ResourcePolicy {
        &self.resources
    }

    fn xml(&self) -> &crate::policy::XmlInputPolicy {
        &self.xml
    }

    fn key_info_reference_uris(&self) -> UriTypeSet {
        self.uris.key_info_references
    }

    fn retrieval_method_uris(&self) -> UriTypeSet {
        self.uris.retrieval_methods
    }

    fn key_info_reference_source_enabled(&self) -> bool {
        true
    }

    fn allowed_transforms(&self) -> Option<&HashSet<String>> {
        self.transforms.allowed_algorithms.as_ref()
    }
}

impl KeyInfoReferencePolicy for crate::policy::VerificationPolicy {
    fn key_establishment(&self) -> &crate::policy::KeyEstablishmentPolicy {
        &self.key_establishment
    }
    fn check_digest_algorithm(
        &self,
        algorithm: DigestAlgorithm,
    ) -> Result<(), crate::policy::PolicyViolation> {
        self.check_digest_algorithm(algorithm)
    }
    fn certificate_signature_algorithms(
        &self,
    ) -> Option<&crate::policy::CertificateSignatureAlgorithms> {
        self.key_trust.certificate_signature_algorithms.as_ref()
    }
    fn resources(&self) -> &crate::policy::ResourcePolicy {
        &self.resources
    }

    fn xml(&self) -> &crate::policy::XmlInputPolicy {
        &self.xml
    }

    fn key_info_reference_uris(&self) -> UriTypeSet {
        self.uris.key_info_references
    }

    fn retrieval_method_uris(&self) -> UriTypeSet {
        self.uris.retrieval_methods
    }

    fn key_info_reference_source_enabled(&self) -> bool {
        self.key_sources
            .contains(crate::policy::KeySourceKind::KeyInfoReference)
    }

    fn allowed_transforms(&self) -> Option<&HashSet<String>> {
        self.transforms.allowed_algorithms.as_ref()
    }
}

struct KeyInfoReferenceMaterializationContext<'a, 'budget, P> {
    policy: &'a P,
    provider: &'a dyn crate::provider::CryptoProvider,
    budgets: &'a mut RetrievalMaterializationBudgets<'budget>,
}

fn materialize_key_info_references_with_budgets<P: KeyInfoReferencePolicy>(
    key_info: &mut KeyInfo,
    origins: Option<&mut Vec<SourceOrigin>>,
    resolver: &UriReferenceResolver<'_>,
    policy: &P,
    provider: &dyn crate::provider::CryptoProvider,
    budgets: &mut RetrievalMaterializationBudgets<'_>,
    materialization: &mut KeyInfoMaterializationState,
) -> Result<RetrievalMaterialization, SignatureVerificationPipelineError> {
    let mut context = KeyInfoReferenceMaterializationContext {
        policy,
        provider,
        budgets,
    };
    let depth = materialization.reference_depth_base;
    materialize_key_info_visit(
        key_info,
        origins,
        resolver,
        &mut context,
        materialization,
        depth,
    )
}

fn parse_referenced_key_info<P: KeyInfoReferencePolicy>(
    node: Node<'_, '_>,
    resolver: &UriReferenceResolver<'_>,
    context: &mut KeyInfoReferenceMaterializationContext<'_, '_, P>,
    materialization: &mut KeyInfoMaterializationState,
    depth: usize,
    source: super::parse::SourceContext<'_>,
) -> Result<KeyInfo, SignatureVerificationPipelineError> {
    materialization.observe_encapsulation(node, resolver, depth)?;
    if let Some(mechanism) = &materialization.encapsulation {
        context
            .policy
            .key_establishment()
            .check_encapsulation(mechanism.algorithm)?;
    }
    super::parse::validate_x509_digest_policy(node, &|algorithm| {
        context.policy.check_digest_algorithm(algorithm)
    })
    .map_err(map_key_info_parse_error)?;
    super::parse::parse_key_info_in_session(
        node,
        context.provider,
        context.budgets.execution.xml_base_resolution(),
        context.policy.resources(),
        source,
        context.policy.certificate_signature_algorithms(),
        &mut context.budgets.key_info_parse.borrow_mut(),
    )
    .map_err(map_key_info_parse_error)
}

fn materialize_external_key_info<P: KeyInfoReferencePolicy>(
    uri: &str,
    resolver: &UriReferenceResolver<'_>,
    context: &mut KeyInfoReferenceMaterializationContext<'_, '_, P>,
    materialization: &mut KeyInfoMaterializationState,
    next_depth: usize,
) -> Result<(KeyInfo, RetrievalMaterialization), SignatureVerificationPipelineError> {
    // The fragment selects a node inside the retrieved document; it
    // is not part of either the caller-owned resource identity or
    // the base URI used by references nested in that document.
    let (resource_uri, fragment) = uri
        .split_once('#')
        .map_or((uri, None), |(resource, fragment)| {
            (resource, (!fragment.is_empty()).then_some(fragment))
        });
    let bytes = resolver
        .external_resource(resource_uri)
        .map_err(|error| {
            SignatureVerificationPipelineError::from(ReferenceProcessingError::UriDereference(
                error,
            ))
        })?
        .ok_or(SignatureVerificationPipelineError::InvalidStructure {
            reason: "KeyInfoReference external resource is unavailable",
        })?;
    // External KeyInfo bytes share the operation's work allowance even if decoding
    // fails before a document exists. Parsing the decoded text is a separate pass.
    context
        .budgets
        .execution
        .xml_parse_work()
        .charge_policy(bytes.len())?;
    let xml = crate::encoding::decode_xml_octets(
        bytes,
        context.policy.resources().max_xml_document_bytes,
    )
    .map_err(|error| map_key_info_xml_decode_error(&error))?;
    let settings =
        DocumentParseSettings::from_policy(*context.policy.xml(), context.policy.resources())
            .with_backend(context.budgets.xml_backend);
    let document = XmlDocument::parse_with_settings_and_budget(
        xml.into_owned(),
        settings,
        context.budgets.execution.xml_parse_work(),
    )
    .map_err(|error| map_document_parse_error(error, settings))?;
    document.with_view(|view| {
        let external_resolver = resolver.for_external_document_view(view, resource_uri);
        let target = match fragment {
            Some(fragment) => external_resolver
                .node_for_same_document_reference(&format!("#{fragment}"))
                .map_err(|error| {
                    SignatureVerificationPipelineError::from(
                        ReferenceProcessingError::UriDereference(error),
                    )
                })?
                .ok_or(SignatureVerificationPipelineError::InvalidStructure {
                    reason: "KeyInfoReference external target is missing or ambiguous",
                })?,
            _ => view.document().root_element(),
        };
        if !target.has_tag_name((XMLDSIG_NS, "KeyInfo")) {
            return Err(SignatureVerificationPipelineError::InvalidStructure {
                reason: "KeyInfoReference external target must be KeyInfo",
            });
        }
        let mut referenced = parse_referenced_key_info(
            target,
            &external_resolver,
            context,
            materialization,
            next_depth,
            super::parse::SourceContext {
                document_base: Some(resource_uri),
                origins: None,
            },
        )?;
        let mut nested_outcome = materialize_key_info_visit(
            &mut referenced,
            None,
            &external_resolver,
            context,
            materialization,
            next_depth,
        )?;
        nested_outcome.merge(materialize_retrieval_methods_with_budgets(
            &mut referenced,
            None,
            &external_resolver,
            context.policy,
            context.provider,
            context.budgets,
            &mut materialization.candidate_work,
        )?);
        // RetrievalMethod nodes are meaningful only in the document
        // whose resolver owns their same-document URI context.
        referenced.sources.retain(|source| {
            !matches!(source, super::parse::KeyInfoSource::RetrievalMethod { .. })
        });
        Ok((referenced, nested_outcome))
    })
}

/// Parse the `KeyInfo` a same-document `KeyInfoReference` selects, with the
/// element of each source when `track` is set.
fn parse_same_document_key_info<P: KeyInfoReferencePolicy>(
    uri: &str,
    track: bool,
    resolver: &UriReferenceResolver<'_>,
    context: &mut KeyInfoReferenceMaterializationContext<'_, '_, P>,
    materialization: &mut KeyInfoMaterializationState,
    depth: usize,
) -> Result<(KeyInfo, Option<Vec<SourceOrigin>>), SignatureVerificationPipelineError> {
    let node = resolver
        .node_for_same_document_reference(uri)
        .map_err(|error| {
            SignatureVerificationPipelineError::from(ReferenceProcessingError::UriDereference(
                error,
            ))
        })?
        .ok_or(SignatureVerificationPipelineError::InvalidStructure {
            reason: "KeyInfoReference target is missing or ambiguous",
        })?;
    if !node.has_tag_name((XMLDSIG_NS, "KeyInfo")) {
        return Err(SignatureVerificationPipelineError::InvalidStructure {
            reason: "KeyInfoReference target must be KeyInfo",
        });
    }
    let mut origins = track.then(Vec::new);
    let referenced = parse_referenced_key_info(
        node,
        resolver,
        context,
        materialization,
        depth,
        super::parse::SourceContext {
            document_base: None,
            origins: origins.as_mut(),
        },
    )?;
    Ok((referenced, origins))
}

fn materialize_key_info_visit<P: KeyInfoReferencePolicy>(
    key_info: &mut KeyInfo,
    mut origins: Option<&mut Vec<SourceOrigin>>,
    resolver: &UriReferenceResolver<'_>,
    context: &mut KeyInfoReferenceMaterializationContext<'_, '_, P>,
    materialization: &mut KeyInfoMaterializationState,
    depth: usize,
) -> Result<RetrievalMaterialization, SignatureVerificationPipelineError> {
    let mut materialized = Vec::new();
    // Origins, when tracked, stay index for index with the sources.
    let mut pending = origins
        .as_deref_mut()
        .map(|origins| std::mem::take(origins).into_iter());
    let mut materialized_origins = Vec::new();
    let mut outcome = RetrievalMaterialization::default();
    for source in std::mem::take(&mut key_info.sources) {
        let origin = pending.as_mut().and_then(Iterator::next);
        let source_work = match &source {
            super::parse::KeyInfoSource::X509Data(info) => info.certificates.len().max(1),
            _ => 1,
        };
        materialization.candidate_work = materialization.candidate_work.saturating_add(source_work);
        context
            .policy
            .resources()
            .validate_key_candidates(materialization.candidate_work)?;

        let super::parse::KeyInfoSource::KeyInfoReference { uri } = source else {
            materialized.push(source);
            materialized_origins.extend(origin);
            continue;
        };
        if !context.policy.key_info_reference_source_enabled() {
            return Err(crate::policy::PolicyViolation::KeyTrust {
                reason: "KeyInfoReference key sources are disabled",
            }
            .into());
        }
        if !context.policy.key_info_reference_uris().allows(&uri) {
            return Err(crate::policy::PolicyViolation::Uri {
                operation: "KeyInfoReference",
                reason: "URI class is disabled",
            }
            .into());
        }
        let next_depth = depth.saturating_add(1);
        context
            .policy
            .resources()
            .validate_key_info_reference_depth(next_depth)?;
        let cycle_key = (resolver.traversal_document_identity(), uri.clone());
        if !materialization.active.insert(cycle_key.clone()) {
            return Err(SignatureVerificationPipelineError::InvalidStructure {
                reason: "KeyInfoReference cycle detected",
            });
        }

        let is_same_document = uri.is_empty() || uri.starts_with('#');
        let (mut referenced, mut referenced_origins, mut nested_outcome) = if is_same_document {
            let (referenced, origins) = parse_same_document_key_info(
                &uri,
                origin.is_some(),
                resolver,
                context,
                materialization,
                next_depth,
            )?;
            (referenced, origins, RetrievalMaterialization::default())
        } else {
            let (referenced, outcome) = materialize_external_key_info(
                &uri,
                resolver,
                context,
                materialization,
                next_depth,
            )?;
            // Material from another document has no element in this one;
            // it is attributed to the instruction that retrieved it.
            let origins = origin.map(|origin| vec![origin.retrieved(); referenced.sources.len()]);
            (referenced, origins, outcome)
        };
        if is_same_document {
            nested_outcome.merge(materialize_key_info_visit(
                &mut referenced,
                referenced_origins.as_mut(),
                resolver,
                context,
                materialization,
                next_depth,
            )?);
        }
        outcome.merge(nested_outcome);
        materialization.active.remove(&cycle_key);
        materialized.extend(referenced.sources);
        materialized_origins.extend(referenced_origins.into_iter().flatten());
    }
    key_info.sources = materialized;
    if let Some(origins) = origins {
        debug_assert_eq!(materialized_origins.len(), key_info.sources.len());
        *origins = materialized_origins;
    }
    context
        .policy
        .resources()
        .validate_key_candidates(key_info.embedded_candidate_count())?;
    Ok(outcome)
}

fn map_key_info_xml_decode_error(
    error: &crate::encoding::XmlEncodingError,
) -> SignatureVerificationPipelineError {
    match error {
        crate::encoding::XmlEncodingError::DecodedLimit { maximum, actual } => {
            SignatureVerificationPipelineError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_DOCUMENT,
                    maximum: *maximum,
                    actual: *actual,
                },
            )
        }
        _ => SignatureVerificationPipelineError::InvalidStructure {
            reason: "KeyInfoReference external resource has an invalid XML encoding",
        },
    }
}

/// Resolved signature hints and experimental recipient mechanism metadata.
/// No key hint establishes trust or permission. The mutation handle is private
/// and bound to the original document, never an external document's local ID.
pub struct SignatureKeyInfoMetadata {
    /// Materialized recipient hints for KEM, ordinary hints otherwise.
    pub key_info: KeyInfo,
    /// Exact KEM parameter set, if the resolved graph contains one mechanism.
    pub encapsulation: Option<crate::provider::KeyEncapsulationAlgorithm>,
    /// Signing fills this `CipherValue`; verification only validates its target.
    #[cfg(feature = "xmldsig-sign")]
    pub(crate) cipher_value: Option<NodeId>,
}

/// Discover operation instructions in local `KeyInfo` references without consuming
/// unrelated key hints. A positive result requires full metadata validation.
///
/// # Errors
/// Returns an error for invalid resource limits, mismatched document identity,
/// or exhausted traversal, parsing, or reference-depth budgets.
pub fn has_same_document_encapsulation(
    node: Node<'_, '_>,
    resolver: &UriReferenceResolver<'_>,
    resources: &crate::policy::ResourcePolicy,
) -> Result<bool, DsigError> {
    resources.validate()?;
    let execution = TransformExecutionBudget::from_resources(resources);
    has_same_document_encapsulation_with_budget(node, resolver, resources, &execution)
}

pub(crate) fn has_same_document_encapsulation_with_budget(
    node: Node<'_, '_>,
    resolver: &UriReferenceResolver<'_>,
    resources: &crate::policy::ResourcePolicy,
    execution: &TransformExecutionBudget,
) -> Result<bool, DsigError> {
    has_encapsulation_with_budget::<crate::policy::SigningPolicy>(
        node, resolver, resources, execution, None,
    )
}

#[cfg(feature = "xmldsig-sign")]
pub(crate) fn has_signing_encapsulation_with_budget(
    node: Node<'_, '_>,
    resolver: &UriReferenceResolver<'_>,
    policy: &crate::policy::SigningPolicy,
    execution: &TransformExecutionBudget,
    backend: crate::XmlBackend,
) -> Result<bool, DsigError> {
    has_encapsulation_with_budget(
        node,
        resolver,
        &policy.resources,
        execution,
        Some((policy, backend)),
    )
}

fn has_encapsulation_with_budget<P: KeyInfoReferencePolicy>(
    node: Node<'_, '_>,
    resolver: &UriReferenceResolver<'_>,
    resources: &crate::policy::ResourcePolicy,
    execution: &TransformExecutionBudget,
    external: Option<(&P, crate::XmlBackend)>,
) -> Result<bool, DsigError> {
    discover_encapsulation_with_budget(node, resolver, resources, execution, external, None)
}

struct ExternalProbePath<'a> {
    uri: &'a str,
    parent: Option<&'a ExternalProbePath<'a>>,
}

struct ProbeContext<'a, P> {
    resources: &'a crate::policy::ResourcePolicy,
    external: Option<(&'a P, crate::XmlBackend)>,
    document_base: Option<&'a str>,
    external_path: Option<&'a ExternalProbePath<'a>>,
}

struct DiscoveryState<'a> {
    path: [Option<(usize, NodeId)>; crate::hard_limits::KEY_INFO_REFERENCE_DEPTH_CEILING + 1],
    work: usize,
    materialization: Option<&'a mut KeyInfoMaterializationState>,
}

fn discover_encapsulation_with_budget<P: KeyInfoReferencePolicy>(
    node: Node<'_, '_>,
    resolver: &UriReferenceResolver<'_>,
    resources: &crate::policy::ResourcePolicy,
    execution: &TransformExecutionBudget,
    external: Option<(&P, crate::XmlBackend)>,
    materialization: Option<&mut KeyInfoMaterializationState>,
) -> Result<bool, DsigError> {
    if resolver.node_for_node_id(node.id()) != Some(node) {
        return Err(DsigError::InvalidStructure {
            reason: "KeyInfo and resolver belong to different documents",
        });
    }
    visit_encapsulation(
        node,
        resolver,
        &ProbeContext {
            resources,
            external,
            document_base: None,
            external_path: None,
        },
        &mut DiscoveryState {
            path: [None; crate::hard_limits::KEY_INFO_REFERENCE_DEPTH_CEILING + 1],
            work: 0,
            materialization,
        },
        0,
        execution,
    )
}

fn record_probe_encapsulation<P: KeyInfoReferencePolicy>(
    node: Node<'_, '_>,
    resolver: &UriReferenceResolver<'_>,
    context: &ProbeContext<'_, P>,
    state: &mut DiscoveryState<'_>,
    depth: usize,
) -> Result<(), DsigError> {
    if let Some(materialization) = state.materialization.as_deref_mut() {
        let mechanism = crate::key_establishment::parse_encapsulation(
            node,
            materialization.encapsulation_template,
        )
        .map_err(|_| DsigError::InvalidStructure {
            reason: "invalid encapsulation mechanism in resolved KeyInfo",
        })?;
        materialization.record_encapsulation(mechanism, resolver, depth)?;
        if let (Some(mechanism), Some((policy, _))) =
            (&materialization.encapsulation, context.external)
        {
            policy
                .key_establishment()
                .check_encapsulation(mechanism.algorithm)?;
        }
    }
    Ok(())
}

fn resolve_probe_uri<P: KeyInfoReferencePolicy>(
    child: Node<'_, '_>,
    uri: &str,
    context: &ProbeContext<'_, P>,
    materializing: bool,
    execution: &TransformExecutionBudget,
) -> Result<Option<String>, DsigError> {
    let Some((policy, _)) = context.external else {
        return Ok(None);
    };
    // XMLDSig 1.1 section 4.5.10 gives KeyInfoReference the same URI
    // dereferencing behavior as Reference, including external XML.
    // https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-KeyInfoReference
    let resolved = crate::c14n::xml_base::resolve_uri_from_node_with_document_base_with_budget(
        child,
        uri,
        context.document_base,
        execution.xml_base_resolution(),
    )
    .map_err(|error| {
        ReferenceProcessingError::UriDereference(super::uri::map_xml_base_resolution_error(error))
    })?;
    if !policy.key_info_reference_uris().allows(&resolved) {
        if materializing {
            return Err(crate::policy::PolicyViolation::Uri {
                operation: "KeyInfoReference",
                reason: "URI class is disabled",
            }
            .into());
        }
        return Ok(None);
    }
    // Resource identity, not a reparsed arena ID, detects external
    // cycles. The active URI chain borrows stack frames, no clones.
    let mut ancestor = context.external_path;
    while let Some(entry) = ancestor {
        if entry.uri == resolved {
            break;
        }
        ancestor = entry.parent;
    }
    if ancestor.is_some() {
        if materializing {
            return Err(DsigError::InvalidStructure {
                reason: "KeyInfoReference cycle detected",
            });
        }
        return Ok(None);
    }
    Ok(Some(resolved))
}

fn visit_external_encapsulation<P: KeyInfoReferencePolicy>(
    child: Node<'_, '_>,
    uri: &str,
    resolver: &UriReferenceResolver<'_>,
    context: &ProbeContext<'_, P>,
    state: &mut DiscoveryState<'_>,
    depth: usize,
    execution: &TransformExecutionBudget,
) -> Result<bool, DsigError> {
    let resources = context.resources;
    let Some((policy, backend)) = context.external else {
        return Ok(false);
    };
    let Some(absolute_uri) = resolve_probe_uri(
        child,
        uri,
        context,
        state.materialization.is_some(),
        execution,
    )?
    else {
        return Ok(false);
    };
    let external_entry = ExternalProbePath {
        uri: &absolute_uri,
        parent: context.external_path,
    };
    let (resource, fragment) = absolute_uri
        .split_once('#')
        .map_or((absolute_uri.as_str(), None), |(resource, fragment)| {
            (resource, Some(fragment))
        });
    resources.validate_key_info_reference_depth(depth + 1)?;
    if depth == crate::hard_limits::KEY_INFO_REFERENCE_DEPTH_CEILING {
        return Err(DsigError::InvalidStructure {
            reason: "KeyInfoReference safety depth exceeded",
        });
    }
    let bytes = match resolver.external_resource(resource) {
        Ok(Some(bytes)) => bytes,
        Err(TransformError::Policy(violation)) => {
            return Err(DsigError::Policy(violation));
        }
        _ => return Ok(false),
    };
    execution.xml_parse_work().charge_policy(bytes.len())?;
    let xml = crate::encoding::decode_xml_octets(bytes, resources.max_xml_document_bytes)
        .map_err(|error| map_key_info_xml_decode_error(&error))?;
    let settings =
        DocumentParseSettings::from_policy(*policy.xml(), resources).with_backend(backend);
    let document = XmlDocument::parse_with_settings_and_budget(
        xml.into_owned(),
        settings,
        execution.xml_parse_work(),
    )
    .map_err(|error| map_document_parse_error(error, settings))?;
    document.with_view(|view| {
        let external_resolver = resolver.for_external_document_view(view, resource);
        let target = match fragment {
            Some(fragment) if !fragment.is_empty() => external_resolver
                .node_for_same_document_reference_with_budget(
                    &absolute_uri[resource.len()..],
                    Some(execution.node_set_materialization()),
                )
                .map_err(ReferenceProcessingError::UriDereference)?,
            _ => Some(view.document().root_element()),
        };
        let Some(target) = target else {
            return Ok(false);
        };
        if !target.has_tag_name((XMLDSIG_NS, "KeyInfo")) {
            return Ok(false);
        }
        visit_encapsulation(
            target,
            &external_resolver,
            &ProbeContext {
                document_base: Some(resource),
                external_path: Some(&external_entry),
                resources,
                external: context.external,
            },
            state,
            depth + 1,
            execution,
        )
    })
}

fn visit_encapsulation<P: KeyInfoReferencePolicy>(
    node: Node<'_, '_>,
    resolver: &UriReferenceResolver<'_>,
    context: &ProbeContext<'_, P>,
    state: &mut DiscoveryState<'_>,
    depth: usize,
    execution: &TransformExecutionBudget,
) -> Result<bool, DsigError> {
    let ProbeContext {
        resources,
        external,
        ..
    } = *context;
    resources.validate_key_info_reference_depth(depth)?;
    if depth > crate::hard_limits::KEY_INFO_REFERENCE_DEPTH_CEILING {
        return Err(DsigError::InvalidStructure {
            reason: "KeyInfoReference safety depth exceeded",
        });
    }
    // Every document on the active stack remains alive for this traversal;
    // arena identity distinguishes equal node IDs in different documents.
    let identity = (std::ptr::from_ref(node.document()) as usize, node.id());
    if state.path[..depth].contains(&Some(identity)) {
        if state.materialization.is_some() {
            return Err(DsigError::InvalidStructure {
                reason: "KeyInfoReference cycle detected",
            });
        }
        return Ok(false);
    }
    state.path[depth] = Some(identity);
    let mut found = false;
    for child in node.children().filter(Node::is_element) {
        let work = match state.materialization.as_deref_mut() {
            Some(materialization) => &mut materialization.candidate_work,
            None => &mut state.work,
        };
        *work += 1;
        resources.validate_key_candidates(*work)?;
        if child.has_tag_name((
            crate::key_establishment::ENCAPSULATION_NS,
            "EncapsulationMechanism",
        )) {
            if state.materialization.is_none() {
                return Ok(true);
            }
            record_probe_encapsulation(child, resolver, context, state, depth)?;
            found = true;
            continue;
        }
        if !child.has_tag_name(("http://www.w3.org/2009/xmldsig11#", "KeyInfoReference")) {
            continue;
        }
        let Some(uri) = child.attribute("URI") else {
            continue;
        };
        if uri.len() > super::parse::MAX_KEY_NAME_TEXT_LEN {
            continue;
        }
        if state.materialization.is_some()
            && let Some((policy, _)) = external
            && !policy.key_info_reference_source_enabled()
        {
            return Err(crate::policy::PolicyViolation::KeyTrust {
                reason: "KeyInfoReference key sources are disabled",
            }
            .into());
        }
        if !uri.is_empty() && !uri.starts_with('#') {
            let target_found = visit_external_encapsulation(
                child, uri, resolver, context, state, depth, execution,
            )?;
            if target_found {
                if state.materialization.is_none() {
                    return Ok(true);
                }
                found = true;
            }
            continue;
        }
        // Unconsumed key hints are not validity requirements. Mechanism
        // discovery checks only reachable KeyInfo instructions, not key
        // candidates that an explicitly supplied recipient never uses.
        // The target type is defined by XMLDSig 1.1 section 4.5.10.
        // https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-KeyInfoReference
        if state.materialization.is_some()
            && let Some((policy, _)) = external
            && !policy.key_info_reference_uris().allows(uri)
        {
            return Err(crate::policy::PolicyViolation::Uri {
                operation: "KeyInfoReference",
                reason: "URI class is disabled",
            }
            .into());
        }
        let target = match resolver.node_for_same_document_reference_with_budget(
            uri,
            Some(execution.node_set_materialization()),
        ) {
            Ok(Some(target)) => target,
            Err(TransformError::Policy(violation)) => return Err(DsigError::Policy(violation)),
            _ => continue,
        };
        if target.has_tag_name((XMLDSIG_NS, "KeyInfo"))
            && visit_encapsulation(target, resolver, context, state, depth + 1, execution)?
        {
            if state.materialization.is_none() {
                return Ok(true);
            }
            found = true;
        }
    }
    Ok(found)
}

fn inspect_signature_key_info_with_budgets<P: KeyInfoReferencePolicy>(
    node: Node<'_, '_>,
    resolver: &UriReferenceResolver<'_>,
    policy: &P,
    provider: &dyn crate::provider::CryptoProvider,
    budgets: &mut RetrievalMaterializationBudgets<'_>,
    template: bool,
    retain_recipient_hints: bool,
) -> Result<SignatureKeyInfoMetadata, DsigError> {
    if resolver.node_for_node_id(node.id()) != Some(node) {
        return Err(DsigError::InvalidStructure {
            reason: "KeyInfo and resolver belong to different documents",
        });
    }
    let mut materialization = KeyInfoMaterializationState {
        collect_encapsulation: true,
        encapsulation_template: template,
        retain_encapsulation_target: true,
        ..Default::default()
    };
    materialization.observe_encapsulation(node, resolver, 0)?;
    if let Some(mechanism) = &materialization.encapsulation {
        policy
            .key_establishment()
            .check_encapsulation(mechanism.algorithm)?;
    }
    let mut key_info = super::parse::parse_key_info_in_session(
        node,
        provider,
        budgets.execution.xml_base_resolution(),
        policy.resources(),
        super::parse::SourceContext::default(),
        policy.certificate_signature_algorithms(),
        &mut budgets.key_info_parse.borrow_mut(),
    )
    .map_err(map_key_info_parse_error)?;
    materialize_key_info_references_with_budgets(
        &mut key_info,
        None,
        resolver,
        policy,
        provider,
        budgets,
        &mut materialization,
    )?;
    let encapsulation = materialization
        .encapsulation
        .as_ref()
        .map(|value| value.algorithm);
    let cipher_value =
        if let Some((resource, cipher, recipient)) = materialization.encapsulation_target.take() {
            // Product mutation boundary: immutable external resources cannot be
            // updated by signing, and foreign node IDs must not address this DOM.
            if resource != resolver.traversal_document_identity() {
                return Err(DsigError::InvalidStructure {
                    reason: "recipient metadata requires its original document context",
                });
            }
            if retain_recipient_hints {
                let recipient =
                    resolver
                        .node_for_node_id(recipient)
                        .ok_or(DsigError::InvalidStructure {
                            reason: "recipient KeyInfo target is unavailable",
                        })?;
                key_info = super::parse::parse_key_info_in_session(
                    recipient,
                    provider,
                    budgets.execution.xml_base_resolution(),
                    policy.resources(),
                    super::parse::SourceContext::default(),
                    policy.certificate_signature_algorithms(),
                    &mut budgets.key_info_parse.borrow_mut(),
                )
                .map_err(map_key_info_parse_error)?;
                // Recipient references use the same cumulative candidate, parse and
                // external-resource allowances as the containing mechanism graph.
                materialization.reference_depth_base = materialization.encapsulation_depth;
                materialize_key_info_references_with_budgets(
                    &mut key_info,
                    None,
                    resolver,
                    policy,
                    provider,
                    budgets,
                    &mut materialization,
                )?;
            }
            Some(cipher)
        } else {
            None
        };
    #[cfg(not(feature = "xmldsig-sign"))]
    let _ = cipher_value;
    Ok(SignatureKeyInfoMetadata {
        key_info,
        encapsulation,
        #[cfg(feature = "xmldsig-sign")]
        cipher_value,
    })
}

#[cfg(feature = "xmldsig-sign")]
pub(crate) fn inspect_signing_key_info_with_budgets(
    node: Node<'_, '_>,
    resolver: &UriReferenceResolver<'_>,
    policy: &crate::policy::SigningPolicy,
    provider: &dyn crate::provider::CryptoProvider,
    execution: &TransformExecutionBudget,
    xpath_parse: &mut XPathSignatureParseBudget,
    xml_backend: crate::XmlBackend,
) -> Result<SignatureKeyInfoMetadata, DsigError> {
    inspect_signature_key_info_with_budgets(
        node,
        resolver,
        policy,
        provider,
        &mut RetrievalMaterializationBudgets {
            key_info_parse: &RefCell::new(super::parse::KeyInfoParseUsage::new(&policy.resources)),
            xpath_parse,
            execution,
            resources: &policy.resources,
            certificate_signature_algorithms: None,
            xml_backend,
        },
        true,
        false,
    )
}

fn inspect_signature_key_info_for_policy<P: KeyInfoReferencePolicy>(
    node: Node<'_, '_>,
    resolver: UriReferenceResolver<'_>,
    policy: &P,
    provider: &dyn crate::provider::CryptoProvider,
    xml_backend: crate::XmlBackend,
    template: bool,
) -> Result<SignatureKeyInfoMetadata, DsigError> {
    let resolver = resolver.with_external_resource_limits(
        policy.resources().max_external_resource_bytes,
        policy.resources().max_external_resource_total_bytes,
    );
    let execution = TransformExecutionBudget::from_resources(policy.resources());
    let mut xpath_parse = XPathSignatureParseBudget::for_execution(policy.resources(), &execution);
    inspect_signature_key_info_with_budgets(
        node,
        &resolver,
        policy,
        provider,
        &mut RetrievalMaterializationBudgets {
            key_info_parse: &RefCell::new(super::parse::KeyInfoParseUsage::new(policy.resources())),
            xpath_parse: &mut xpath_parse,
            execution: &execution,
            resources: policy.resources(),
            certificate_signature_algorithms: policy.certificate_signature_algorithms(),
            xml_backend,
        },
        template,
        true,
    )
}

/// Inspect signing hints and KEM targets through the bounded `KeyInfoReference`
/// graph. KEM targets must belong to the document that will be mutated.
///
/// # Errors
/// Returns an error for invalid policy, malformed or cyclic references, denied
/// sources or URIs, exhausted resources, or a KEM target outside the document.
pub fn inspect_signing_key_info(
    node: Node<'_, '_>,
    resolver: UriReferenceResolver<'_>,
    policy: &crate::policy::SigningPolicy,
    provider: &dyn crate::provider::CryptoProvider,
    xml_backend: crate::XmlBackend,
) -> Result<SignatureKeyInfoMetadata, DsigError> {
    policy.validate()?;
    inspect_signature_key_info_for_policy(node, resolver, policy, provider, xml_backend, true)
}

/// Inspect verification hints and KEM metadata with the same source, URI,
/// candidate, depth and cycle gates as core verification.
/// This original-document metadata API requires KEM targets in that document;
/// core verification also supports caller-supplied external KEM resources.
///
/// # Errors
/// Returns an error for invalid policy or metadata, denied key sources or URIs,
/// exhausted resources, reference cycles, or an external KEM mutation target.
pub fn inspect_verification_key_info(
    node: Node<'_, '_>,
    resolver: UriReferenceResolver<'_>,
    policy: &crate::policy::VerificationPolicy,
    provider: &dyn crate::provider::CryptoProvider,
    xml_backend: crate::XmlBackend,
) -> Result<SignatureKeyInfoMetadata, DsigError> {
    policy.validate()?;
    inspect_signature_key_info_for_policy(node, resolver, policy, provider, xml_backend, false)
}

/// Inspect operation instructions for a caller-pinned key, leaving unrelated
/// lookup hints unconsumed. Discovery and materialization share one allowance.
/// Like `inspect_verification_key_info`, this original-document metadata API
/// rejects external KEM targets; it never reports a permitted external mechanism
/// as absent. Use core verification with a decapsulation key for those targets.
///
/// # Errors
/// Returns an error when discovery or required metadata processing fails policy,
/// structure, identity, or resource checks. No reachable mechanism yields `None`.
pub fn inspect_pinned_verification_key_info(
    node: Node<'_, '_>,
    resolver: UriReferenceResolver<'_>,
    policy: &crate::policy::VerificationPolicy,
    provider: &dyn crate::provider::CryptoProvider,
    xml_backend: crate::XmlBackend,
) -> Result<Option<SignatureKeyInfoMetadata>, DsigError> {
    policy.validate()?;
    let resolver = resolver.with_external_resource_limits(
        policy.resources.max_external_resource_bytes,
        policy.resources.max_external_resource_total_bytes,
    );
    let execution = TransformExecutionBudget::from_resources(&policy.resources);
    if !has_encapsulation_with_budget(
        node,
        &resolver,
        &policy.resources,
        &execution,
        Some((policy, xml_backend)),
    )? {
        return Ok(None);
    }
    let mut xpath_parse = XPathSignatureParseBudget::for_execution(&policy.resources, &execution);
    inspect_signature_key_info_with_budgets(
        node,
        &resolver,
        policy,
        provider,
        &mut RetrievalMaterializationBudgets {
            key_info_parse: &RefCell::new(super::parse::KeyInfoParseUsage::new(&policy.resources)),
            xpath_parse: &mut xpath_parse,
            execution: &execution,
            resources: &policy.resources,
            certificate_signature_algorithms: policy.certificate_signature_algorithms(),
            xml_backend,
        },
        false,
        true,
    )
    .map(Some)
}

fn materialize_key_info_references_for_policy<P: KeyInfoReferencePolicy>(
    key_info: &mut KeyInfo,
    resolver: UriReferenceResolver<'_>,
    policy: &P,
    provider: &dyn crate::provider::CryptoProvider,
    xml_backend: crate::XmlBackend,
) -> Result<(), DsigError> {
    let resolver = resolver.with_external_resource_limits(
        policy.resources().max_external_resource_bytes,
        policy.resources().max_external_resource_total_bytes,
    );
    let execution_budget = TransformExecutionBudget::from_resources(policy.resources());
    let mut xpath_parse_budget =
        XPathSignatureParseBudget::for_execution(policy.resources(), &execution_budget);
    let mut budgets = RetrievalMaterializationBudgets {
        key_info_parse: &RefCell::new(super::parse::KeyInfoParseUsage::new(policy.resources())),
        xpath_parse: &mut xpath_parse_budget,
        execution: &execution_budget,
        resources: policy.resources(),
        certificate_signature_algorithms: policy.certificate_signature_algorithms(),
        xml_backend,
    };
    let mut materialization = KeyInfoMaterializationState::default();
    // Candidate-local retrieval failures remain deferred: this metadata-only
    // entry point cannot know whether a later key-selection stage needs them.
    materialize_key_info_references_with_budgets(
        key_info,
        None,
        &resolver,
        policy,
        provider,
        &mut budgets,
        &mut materialization,
    )?;
    Ok(())
}

/// Resolve and recursively expand policy-allowed `KeyInfoReference` sources
/// while preparing caller-supplied key material for signing.
///
/// The recursive reference traversal shares the verifier's candidate-work,
/// depth, cycle, target, XML parsing, and external-resource bounds. Retrieval
/// methods nested in an external referenced document are materialized while
/// that document's URI context is active; retrieval methods in the caller's
/// document remain the responsibility of the complete signing pipeline.
/// candidate failures are deferred so an earlier usable key source can still
/// be selected; the complete signing pipeline reports the retained failure if
/// no source resolves to a key. URI classes remain controlled by the signing
/// policy's `uris` field; external
/// bytes must be attached to `resolver` explicitly by the caller. The resolver
/// is consumed so this operation can bind a fresh aggregate external-resource
/// budget to the supplied policy. `xml_backend` is used for every recursively
/// referenced XML document, preserving the caller's parser semantics.
///
/// # Errors
/// Returns an error for invalid policy, denied references, missing or malformed
/// targets, cycles, or exhausted reference and materialization budgets.
pub fn materialize_signing_key_info_references(
    key_info: &mut KeyInfo,
    resolver: UriReferenceResolver<'_>,
    policy: &crate::policy::SigningPolicy,
    provider: &dyn crate::provider::CryptoProvider,
    xml_backend: crate::XmlBackend,
) -> Result<(), DsigError> {
    policy.validate()?;
    materialize_key_info_references_for_policy(key_info, resolver, policy, provider, xml_backend)
}

/// Resolve and recursively expand policy-allowed `KeyInfoReference` sources
/// before verification key selection.
///
/// In addition to URI and resource policy, this entry point enforces the
/// verification policy's `KeySourceKind::KeyInfoReference` trust gate. Retrieval
/// methods nested in an external referenced document are materialized in that
/// document's URI context; retrieval methods in the caller's document remain
/// the responsibility of the complete verification pipeline. Candidate-local
/// retrieval failures remain deferred so usable sibling sources survive; the
/// complete pipeline reports one only when key selection has no fallback.
/// External bytes must be attached to `resolver` explicitly by the caller. The resolver is
/// consumed so this operation can bind a fresh aggregate external-resource
/// budget to the supplied policy. `xml_backend` is used for every recursively
/// referenced XML document, preserving the caller's parser semantics.
///
/// # Errors
/// Returns an error for invalid policy, disabled reference sources or URI classes,
/// missing or malformed targets, cycles, or exhausted materialization budgets.
pub fn materialize_verification_key_info_references(
    key_info: &mut KeyInfo,
    resolver: UriReferenceResolver<'_>,
    policy: &crate::policy::VerificationPolicy,
    provider: &dyn crate::provider::CryptoProvider,
    xml_backend: crate::XmlBackend,
) -> Result<(), DsigError> {
    policy.validate()?;
    materialize_key_info_references_for_policy(key_info, resolver, policy, provider, xml_backend)
}

struct RetrievalHint {
    uri: String,
    resource_type: Option<String>,
    transforms: RetrievalMethodTransforms,
}

struct RetrievalUsage<'a> {
    total_binary_len: &'a mut usize,
    candidate_work: &'a mut usize,
    outcome: &'a mut RetrievalMaterialization,
}

fn materialize_raw_certificate<P: KeyInfoReferencePolicy>(
    hint: RetrievalHint,
    resolver: &UriReferenceResolver<'_>,
    context: &mut KeyInfoReferenceMaterializationContext<'_, '_, P>,
    usage: &mut RetrievalUsage<'_>,
) -> Result<super::parse::KeyInfoSource, DsigError> {
    let RetrievalHint {
        uri: resolved_uri,
        resource_type,
        transforms,
    } = hint;
    let allowed_uri_types = context.policy.retrieval_method_uris();
    let budgets = &mut *context.budgets;
    let candidate_work = &mut *usage.candidate_work;
    let total_binary_len = &mut *usage.total_binary_len;
    let outcome = &mut *usage.outcome;
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
            SignatureVerificationPipelineError::Reference(ReferenceProcessingError::Transform(
                super::TransformError::UnsupportedUri(resolved_uri.clone()),
            ))
        });
        return Ok(super::parse::KeyInfoSource::RetrievalMethod {
            uri: resolved_uri,
            resource_type,
            transforms,
        });
    };
    *candidate_work = candidate_work.saturating_add(1);
    budgets.resources.validate_key_candidates(*candidate_work)?;
    if certificate.len() > MAX_X509_DECODED_BINARY_LEN {
        return Err(SignatureVerificationPipelineError::InvalidStructure {
            reason: "raw X509 RetrievalMethod certificate exceeds maximum allowed length",
        });
    }
    add_retrieval_binary_usage(total_binary_len, certificate.len())?;
    let parsed = match super::parse::parse_x509_certificate_in(
        certificate,
        &budgets.key_info_parse.borrow().certificates,
    ) {
        Ok(parsed) => parsed,
        Err(error) => {
            let error = map_key_info_parse_error(error);
            if matches!(error, SignatureVerificationPipelineError::Policy(_)) {
                return Err(error);
            }
            outcome.deferred_error.get_or_insert(error);
            return Ok(super::parse::KeyInfoSource::RetrievalMethod {
                uri: resolved_uri,
                resource_type,
                transforms,
            });
        }
    };
    Ok(super::parse::KeyInfoSource::X509Data(
        super::parse::X509DataInfo {
            certificates: vec![certificate.to_vec()],
            parsed_certificates: vec![parsed],
            certificate_chain: vec![0],
            ..super::parse::X509DataInfo::default()
        },
    ))
}

/// The materialized source and, when read, the selected `X509Data` element.
fn materialize_x509_data<P: KeyInfoReferencePolicy>(
    hint: RetrievalHint,
    resolver: &UriReferenceResolver<'_>,
    context: &mut KeyInfoReferenceMaterializationContext<'_, '_, P>,
    usage: &mut RetrievalUsage<'_>,
) -> Result<(super::parse::KeyInfoSource, Option<NodeId>), DsigError> {
    let RetrievalHint {
        uri: resolved_uri,
        resource_type,
        transforms,
    } = hint;
    let policy = context.policy;
    let provider = context.provider;
    let allowed_uri_types = policy.retrieval_method_uris();
    let allowed_transforms = policy.allowed_transforms();
    let budgets = &mut *context.budgets;
    let candidate_work = &mut *usage.candidate_work;
    let total_binary_len = &mut *usage.total_binary_len;
    let outcome = &mut *usage.outcome;
    if !allowed_uri_types.allows(&resolved_uri) {
        return Err(crate::policy::PolicyViolation::Uri {
            operation: "verification",
            reason: "retrieval method URI class is not permitted",
        }
        .into());
    }
    let target = resolver
        .node_for_same_document_reference(&resolved_uri)
        .map_err(ReferenceProcessingError::Transform)?;
    let Some(target) = target else {
        outcome.deferred_error.get_or_insert(
            SignatureVerificationPipelineError::InvalidStructure {
                reason: "X509Data RetrievalMethod target is missing or ambiguous",
            },
        );
        return Ok((
            super::parse::KeyInfoSource::RetrievalMethod {
                uri: resolved_uri,
                resource_type,
                transforms,
            },
            None,
        ));
    };
    let node = match transforms {
        RetrievalMethodTransforms::None if target.has_tag_name((XMLDSIG_NS, "X509Data")) => target,
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
            budgets
                .xpath_parse
                .validate_expression(&expression)
                .map_err(ReferenceProcessingError::Transform)?;
            budgets
                .xpath_parse
                .validate_namespaces(&namespaces)
                .map_err(ReferenceProcessingError::Transform)?;
            select_retrieved_x509_data_root(target, budgets.execution)?
        }
        RetrievalMethodTransforms::Unsupported => {
            return Err(SignatureVerificationPipelineError::InvalidStructure {
                reason: "X509Data RetrievalMethod contains unsupported transforms",
            });
        }
    };
    super::parse::validate_x509_digest_policy(node, &|algorithm| {
        policy.check_digest_algorithm(algorithm)
    })
    .map_err(map_key_info_parse_error)?;
    let data = parse_x509_data_dispatch_with_budget_and_provider(
        node,
        total_binary_len,
        candidate_work,
        provider,
        budgets.resources,
        budgets.certificate_signature_algorithms,
        &budgets.key_info_parse.borrow().certificates,
    )
    .map_err(map_key_info_parse_error)?;
    Ok((super::parse::KeyInfoSource::X509Data(data), Some(node.id())))
}

fn materialize_retrieval_methods_with_budgets<P: KeyInfoReferencePolicy>(
    key_info: &mut KeyInfo,
    mut origins: Option<&mut Vec<SourceOrigin>>,
    resolver: &UriReferenceResolver<'_>,
    policy: &P,
    provider: &dyn crate::provider::CryptoProvider,
    budgets: &mut RetrievalMaterializationBudgets<'_>,
    candidate_work: &mut usize,
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
    // Origins, when tracked, stay index for index with the sources.
    let mut pending = origins
        .as_deref_mut()
        .map(|origins| std::mem::take(origins).into_iter());
    let mut materialized_origins = Vec::new();
    let mut outcome = RetrievalMaterialization::default();
    for source in std::mem::take(&mut key_info.sources) {
        let origin = pending.as_mut().and_then(Iterator::next);
        let super::parse::KeyInfoSource::RetrievalMethod {
            uri: resolved_uri,
            resource_type,
            transforms,
        } = source
        else {
            materialized.push(source);
            materialized_origins.extend(origin);
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

        let hint = RetrievalHint {
            uri: resolved_uri,
            resource_type,
            transforms,
        };
        let mut context = KeyInfoReferenceMaterializationContext {
            policy,
            provider,
            budgets,
        };
        let mut usage = RetrievalUsage {
            total_binary_len: &mut total_binary_len,
            candidate_work,
            outcome: &mut outcome,
        };
        let (source, element) = if hint.resource_type.as_deref()
            == Some("http://www.w3.org/2000/09/xmldsig#rawX509Certificate")
        {
            (
                materialize_raw_certificate(hint, resolver, &mut context, &mut usage)?,
                None,
            )
        } else if hint.resource_type.as_deref()
            == Some("http://www.w3.org/2000/09/xmldsig#X509Data")
        {
            materialize_x509_data(hint, resolver, &mut context, &mut usage)?
        } else {
            (
                super::parse::KeyInfoSource::RetrievalMethod {
                    uri: hint.uri,
                    resource_type: hint.resource_type,
                    transforms: hint.transforms,
                },
                None,
            )
        };
        // A selected X509Data element of this document is the source; a raw
        // external certificate is attributed to its RetrievalMethod.
        materialized_origins.extend(origin.map(|origin| match (&source, element) {
            (_, Some(element)) => SourceOrigin::Element(element),
            (super::parse::KeyInfoSource::RetrievalMethod { .. }, None) => origin,
            (_, None) => origin.retrieved(),
        }));
        materialized.push(source);
    }
    key_info.sources = materialized;
    if let Some(origins) = origins {
        debug_assert_eq!(materialized_origins.len(), key_info.sources.len());
        *origins = materialized_origins;
    }
    Ok(outcome)
}

fn select_retrieved_x509_data_root<'a, 'input>(
    target: Node<'a, 'input>,
    execution_budget: &TransformExecutionBudget,
) -> Result<Node<'a, 'input>, SignatureVerificationPipelineError> {
    // XMLDSig XPath filtering evaluates the predicate for every node in the
    // dereferenced node-set, including attribute and namespace nodes. The
    // element-only scan below selects X509Data but must not undercount that
    // XPath context cardinality.
    let context_nodes = NodeSet::ensure_subtree_materialization_fits_with_budget(
        target,
        false,
        execution_budget.node_set_materialization(),
    )
    .map_err(ReferenceProcessingError::Transform)?;
    execution_budget
        .validate_xpath_context_evaluations(context_nodes)
        .map_err(ReferenceProcessingError::Transform)?;
    execution_budget
        .charge_xpath_work(context_nodes)
        .map_err(ReferenceProcessingError::Transform)?;
    execution_budget
        .charge_node_filter_work(context_nodes)
        .map_err(ReferenceProcessingError::Transform)?;
    let mut root = None;
    for candidate in target.descendants() {
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
    let mut xpath_parse_budget = XPathSignatureParseBudget::default();
    let execution_budget = TransformExecutionBudget::default();
    let resources = crate::policy::ResourcePolicy::default();
    let mut budgets = RetrievalMaterializationBudgets {
        key_info_parse: &RefCell::new(super::parse::KeyInfoParseUsage::new(&resources)),
        xpath_parse: &mut xpath_parse_budget,
        execution: &execution_budget,
        resources: &resources,
        certificate_signature_algorithms: None,
        xml_backend: crate::XmlBackend::default(),
    };
    let mut candidate_work = key_info.embedded_candidate_count();
    let mut policy = crate::policy::VerificationPolicy::default();
    policy.uris.retrieval_methods = allowed_uri_types;
    policy.transforms.allowed_algorithms = allowed_transforms.cloned();
    materialize_retrieval_methods_with_budgets(
        key_info,
        None,
        resolver,
        &policy,
        provider,
        &mut budgets,
        &mut candidate_work,
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

fn manifest_reference_failure_reason(
    error: ReferenceProcessingError,
    ref_index: usize,
) -> FailureReason {
    // Same Unavailable outcome as a SignedInfo Reference without caller bytes.
    if matches!(
        error,
        ReferenceProcessingError::UriDereference(TransformError::ExternalResourceUnavailable(_))
    ) {
        return FailureReason::ReferenceUnavailable { ref_index };
    }
    match error.into_policy_violation() {
        Ok(_) => FailureReason::ReferencePolicyViolation { ref_index },
        Err(_) => FailureReason::ReferenceProcessingFailure { ref_index },
    }
}

struct CompiledManifestReference {
    index: usize,
    reference: Reference,
    reference_node_id: NodeId,
}

struct CompiledManifestInvalid {
    result: ReferenceResult,
}

enum ScheduledManifestReference {
    Parsed {
        node: OperationNodeId,
        reference: CompiledManifestReference,
    },
    Invalid {
        node: OperationNodeId,
        invalid: CompiledManifestInvalid,
    },
}

impl ScheduledManifestReference {
    fn index(&self) -> usize {
        match self {
            Self::Parsed { reference, .. } => reference.index,
            Self::Invalid { invalid, .. } => invalid.result.reference_index,
        }
    }
}

struct ManifestVerification<'context, 'inputs, C> {
    context: &'context VerifyContext<'inputs>,
    capture: &'context C,
}

fn schedule_manifest_references(
    operation: &mut OperationExecutionContext<
        &crate::policy::VerificationPolicy,
        &VerificationOperationBudgets,
    >,
    view: DocumentView<'_>,
    resolver: &UriReferenceResolver<'_>,
    parsed: ParsedManifestReferences,
    discovery: OperationNodeId,
) -> Result<Vec<ScheduledManifestReference>, DsigError> {
    operation.extend();
    let mut scheduled = Vec::with_capacity(parsed.references.len() + parsed.invalid_results.len());
    for item in parsed.references {
        let resource = operation.budgets().resource_identity_for_reference(
            &item.reference,
            item.index,
            resolver,
            view,
            resolver.node_for_node_id(item.reference_node_id),
        );
        let node = operation.add_node(
            OperationNodeKind::Digest { index: item.index },
            OperationStage::AuthenticatedDependency,
            Some(resource.clone()),
        );
        operation
            .add_dependency(node, discovery)
            .map_err(map_verification_plan_error)?;
        scheduled.push(ScheduledManifestReference::Parsed {
            node,
            reference: item,
        });
    }
    for item in parsed.invalid_results {
        let node = operation.add_node(
            OperationNodeKind::Digest {
                index: item.result.reference_index,
            },
            OperationStage::AuthenticatedDependency,
            None,
        );
        operation
            .add_dependency(node, discovery)
            .map_err(map_verification_plan_error)?;
        scheduled.push(ScheduledManifestReference::Invalid {
            node,
            invalid: item,
        });
    }
    scheduled.sort_by_key(ScheduledManifestReference::index);
    operation.compile().map_err(map_verification_plan_error)?;
    Ok(scheduled)
}

fn evaluate_manifest_reference<C: VerificationCapture>(
    reference: &Reference,
    index: usize,
    execution: &ReferenceExecutionContext<'_, C>,
    resolver: &UriReferenceResolver<'_>,
    signature_node: Node<'_, '_>,
    ctx: &VerifyContext<'_>,
    reference_node: Option<Node<'_, '_>>,
) -> ReferenceResult {
    if execution.transform_budget.remaining_c14n_output() == 0
        || super::transforms::validate_relationship_chain(
            &reference.transforms,
            ctx.policy.transforms.opc_relationship_edition,
        )
        .is_err()
        || reference.transforms.len() > ctx.policy.resources.max_transforms_per_reference
        || ctx
            .policy
            .check_digest_algorithm(reference.digest_method)
            .is_err()
    {
        manifest_reference_invalid_result(
            reference,
            index,
            FailureReason::ReferencePolicyViolation { ref_index: index },
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
                index,
                reference_node,
                execution,
            )
            .unwrap_or_else(|error| {
                manifest_reference_invalid_result(
                    reference,
                    index,
                    manifest_reference_failure_reason(error, index),
                )
            }),
            Err(SignatureVerificationPipelineError::Policy(_)) => {
                manifest_reference_invalid_result(
                    reference,
                    index,
                    FailureReason::ReferencePolicyViolation { ref_index: index },
                )
            }
            Err(_) => manifest_reference_invalid_result(
                reference,
                index,
                FailureReason::ReferenceProcessingFailure { ref_index: index },
            ),
        }
    }
}

fn execute_manifest_reference<C: VerificationCapture>(
    operation: &mut OperationExecutionContext<
        &crate::policy::VerificationPolicy,
        &VerificationOperationBudgets,
    >,
    view: DocumentView<'_>,
    signature_node: Node<'_, '_>,
    resolver: &UriReferenceResolver<'_>,
    verification: &ManifestVerification<'_, '_, C>,
    scheduled_reference: ScheduledManifestReference,
) -> Result<(OperationNodeId, ReferenceResult), DsigError> {
    let ctx = verification.context;
    let capture = verification.capture;
    match scheduled_reference {
        ScheduledManifestReference::Invalid { node, invalid } => {
            let result = operation.run(node, || {
                Ok::<_, SignatureVerificationPipelineError>(invalid.result)
            })?;
            Ok((node, result))
        }
        ScheduledManifestReference::Parsed {
            node,
            reference: compiled,
        } => {
            let observed = operation.budgets().resource_identity_for_reference(
                &compiled.reference,
                compiled.index,
                resolver,
                view,
                resolver.node_for_node_id(compiled.reference_node_id),
            );
            let result = operation.run_with_resource(node, &observed, || {
                let reference = &compiled.reference;
                let budgets = operation.budgets();
                let execution = ReferenceExecutionContext {
                    store_pre_digest: ctx.store_pre_digest,
                    transform_options: ctx.transform_options(),
                    transform_budget: &budgets.transforms,
                    canonicalized_data_budget: &budgets.canonicalized,
                    provider: ctx.provider,
                    capture,
                };
                let mut result = evaluate_manifest_reference(
                    reference,
                    compiled.index,
                    &execution,
                    resolver,
                    signature_node,
                    ctx,
                    resolver.node_for_node_id(compiled.reference_node_id),
                );
                bind_reference_evidence(
                    &mut result,
                    reference,
                    view,
                    resolver.node_for_node_id(compiled.reference_node_id),
                    &observed,
                );
                if result.status == DsigStatus::Valid
                    && reference
                        .transforms
                        .iter()
                        .all(transform_preserves_manifest_structure)
                    && let Some(uri) = reference.uri.as_deref()
                    && let Ok(Some(target)) = resolver.node_id_for_same_document_reference(uri)
                {
                    operation.authenticate(view.node_identity_by_id(target));
                }
                Ok::<_, SignatureVerificationPipelineError>(result)
            })?;
            Ok((node, result))
        }
    }
}

fn process_authenticated_manifest_references<C: VerificationCapture>(
    operation: &mut OperationExecutionContext<
        &crate::policy::VerificationPolicy,
        &VerificationOperationBudgets,
    >,
    view: DocumentView<'_>,
    signature_node: Node<'_, '_>,
    resolver: &UriReferenceResolver<'_>,
    verification: &ManifestVerification<'_, '_, C>,
    mut remaining_reference_capacity: usize,
    // The accepted crypto node and the SignedInfo digests that authenticate
    // the first Manifest frontier.
    core_validation: &[OperationNodeId],
) -> Result<(Vec<ReferenceResult>, Vec<OperationNodeId>), SignatureVerificationPipelineError> {
    let ctx = verification.context;
    let mut processed_manifests = HashSet::new();
    let mut next_reference_index = 0usize;
    let mut frontier_index = 0usize;
    let mut completed_digests = Vec::new();
    let mut results = Vec::new();
    loop {
        operation.extend();
        let discovery = operation.add_node(
            OperationNodeKind::Manifest {
                index: frontier_index,
            },
            OperationStage::AuthenticatedDependency,
            None,
        );
        for digest in core_validation.iter().chain(&completed_digests) {
            operation
                .add_dependency(discovery, *digest)
                .map_err(map_verification_plan_error)?;
        }
        operation.compile().map_err(map_verification_plan_error)?;
        let parsed = operation.run(discovery, || {
            let mut xpath_parse = operation.budgets().xpath_parse.borrow_mut();
            let mut state = ManifestDiscoveryState {
                processed: &mut processed_manifests,
                remaining_capacity: &mut remaining_reference_capacity,
                next_reference_index: &mut next_reference_index,
                xpath_parse: &mut xpath_parse,
            };
            parse_manifest_references(
                signature_node,
                operation,
                view,
                &mut state,
                ctx.allowed_transform_uris(),
            )
        })?;
        let discovered = parsed.references.len() + parsed.invalid_results.len();
        if discovered == 0 {
            break;
        }

        let scheduled = schedule_manifest_references(operation, view, resolver, parsed, discovery)?;

        for scheduled_reference in scheduled {
            let (node, result) = execute_manifest_reference(
                operation,
                view,
                signature_node,
                resolver,
                verification,
                scheduled_reference,
            )?;
            let accepted = result.status == DsigStatus::Valid;
            operation.set_outcome(
                node,
                accepted,
                if accepted {
                    OperationDecisionReason::ReferenceDigestVerified
                } else {
                    OperationDecisionReason::ReferenceDigestRejected
                },
            );
            completed_digests.push(node);
            results.push(result);
        }
        frontier_index += 1;
    }
    results.sort_by_key(|result| result.reference_index);
    Ok((results, completed_digests))
}

fn manifest_reference_invalid_result(
    reference: &Reference,
    index: usize,
    reason: FailureReason,
) -> ReferenceResult {
    reference_failure_result(
        reference,
        ReferenceSet::Manifest,
        index,
        DsigStatus::Invalid(reason),
    )
}

fn parse_manifest_references(
    signature_node: Node<'_, '_>,
    operation: &OperationExecutionContext<
        &crate::policy::VerificationPolicy,
        &VerificationOperationBudgets,
    >,
    view: DocumentView<'_>,
    state: &mut ManifestDiscoveryState<'_>,
    allowed_transforms: Option<&HashSet<String>>,
) -> Result<ParsedManifestReferences, SignatureVerificationPipelineError> {
    let mut references = Vec::new();
    let mut invalid = Vec::new();
    // XMLDSig 1.1 §5.1 binds a Manifest through references, independently of
    // physical Signature/Object ancestry. Use only this operation's existing
    // authentication state; another Signature's successes cannot admit it.
    // https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/#sec-Manifest
    let document = signature_node.document();
    let scan = &operation.budgets().transforms;
    for manifest_node in document.descendants() {
        scan.charge_node_filter_work(1)
            .map_err(ReferenceProcessingError::Transform)?;
        if !manifest_node.has_tag_name((XMLDSIG_NS, "Manifest"))
            || state.processed.contains(&manifest_node.id())
        {
            continue;
        }
        // Leave unauthenticated Manifests unmarked so a verified outer
        // Manifest can make them eligible on the next discovery pass.
        if !manifest_is_authenticated(manifest_node, operation, view)? {
            continue;
        }
        if !state.processed.insert(manifest_node.id()) {
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
            if *state.remaining_capacity == 0 {
                return Err(SignatureVerificationPipelineError::InvalidStructure {
                    reason: "signed Manifests exceed the per-signature Reference limit",
                });
            }
            *state.remaining_capacity -= 1;
            let reference_index = *state.next_reference_index;
            *state.next_reference_index += 1;
            match parse_reference_with_xpath_budget(child, state.xpath_parse) {
                Ok(reference) => references.push(CompiledManifestReference {
                    index: reference_index,
                    reference,
                    reference_node_id: child.id(),
                }),
                Err(ParseError::Transform(super::TransformError::UnsupportedTransform(uri))) => {
                    let digest_algorithm =
                        reference_digest_method(child).map_err(map_manifest_parse_error)?;
                    let reason =
                        if allowed_transforms.is_some_and(|allowed| !allowed.contains(&uri)) {
                            FailureReason::ReferencePolicyViolation {
                                ref_index: reference_index,
                            }
                        } else {
                            FailureReason::ReferenceProcessingFailure {
                                ref_index: reference_index,
                            }
                        };
                    invalid.push(CompiledManifestInvalid {
                        result: ReferenceResult {
                            reference_identity: Some(view.node_identity(child)),
                            target_identity: None,
                            external_resource_fingerprint: None,
                            external_payload: None,
                            coverage: ReferenceCoverage::TransformedData,
                            reference_set: ReferenceSet::Manifest,
                            reference_index,
                            uri: child.attribute("URI").unwrap_or("<omitted>").to_owned(),
                            digest_algorithm,
                            status: DsigStatus::Invalid(reason),
                            pre_digest_data: None,
                        },
                    });
                }
                Err(error) => return Err(map_manifest_parse_error(error)),
            }
        }
    }
    Ok(ParsedManifestReferences {
        references,
        invalid_results: invalid,
    })
}

fn manifest_is_authenticated(
    manifest_node: Node<'_, '_>,
    operation: &OperationExecutionContext<
        &crate::policy::VerificationPolicy,
        &VerificationOperationBudgets,
    >,
    view: DocumentView<'_>,
) -> Result<bool, DsigError> {
    for ancestor in manifest_node.ancestors() {
        operation
            .budgets()
            .transforms
            .charge_node_filter_work(1)
            .map_err(ReferenceProcessingError::Transform)?;
        if operation.is_authenticated(view.node_identity(ancestor)) {
            return Ok(true);
        }
    }
    Ok(false)
}

struct ParsedManifestReferences {
    references: Vec<CompiledManifestReference>,
    invalid_results: Vec<CompiledManifestInvalid>,
}

struct ManifestDiscoveryState<'a> {
    processed: &'a mut HashSet<NodeId>,
    remaining_capacity: &'a mut usize,
    next_reference_index: &'a mut usize,
    xpath_parse: &'a mut XPathSignatureParseBudget,
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
        | Transform::Base64Decode
        | Transform::Relationship(_) => false,
        #[cfg(feature = "xslt")]
        Transform::Xslt(_) => false,
    }
}

#[expect(
    clippy::large_enum_variant,
    reason = "single bounded authorization result avoids heap allocation"
)]
enum ResolvedVerifyingKey<'a> {
    Established(super::HmacVerificationKey),
    Borrowed(&'a dyn VerifyingKey),
    Owned(super::ResolvedVerificationKey<'a>),
}

impl ResolvedVerifyingKey<'_> {
    fn evidence(
        &self,
        policy: &crate::policy::VerificationPolicy,
    ) -> Result<super::KeyTrustEvidence, DsigError> {
        match self {
            Self::Established(_) => {
                if policy.key_trust.mode != crate::policy::VerificationTrustMode::CryptographicOnly
                {
                    return Err(crate::policy::PolicyViolation::KeyTrust {
                        reason: "KEM/HMAC does not authenticate sender identity",
                    }
                    .into());
                }
                Ok(super::KeyTrustEvidence::NotEstablished)
            }
            Self::Borrowed(_)
                if policy.key_trust.mode
                    == crate::policy::VerificationTrustMode::CryptographicOnly =>
            {
                Ok(super::KeyTrustEvidence::NotEstablished)
            }
            Self::Borrowed(_) => Ok(super::KeyTrustEvidence::CallerTrusted),
            Self::Owned(key) => key.authorize(policy),
        }
    }
    fn as_ref(&self) -> &dyn VerifyingKey {
        match self {
            Self::Established(key) => key,
            Self::Borrowed(key) => *key,
            Self::Owned(key) => key.as_ref(),
        }
    }
}

fn resolve_verifying_key<'k>(
    ctx: &VerifyContext<'k>,
    key: Option<&'k dyn VerifyingKey>,
    key_info: Option<&KeyInfo>,
    algorithm: SignatureAlgorithm,
    budget: &mut super::InspectedKeyCandidateBudget,
) -> Result<Option<ResolvedVerifyingKey<'k>>, SignatureVerificationPipelineError> {
    if let Some(key) = key {
        if !ctx
            .policy
            .key_sources
            .contains(crate::policy::KeySourceKind::PresetKey)
        {
            return Err(crate::policy::PolicyViolation::KeyTrust {
                reason: "pre-resolved verification keys are disabled",
            }
            .into());
        }
        require_verifying_key_candidate_capacity(&ctx.policy)?;
        budget.charge()?;
        return Ok(Some(ResolvedVerifyingKey::Borrowed(key)));
    }
    if let Some(resolver) = ctx.key_resolver {
        require_verifying_key_candidate_capacity(&ctx.policy)?;
        let resolved = resolver.resolve_for_verification_with_budget(
            key_info,
            algorithm,
            &ctx.policy,
            ctx.provider,
            budget,
        )?;
        if let Some(key) = &resolved {
            key.authorize(&ctx.policy)?;
        }
        return Ok(resolved.map(ResolvedVerifyingKey::Owned));
    }
    Ok(None)
}

fn require_verifying_key_candidate_capacity(
    policy: &crate::policy::VerificationPolicy,
) -> Result<(), SignatureVerificationPipelineError> {
    policy
        .resources
        .validate_key_candidates(1)
        .map_err(Into::into)
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
            if transform_chain_uses_implicit_c14n(
                classify_uri(uri) == UriClass::External,
                &reference.transforms,
            ) {
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

/// Query-funded form: the attacker-sized URI is copied into `work`'s storage.
fn enforce_current_transform_allowed<W: structured_asn1::memory::Work>(
    allowed_transforms: Option<&HashSet<String>>,
    algorithm: &str,
    work: &W,
) -> Result<(), SignatureVerificationPipelineError> {
    use crate::xml::dom::storage::Storage as _;
    if allowed_transforms.is_some_and(|allowed| !allowed.contains(algorithm)) {
        return Err(
            match crate::xml::dom::storage::Accounted(work).formatted(format_args!("{algorithm}")) {
                Ok(algorithm) => DsigError::AccountedPolicyAlgorithm {
                    operation: "verification transform",
                    algorithm: algorithm.into_owned(),
                },
                Err(crate::xml::dom::ParseError::SharedExecution(cause)) => cause.into(),
                Err(cause) => cause.into(),
            },
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub(super) struct SignatureChildNodes<'a, 'input> {
    signed_info: Node<'a, 'input>,
    signature_value: Node<'a, 'input>,
    pub(super) key_info: Option<Node<'a, 'input>>,
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
    validate_signature_child_order(
        signed_info_index,
        signature_value_index,
        key_info_index,
        first_unexpected_dsig_index,
    )?;

    Ok(SignatureChildNodes {
        signed_info: signed_info_node,
        signature_value: signature_value_node,
        key_info: key_info_node,
    })
}

fn validate_signature_child_order(
    signed_info_index: Option<usize>,
    signature_value_index: Option<usize>,
    key_info_index: Option<usize>,
    first_unexpected_dsig_index: Option<usize>,
) -> Result<(), DsigError> {
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

    Ok(())
}

fn decode_signature_value(
    signature_value_node: Node<'_, '_>,
    algorithm: SignatureAlgorithm,
    resources: &crate::policy::ResourcePolicy,
) -> Result<Vec<u8>, SignatureVerificationPipelineError> {
    if matches!(algorithm, SignatureAlgorithm::PostQuantum(_)) {
        let (maximum, raw_maximum) = signature_value_limits(algorithm, resources);
        // PQ signatures can be tens of kilobytes: borrow their XML text and
        // stream directly into the decoded allocation, without a second
        // full-size normalized Base64 buffer.
        let payload = super::whitespace::XmlBase64Payload::bounded(
            signature_value_node,
            raw_maximum,
            maximum,
        )
        .map_err(
            |reason| SignatureVerificationPipelineError::InvalidStructure {
                reason: match reason {
                    "unexpected nested element" => {
                        "SignatureValue must not contain element children"
                    }
                    "maximum allowed text length" => {
                        "SignatureValue exceeds maximum allowed text length"
                    }
                    "maximum allowed base64 length" => {
                        "SignatureValue exceeds maximum allowed length"
                    }
                    _ => "SignatureValue contains malformed Base64",
                },
            },
        )?;
        return payload.decode().map_err(|_| {
            SignatureVerificationPipelineError::InvalidStructure {
                reason: "SignatureValue contains malformed Base64",
            }
        });
    }
    for child in signature_value_node.children() {
        if child.is_element() {
            return Err(SignatureVerificationPipelineError::InvalidStructure {
                reason: "SignatureValue must not contain element children",
            });
        }
    }

    // Count bounded borrowed text first: comments may split a
    // signature into many tiny text nodes. Reserving per node would repeatedly
    // copy the accumulated payload; one exact reservation keeps this linear.
    let (maximum, raw_maximum) = signature_value_limits(algorithm, resources);
    let mut text_len = 0usize;
    let mut normalized_len = 0usize;
    for child in signature_value_node.children().filter(Node::is_text) {
        if let Some(text) = child.text() {
            if text.len() > raw_maximum - text_len {
                return Err(SignatureVerificationPipelineError::InvalidStructure {
                    reason: "SignatureValue exceeds maximum allowed text length",
                });
            }
            text_len += text.len();
            for byte in text.bytes() {
                if matches!(byte, b' ' | b'\t' | b'\r' | b'\n') {
                    continue;
                }
                if normalized_len == maximum {
                    return Err(SignatureVerificationPipelineError::InvalidStructure {
                        reason: "SignatureValue exceeds maximum allowed length",
                    });
                }
                normalized_len += 1;
            }
        }
    }
    let mut normalized = Vec::with_capacity(normalized_len);
    let mut raw_text_len = 0usize;
    for child in signature_value_node.children().filter(Node::is_text) {
        if let Some(text) = child.text() {
            push_normalized_signature_text(
                text,
                &mut raw_text_len,
                &mut normalized,
                algorithm,
                resources,
            )?;
        }
    }

    Ok(base64::engine::general_purpose::STANDARD.decode(normalized)?)
}

fn push_normalized_signature_text(
    text: &str,
    raw_text_len: &mut usize,
    normalized: &mut Vec<u8>,
    algorithm: SignatureAlgorithm,
    resources: &crate::policy::ResourcePolicy,
) -> Result<(), SignatureVerificationPipelineError> {
    let (maximum, raw_maximum) = signature_value_limits(algorithm, resources);
    if text.len() > raw_maximum - *raw_text_len {
        return Err(SignatureVerificationPipelineError::InvalidStructure {
            reason: "SignatureValue exceeds maximum allowed text length",
        });
    }
    *raw_text_len += text.len();
    let additional = text
        .bytes()
        .filter(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        .count();
    if additional > maximum - normalized.len() {
        return Err(SignatureVerificationPipelineError::InvalidStructure {
            reason: "SignatureValue exceeds maximum allowed length",
        });
    }

    normalize_xml_base64_bytes(text.as_bytes(), normalized, |_| true).map_err(|err| {
        SignatureVerificationPipelineError::SignatureValueBase64(base64::DecodeError::InvalidByte(
            err.normalized_offset,
            err.invalid_byte,
        ))
    })?;

    Ok(())
}

fn signature_value_limits(
    algorithm: SignatureAlgorithm,
    resources: &crate::policy::ResourcePolicy,
) -> (usize, usize) {
    // FIPS 205 table 2 includes signatures up to 49,856 octets. The old
    // RSA-oriented encoded-text ceiling is not their wire contract.
    // https://doi.org/10.6028/NIST.FIPS.205
    // XSD 1.0 section 3.2.16 fixes base64Binary whitespace to collapse:
    // https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#base64Binary
    // Raw text is bounded by the operation's XML budget, not the wire width.
    let encoded = match algorithm {
        SignatureAlgorithm::PostQuantum(parameter) => parameter.signature_len().div_ceil(3) * 4,
        _ => MAX_SIGNATURE_VALUE_LEN,
    };
    (encoded, resources.max_xml_document_bytes)
}

fn verify_with_algorithm(
    algorithm: SignatureAlgorithm,
    public_key_pem: &str,
    signed_data: &[u8],
    signature_value: &[u8],
) -> Result<bool, SignatureVerificationPipelineError> {
    match algorithm {
        #[cfg(feature = "legacy-algorithms")]
        SignatureAlgorithm::RsaMd5 | SignatureAlgorithm::RsaRipemd160 => Ok(
            verify_rsa_signature_pem(algorithm, public_key_pem, signed_data, signature_value)?,
        ),
        #[cfg(feature = "legacy-algorithms")]
        SignatureAlgorithm::EcdsaRipemd160 => Ok(verify_ecdsa_signature_pem(
            algorithm,
            public_key_pem,
            signed_data,
            signature_value,
        )?),
        #[cfg(feature = "legacy-algorithms")]
        SignatureAlgorithm::HmacMd5 | SignatureAlgorithm::HmacRipemd160 => {
            Err(SignatureVerificationError::UnsupportedAlgorithm {
                uri: algorithm.uri().to_owned(),
            }
            .into())
        }
        SignatureAlgorithm::Ed25519
        | SignatureAlgorithm::Ed25519Ctx
        | SignatureAlgorithm::Ed25519Ph
        | SignatureAlgorithm::Ed448
        | SignatureAlgorithm::Ed448Ph
        | SignatureAlgorithm::PostQuantum(_) => {
            let pem = super::signature::PemBlock::decode(public_key_pem)
                .filter(|pem| pem.label == "PUBLIC KEY")
                .ok_or(SignatureVerificationError::InvalidKeyPem)?;
            Ok(super::modern::verify(
                algorithm,
                &pem.contents,
                signed_data,
                signature_value,
                &super::pkix::CertificateSession::standalone(),
            )?)
        }
        SignatureAlgorithm::DsaSha1 | SignatureAlgorithm::DsaSha256 => {
            let pem = super::signature::PemBlock::decode(public_key_pem)
                .filter(|pem| pem.label == "PUBLIC KEY")
                .ok_or(SignatureVerificationError::InvalidKeyPem)?;
            Ok(verify_dsa_signature_spki(
                algorithm,
                &pem.contents,
                signed_data,
                signature_value,
            )?)
        }
        SignatureAlgorithm::HmacSha1
        | SignatureAlgorithm::HmacSha224
        | SignatureAlgorithm::HmacSha256
        | SignatureAlgorithm::HmacSha384
        | SignatureAlgorithm::HmacSha512 => Err(SignatureVerificationError::UnsupportedAlgorithm {
            uri: algorithm.uri().to_string(),
        }
        .into()),
        SignatureAlgorithm::RsaSha1
        | SignatureAlgorithm::RsaSha224
        | SignatureAlgorithm::RsaSha256
        | SignatureAlgorithm::RsaSha384
        | SignatureAlgorithm::RsaSha512
        | SignatureAlgorithm::RsaPssSha1
        | SignatureAlgorithm::RsaPssSha224
        | SignatureAlgorithm::RsaPssSha256
        | SignatureAlgorithm::RsaPssSha384
        | SignatureAlgorithm::RsaPssSha512
        | SignatureAlgorithm::RsaPssSha3_224
        | SignatureAlgorithm::RsaPssSha3_256
        | SignatureAlgorithm::RsaPssSha3_384
        | SignatureAlgorithm::RsaPssSha3_512
        | SignatureAlgorithm::RsaPss(_) => Ok(verify_rsa_signature_pem(
            algorithm,
            public_key_pem,
            signed_data,
            signature_value,
        )?),
        SignatureAlgorithm::EcdsaSha1
        | SignatureAlgorithm::EcdsaSha224
        | SignatureAlgorithm::EcdsaSha256
        | SignatureAlgorithm::EcdsaSha384
        | SignatureAlgorithm::EcdsaSha512
        | SignatureAlgorithm::EcdsaSha3_224
        | SignatureAlgorithm::EcdsaSha3_256
        | SignatureAlgorithm::EcdsaSha3_384
        | SignatureAlgorithm::EcdsaSha3_512 => {
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
mod tests;
