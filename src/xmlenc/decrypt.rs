//! XMLEnc decryption entry point and key resolvers.

use std::{borrow::Cow, fmt, sync::Arc};

#[cfg(test)]
use crate::xml::dom::Document;
#[cfg(test)]
use base64::Engine as _;

use crate::document::{DocumentParseSettings, XmlDocument, XmlParseWorkBudget};
use crate::operation::{
    OperationExecutionContext, OperationNodeId, OperationNodeKind, OperationPlanError,
    OperationStage,
};
use rsa::RsaPrivateKey;

use super::parse::validate_encrypted_data_metadata;
use super::types::{MAX_CIPHER_VALUE_BASE64_LEN, XMLENC_NS, validate_ciphertext_framing};
use super::{
    DataEncryptionAlgorithm, DecryptedContent, EncryptedData, EncryptedDataType, EncryptedKey,
    KeyTransportAlgorithm, KeyWrapAlgorithm, OaepDigestAlgorithm, RsaOaepParameters, XmlEncError,
    map_document_error,
};

#[cfg(test)]
use super::parse_encrypted_data;

/// Aggregate key-candidate work allowance for one cryptographic operation.
///
/// Resolver implementations must consume one unit before each key lookup or
/// unwrap attempt. A single budget is shared across direct and recipient keys.
#[derive(Debug)]
pub struct KeyCandidateBudget {
    maximum: usize,
    remaining: usize,
    key_establishment: super::key_establishment_budget::KeyEstablishmentUsage,
}

impl KeyCandidateBudget {
    /// Create the fixed implementation-wide budget for one operation.
    pub fn for_operation() -> Self {
        Self::with_limit(crate::hard_limits::KEY_CANDIDATE_CEILING)
    }

    /// Create a budget from a validated operation policy ceiling.
    pub fn with_limit(maximum: usize) -> Self {
        Self {
            maximum,
            remaining: maximum,
            key_establishment: Default::default(),
        }
    }

    /// Number of candidate attempts still available to this operation.
    pub const fn remaining(&self) -> usize {
        self.remaining
    }

    /// Derive a key against the caller's operation snapshot, retaining all KDF
    /// reservations in this same budget across nested sources and retries.
    /// Resolvers must forward the snapshot received by their policy-aware entry
    /// point; they must never choose a profile from document content.
    pub fn derive_key(
        &mut self,
        provider: &dyn crate::provider::CryptoProvider,
        policy: &crate::policy::DecryptionPolicy,
        parameters: &crate::provider::KdfParameters<'_>,
        secret: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, XmlEncError> {
        self.key_establishment
            .derive_key(&policy.key_establishment, provider, parameters, secret)
    }

    /// Establish a shared secret and derive its consuming key after reserving
    /// both outputs and checking both permissions before either provider call.
    /// Candidate allowance includes scalar multiplication and derivation.
    pub fn agree_and_derive(
        &mut self,
        provider: &dyn crate::provider::CryptoProvider,
        policy: &crate::policy::DecryptionPolicy,
        key: &dyn crate::provider::KeyAgreementKey,
        agreement: &crate::provider::KeyAgreementParameters<'_>,
        parameters: &crate::provider::KdfParameters<'_>,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, XmlEncError> {
        self.consume(2)?;
        self.key_establishment.agree_and_derive(
            &policy.key_establishment,
            provider,
            key,
            agreement,
            parameters,
        )
    }

    /// Charge attempted candidate work before performing it.
    pub fn consume(&mut self, count: usize) -> Result<(), XmlEncError> {
        self.require_available(count)?;
        self.remaining -= count;
        Ok(())
    }

    pub(super) fn require_available(&self, count: usize) -> Result<(), XmlEncError> {
        if count > self.remaining {
            return Err(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::KEY_CANDIDATES,
                maximum: self.maximum,
                actual: self
                    .maximum
                    .saturating_sub(self.remaining)
                    .saturating_add(count),
            }
            .into());
        }
        Ok(())
    }

    fn account_returned_candidates(
        &mut self,
        remaining_before: usize,
        returned: usize,
    ) -> Result<(), XmlEncError> {
        let resolver_charged = remaining_before.saturating_sub(self.remaining);
        self.consume(returned.saturating_sub(resolver_charged))
    }
}

/// Supplies a content-encryption key for parsed XMLEnc data.
/// A source resolved for a wrapping algorithm. Its output is never implicitly
/// treated as a CEK or exported from a non-exportable provider handle.
pub enum KeyEncryptionKeySource<'a> {
    /// Application-owned key material without transported establishment hints.
    Direct,
    /// A key transporting this operation's wrapping key.
    Encrypted(&'a EncryptedKey),
    /// Agreement producing this operation's wrapping key.
    Agreement(&'a super::AgreementMethod),
    /// Derivation producing this operation's wrapping key.
    Derived(&'a super::DerivedKey),
}

/// Supplies keys for an XMLEnc operation under its immutable policy snapshot.
pub trait DecryptionKeyResolver {
    /// Resolve an actual KEK purpose; default refusal prevents incorrectly
    /// adapting a content algorithm merely because its key width happens to fit.
    fn resolve_key_encryption_keys_with_policy(
        &self,
        _provider: &dyn crate::provider::CryptoProvider,
        _algorithm: KeyWrapAlgorithm,
        _source: KeyEncryptionKeySource<'_>,
        _policy: &crate::policy::DecryptionPolicy,
        _budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<crate::provider::RecoveredContentKey>, XmlEncError> {
        Err(XmlEncError::KeyNotFound)
    }
    /// Resolve an agreement under the operation snapshot and shared allowance.
    /// Default refusal prevents a raw content key from bypassing AgreementMethod.
    fn resolve_agreement_content_keys_with_policy(
        &self,
        _provider: &dyn crate::provider::CryptoProvider,
        _algorithm: DataEncryptionAlgorithm,
        _descriptor: &super::AgreementMethod,
        _policy: &crate::policy::DecryptionPolicy,
        _budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<crate::provider::RecoveredContentKey>, XmlEncError> {
        Err(XmlEncError::KeyNotFound)
    }
    /// Resolve a transported derivation descriptor using the same immutable
    /// operation policy and cumulative candidate/KDF allowance. The default
    /// refuses it; a raw content-key resolver must not bypass derivation.
    fn resolve_derived_content_keys_with_policy(
        &self,
        _provider: &dyn crate::provider::CryptoProvider,
        _algorithm: DataEncryptionAlgorithm,
        _descriptor: &super::DerivedKey,
        _policy: &crate::policy::DecryptionPolicy,
        _budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<crate::provider::RecoveredContentKey>, XmlEncError> {
        Err(XmlEncError::KeyNotFound)
    }
    /// Resolve operation candidates without dropping implicit-rejection state.
    /// Wrappers around recipient resolvers must forward this method; converting
    /// recovered candidates to raw bytes loses the final content acceptance gate.
    fn resolve_content_keys_with_policy(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
        policy: &crate::policy::DecryptionPolicy,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<crate::provider::RecoveredContentKey>, XmlEncError> {
        self.resolve_key_candidates_with_policy(provider, algorithm, encrypted_key, policy, budget)
            .map(|keys| {
                keys.into_iter()
                    .map(crate::provider::RecoveredContentKey::confirmed)
                    .collect()
            })
    }
    /// Resolve under the operation's immutable snapshot. RSA resolvers enforce
    /// `rsa_keys` before provider recovery; wrappers must forward this snapshot.
    ///
    /// The default supports direct content keys only and returns
    /// [`XmlEncError::KeyNotFound`] for recipients without invoking legacy
    /// resolution. Recipient resolvers must override this method: recovered
    /// symmetric bytes cannot prove the original key met the operation policy.
    fn resolve_key_candidates_with_policy(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
        policy: &crate::policy::DecryptionPolicy,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<Vec<u8>>, XmlEncError> {
        policy.validate()?;
        if encrypted_key.is_some() {
            return Err(XmlEncError::KeyNotFound);
        }
        self.resolve_key_candidates(provider, algorithm, None, budget)
    }

    /// Resolve the symmetric key for `algorithm`, optionally unwrapping `encrypted_key`.
    fn resolve_key(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
    ) -> Result<Vec<u8>, XmlEncError>;

    /// Resolve ordered candidate keys for one prepared decryption operation.
    ///
    /// The default preserves single-key resolver behavior. Key rings override
    /// this method so parsing, policy validation, and ciphertext decoding occur
    /// once while only authenticated primitive decryption is retried. Overrides
    /// must consume the shared budget before every lookup or unwrap attempt.
    /// The context also accounts for any returned candidates an implementation
    /// did not explicitly charge. Returning [`XmlEncError::Policy`] rejects the
    /// complete operation and never advances to another key source; use a
    /// candidate-local error such as [`XmlEncError::KeyNotFound`] when later
    /// ordered sources are still eligible.
    fn resolve_key_candidates(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<Vec<u8>>, XmlEncError> {
        budget.consume(1)?;
        self.resolve_key(provider, algorithm, encrypted_key)
            .map(|key| vec![key])
    }
}

/// Derive a direct content key or wrapping key from caller-owned secret
/// material and parsed KDF parameters. The operation, not this request object,
/// supplies permission and cumulative allowance. Secret material is borrowed.
pub struct DerivedKeyDecryptor<'a> {
    method: &'a super::KeyDerivationMethod,
    input: DerivedKeyInput<'a>,
    purpose: DerivedKeyPurpose,
    master_key_name: Option<&'a str>,
}

/// Application-owned key-establishment input; private handles and secret bytes
/// are borrowed, and document data cannot replace their provenance.
pub enum DerivedKeyInput<'a> {
    /// Caller-selected secret or password octets.
    Secret(&'a [u8]),
    /// Caller-selected private handle and peer parameters for agreement.
    Agreement {
        /// Opaque private key belonging to the selected provider.
        key: &'a dyn crate::provider::KeyAgreementKey,
        /// Encoded public peer and the requested agreement algorithm.
        parameters: crate::provider::KeyAgreementParameters<'a>,
    },
}

enum DerivedKeyPurpose {
    Content(DataEncryptionAlgorithm),
    Wrapping(KeyWrapAlgorithm),
}

impl<'a> DerivedKeyDecryptor<'a> {
    /// Bind explicitly selected KDF parameters to an application-owned secret.
    /// This does not discover keys or permit algorithms on the caller's behalf.
    pub fn content(
        method: &'a super::KeyDerivationMethod,
        input: DerivedKeyInput<'a>,
        algorithm: DataEncryptionAlgorithm,
    ) -> Self {
        Self {
            method,
            input,
            purpose: DerivedKeyPurpose::Content(algorithm),
            master_key_name: None,
        }
    }

    /// Bind a wrapping-key derivation rather than a content-key derivation.
    /// Purpose is application context, never inferred from untrusted XML widths.
    pub fn wrapping(
        method: &'a super::KeyDerivationMethod,
        input: DerivedKeyInput<'a>,
        algorithm: KeyWrapAlgorithm,
    ) -> Self {
        Self {
            method,
            input,
            purpose: DerivedKeyPurpose::Wrapping(algorithm),
            master_key_name: None,
        }
    }

    /// Bind XML MasterKeyName to the caller-selected material. A transported
    /// name never selects or substitutes private material by itself.
    pub fn master_key_name(mut self, name: &'a str) -> Self {
        self.master_key_name = Some(name);
        self
    }

    fn derive(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        width: usize,
        policy: &crate::policy::DecryptionPolicy,
        budget: &mut KeyCandidateBudget,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, XmlEncError> {
        let parameters = self.method.parameters(width)?;
        match &self.input {
            DerivedKeyInput::Secret(secret) => {
                budget.consume(1)?;
                budget.derive_key(provider, policy, &parameters, secret)
            }
            DerivedKeyInput::Agreement {
                key,
                parameters: agreement,
            } => budget.agree_and_derive(provider, policy, *key, agreement, &parameters),
        }
    }
}

impl fmt::Debug for DerivedKeyDecryptor<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DerivedKeyDecryptor")
            .finish_non_exhaustive()
    }
}

impl DecryptionKeyResolver for DerivedKeyDecryptor<'_> {
    fn resolve_key_encryption_keys_with_policy(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: KeyWrapAlgorithm,
        source: KeyEncryptionKeySource<'_>,
        policy: &crate::policy::DecryptionPolicy,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<crate::provider::RecoveredContentKey>, XmlEncError> {
        if !matches!(self.purpose, DerivedKeyPurpose::Wrapping(expected) if expected == algorithm) {
            return Err(XmlEncError::KeyNotFound);
        }
        match source {
            KeyEncryptionKeySource::Derived(descriptor)
                if descriptor
                    .method
                    .as_ref()
                    .is_none_or(|method| method == self.method)
                    && descriptor
                        .master_key_name
                        .as_deref()
                        .is_none_or(|name| Some(name) == self.master_key_name) => {}
            KeyEncryptionKeySource::Agreement(descriptor) => {
                let DerivedKeyInput::Agreement { parameters, .. } = &self.input else {
                    return Err(XmlEncError::KeyNotFound);
                };
                if descriptor.algorithm.uri() != parameters.algorithm
                    || descriptor
                        .method
                        .as_ref()
                        .is_some_and(|method| method != self.method)
                    || descriptor.originator.is_some()
                    || descriptor.recipient.is_some()
                    || !descriptor.nonce.is_empty()
                    || descriptor.legacy_digest.is_some()
                {
                    return Err(XmlEncError::KeyNotFound);
                }
            }
            _ => return Err(XmlEncError::KeyNotFound),
        }
        budget.require_available(match self.input {
            DerivedKeyInput::Secret(_) => 2,
            DerivedKeyInput::Agreement { .. } => 3,
        })?;
        let mut key = self.derive(provider, algorithm.key_len(), policy, budget)?;
        Ok(vec![crate::provider::RecoveredContentKey::confirmed(
            core::mem::take(&mut *key),
        )])
    }
    fn resolve_agreement_content_keys_with_policy(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        descriptor: &super::AgreementMethod,
        policy: &crate::policy::DecryptionPolicy,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<crate::provider::RecoveredContentKey>, XmlEncError> {
        let DerivedKeyInput::Agreement { parameters, .. } = &self.input else {
            return Err(XmlEncError::KeyNotFound);
        };
        // This request binds both parties out of band. A transported selector
        // requires the full expected-descriptor resolver, not silent ignoring.
        if descriptor.algorithm.uri() != parameters.algorithm
            || descriptor
                .method
                .as_ref()
                .is_some_and(|method| method != self.method)
            || descriptor.originator.is_some()
            || descriptor.recipient.is_some()
            || !descriptor.nonce.is_empty()
            || descriptor.legacy_digest.is_some()
        {
            return Err(XmlEncError::KeyNotFound);
        }
        self.resolve_content_keys_with_policy(provider, algorithm, None, policy, budget)
    }
    fn resolve_derived_content_keys_with_policy(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        descriptor: &super::DerivedKey,
        policy: &crate::policy::DecryptionPolicy,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<crate::provider::RecoveredContentKey>, XmlEncError> {
        // XMLEnc 1.1 §5.4.1 leaves AlgorithmID/party validation to the
        // application. Match its entire expected descriptor BEFORE dispatch,
        // retaining bit boundaries and preventing document-selected context.
        // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-ConcatKDF
        if descriptor
            .method
            .as_ref()
            .is_some_and(|method| method != self.method)
            || descriptor
                .master_key_name
                .as_deref()
                .is_some_and(|name| Some(name) != self.master_key_name)
        {
            return Err(XmlEncError::KeyNotFound);
        }
        self.resolve_content_keys_with_policy(provider, algorithm, None, policy, budget)
    }
    fn resolve_key(
        &self,
        _provider: &dyn crate::provider::CryptoProvider,
        _algorithm: DataEncryptionAlgorithm,
        _encrypted_key: Option<&EncryptedKey>,
    ) -> Result<Vec<u8>, XmlEncError> {
        // A policy-free legacy callback must not create a fresh KDF allowance.
        Err(XmlEncError::KeyNotFound)
    }

    fn resolve_content_keys_with_policy(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
        policy: &crate::policy::DecryptionPolicy,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<crate::provider::RecoveredContentKey>, XmlEncError> {
        policy.validate()?;
        match (&self.purpose, encrypted_key) {
            (DerivedKeyPurpose::Content(_), Some(_)) | (DerivedKeyPurpose::Wrapping(_), None) => {
                return Err(XmlEncError::KeyNotFound);
            }
            (DerivedKeyPurpose::Content(expected), None) if *expected != algorithm => {
                return Err(XmlEncError::KeyNotFound);
            }
            _ => {}
        }
        let wrap = match encrypted_key {
            None => None,
            Some(encrypted_key) => {
                validate_encrypted_key_policy(encrypted_key, policy)?;
                encrypted_key.encryption_method.validate_structure()?;
                Some(KeyWrapAlgorithm::from_uri(
                    &encrypted_key.encryption_method.algorithm,
                )?)
            }
        };
        if let (DerivedKeyPurpose::Wrapping(expected), Some(actual)) = (&self.purpose, wrap)
            && *expected != actual
        {
            return Err(XmlEncError::KeyNotFound);
        }
        let width = match wrap {
            Some(wrap) => wrap.key_len(),
            None => algorithm.key_len(),
        };
        // Check the complete attempt before expensive password or scalar work.
        // Individual stages still charge themselves, retaining failed work and
        // forwarding this same budget into the existing unwrap implementation.
        let derivation_attempts = match self.input {
            DerivedKeyInput::Secret(_) => 1,
            DerivedKeyInput::Agreement { .. } => 2,
        };
        let required = if wrap.is_some() {
            derivation_attempts + 1
        } else {
            derivation_attempts
        };
        budget.require_available(required)?;
        let mut key = self.derive(provider, width, policy, budget)?;
        if let Some(wrap) = wrap {
            // Reuse the existing policy-aware recipient path rather than keeping
            // a second implementation of wrap-family, framing and key checks.
            return KekDecryptor::borrowed_with_kind(&key, wrap.key_kind())
                .resolve_content_keys_with_policy(
                    provider,
                    algorithm,
                    encrypted_key,
                    policy,
                    budget,
                );
        }
        Ok(vec![crate::provider::RecoveredContentKey::confirmed(
            core::mem::take(&mut *key),
        )])
    }
}

/// Direct non-exportable content key, with no private-key or symmetric-byte export.
pub struct OpaqueContentKeyResolver {
    key: std::sync::Arc<dyn crate::provider::ContentDecryptionKey>,
}

impl OpaqueContentKeyResolver {
    /// Retain a caller-selected handle; policy remains in the operation context.
    pub fn new(key: std::sync::Arc<dyn crate::provider::ContentDecryptionKey>) -> Self {
        Self { key }
    }
}

impl DecryptionKeyResolver for OpaqueContentKeyResolver {
    fn resolve_key(
        &self,
        _provider: &dyn crate::provider::CryptoProvider,
        _algorithm: DataEncryptionAlgorithm,
        _encrypted_key: Option<&EncryptedKey>,
    ) -> Result<Vec<u8>, XmlEncError> {
        Err(crate::provider::ProviderError::KeyNotExportable.into())
    }
    fn resolve_content_keys_with_policy(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
        policy: &crate::policy::DecryptionPolicy,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<crate::provider::RecoveredContentKey>, XmlEncError> {
        policy.validate()?;
        if encrypted_key.is_some() {
            return Err(XmlEncError::KeyNotFound);
        }
        budget.consume(1)?;
        provider.require_capability(crate::provider::ProviderCapability::Decrypt(algorithm))?;
        validate_content_key_len(algorithm, self.key.key_len())?;
        Ok(vec![crate::provider::RecoveredContentKey::opaque(
            self.key.clone(),
        )])
    }
}

/// Opaque KEK recipient resolver that retains the unwrapped CEK in its provider.
pub struct OpaqueKekDecryptor {
    key: std::sync::Arc<dyn crate::provider::KeyUnwrappingKey>,
}

impl OpaqueKekDecryptor {
    /// Select a caller-owned KEK without adding a second policy surface.
    pub fn new(key: std::sync::Arc<dyn crate::provider::KeyUnwrappingKey>) -> Self {
        Self { key }
    }
}

impl DecryptionKeyResolver for OpaqueKekDecryptor {
    fn resolve_key(
        &self,
        _provider: &dyn crate::provider::CryptoProvider,
        _algorithm: DataEncryptionAlgorithm,
        _encrypted_key: Option<&EncryptedKey>,
    ) -> Result<Vec<u8>, XmlEncError> {
        Err(crate::provider::ProviderError::KeyNotExportable.into())
    }
    fn resolve_content_keys_with_policy(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
        policy: &crate::policy::DecryptionPolicy,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<crate::provider::RecoveredContentKey>, XmlEncError> {
        policy.validate()?;
        let encrypted_key = encrypted_key.ok_or(XmlEncError::KeyNotFound)?;
        validate_encrypted_key_policy(encrypted_key, policy)?;
        encrypted_key.encryption_method.validate_structure()?;
        let wrap = KeyWrapAlgorithm::from_uri(&encrypted_key.encryption_method.algorithm)?;
        provider.require_capability(crate::provider::ProviderCapability::KeyUnwrap(wrap))?;
        budget.consume(1)?;
        let wrapped = encrypted_key.cipher_data.octets()?;
        if wrapped.len() != algorithm.key_len() + wrap.overhead() {
            return Err(XmlEncError::InvalidWrappedKeyLength {
                expected: algorithm.key_len() + wrap.overhead(),
                actual: wrapped.len(),
            });
        }
        let key = provider.unwrap_content_key(self.key.as_ref(), wrap, algorithm, &wrapped)?;
        validate_content_key_len(algorithm, key.key_len())?;
        Ok(vec![key])
    }
}

/// Caller-owned target selection for document decryption.
#[derive(Debug, Clone, Copy, Default)]
pub struct DocumentDecryptionOptions<'a> {
    /// Select a specific `EncryptedData` by its `Id` attribute.
    pub encrypted_data_id: Option<&'a str>,
}

/// Immutable XMLEnc decryption operation context.
pub struct DecryptContext<'a> {
    resolver: &'a dyn DecryptionKeyResolver,
    policy: crate::policy::DecryptionPolicy,
    provider: &'a dyn crate::provider::CryptoProvider,
    xml_backend: crate::XmlBackend,
    id_attributes: &'a [crate::IdAttributeRegistration],
    external_resources: Option<&'a std::collections::HashMap<String, Vec<u8>>>,
}

struct DecryptionPlanNodes {
    document: OperationNodeId,
    ciphertext: OperationNodeId,
    key: OperationNodeId,
    crypto: OperationNodeId,
    evidence: OperationNodeId,
    mutation: Option<OperationNodeId>,
}

struct DecryptionOperationBudgets {
    key_candidates: std::cell::RefCell<KeyCandidateBudget>,
    xml_parse: XmlParseWorkBudget,
}

struct DecryptionReferenceGate<'a> {
    operation:
        &'a OperationExecutionContext<crate::policy::DecryptionPolicy, DecryptionOperationBudgets>,
    document: OperationNodeId,
    ciphertext: OperationNodeId,
}

impl super::cipher_reference::ReferenceOperationGate for DecryptionReferenceGate<'_> {
    fn run_resource(
        &self,
        identity: &crate::operation::OperationResourceIdentity,
        action: &mut dyn FnMut() -> Result<Vec<u8>, XmlEncError>,
    ) -> Result<Vec<u8>, XmlEncError> {
        self.operation
            .run_discovered_resource(self.document, self.ciphertext, identity, action)
    }
}

impl DecryptionOperationBudgets {
    fn from_policy(policy: &crate::policy::DecryptionPolicy) -> Self {
        Self {
            key_candidates: std::cell::RefCell::new(KeyCandidateBudget::with_limit(
                policy.resources.max_key_candidates,
            )),
            xml_parse: XmlParseWorkBudget::from_resources(&policy.resources),
        }
    }
}

fn compile_decryption_plan(
    operation: &mut OperationExecutionContext<
        crate::policy::DecryptionPolicy,
        DecryptionOperationBudgets,
    >,
    mutation: bool,
) -> Result<DecryptionPlanNodes, XmlEncError> {
    let document = operation.add_node(OperationNodeKind::Document, OperationStage::Parse, None);
    let ciphertext =
        operation.add_node(OperationNodeKind::Ciphertext, OperationStage::Resolve, None);
    operation
        .add_dependency(ciphertext, document)
        .map_err(map_decryption_plan_error)?;
    let key = operation.add_node(
        OperationNodeKind::Key { index: 0 },
        OperationStage::Resolve,
        None,
    );
    operation
        .add_dependency(key, ciphertext)
        .map_err(map_decryption_plan_error)?;
    let crypto = operation.add_node(OperationNodeKind::Crypto, OperationStage::Crypto, None);
    operation
        .add_dependency(crypto, key)
        .map_err(map_decryption_plan_error)?;
    let evidence = operation.add_node(OperationNodeKind::Evidence, OperationStage::Evidence, None);
    operation
        .add_dependency(evidence, crypto)
        .map_err(map_decryption_plan_error)?;
    let mutation = mutation.then(|| {
        let node = operation.add_node(OperationNodeKind::Mutation, OperationStage::Mutation, None);
        operation
            .add_dependency(node, evidence)
            .expect("evidence-to-mutation stage order is fixed");
        node
    });
    operation.compile().map_err(map_decryption_plan_error)?;
    Ok(DecryptionPlanNodes {
        document,
        ciphertext,
        key,
        crypto,
        evidence,
        mutation,
    })
}

struct ProcessedDecryption<T> {
    output: T,
    operation:
        OperationExecutionContext<crate::policy::DecryptionPolicy, DecryptionOperationBudgets>,
    mutation: Option<OperationNodeId>,
}

#[derive(Clone, Copy)]
enum DecryptionInput<'a> {
    Xml {
        source: &'a str,
        node_start: Option<usize>,
    },
    Parsed(&'a EncryptedData),
}

fn cipher_reference_node<'doc, 'input>(
    node: crate::xml::dom::Node<'doc, 'input>,
) -> Result<crate::xml::dom::Node<'doc, 'input>, XmlEncError> {
    node.children()
        .find(|child| child.has_tag_name((XMLENC_NS, "CipherData")))
        .and_then(|child| {
            child
                .children()
                .find(|node| node.has_tag_name((XMLENC_NS, "CipherReference")))
        })
        .ok_or(XmlEncError::MissingRequired("CipherReference"))
}

fn selected_encrypted_node<'doc, 'input>(
    document: &'doc crate::xml::dom::Document<'input>,
    start: Option<usize>,
) -> Result<crate::xml::dom::Node<'doc, 'input>, XmlEncError> {
    match start {
        Some(start) => document
            .descendants()
            .find(|node| node.is_element() && node.range().start == start)
            .ok_or_else(|| XmlEncError::OperationPlan("selected encrypted node is absent".into())),
        None => Ok(document.root_element()),
    }
}

fn map_decryption_plan_error(error: OperationPlanError) -> XmlEncError {
    XmlEncError::from(error)
}

impl<'a> DecryptContext<'a> {
    /// Create a context with the default decryption policy and RustCrypto provider.
    pub fn new(resolver: &'a dyn DecryptionKeyResolver) -> Self {
        Self {
            resolver,
            policy: crate::policy::DecryptionPolicy::default(),
            provider: crate::provider::default_provider(),
            xml_backend: crate::XmlBackend::default(),
            id_attributes: &[],
            external_resources: None,
        }
    }

    /// Replace the complete immutable decryption policy snapshot.
    pub fn policy(mut self, policy: crate::policy::DecryptionPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Select the cryptographic provider for this decryption operation.
    pub fn provider(mut self, provider: &'a dyn crate::provider::CryptoProvider) -> Self {
        self.provider = provider;
        self
    }

    /// Select the compiled XML parser backend for this decryption operation.
    pub fn xml_backend(mut self, backend: crate::XmlBackend) -> Self {
        self.xml_backend = backend;
        self
    }

    fn document_parse_settings(&self) -> DocumentParseSettings {
        DocumentParseSettings::from_policy(&self.policy.xml, &self.policy.resources)
            .with_backend(self.xml_backend)
    }

    /// Add caller-declared ID attributes for operation start-node lookup.
    pub fn id_attributes(mut self, registrations: &'a [crate::IdAttributeRegistration]) -> Self {
        self.id_attributes = registrations;
        self
    }

    /// Supply immutable external ciphertext resources. No implicit I/O occurs.
    pub fn external_resources(
        mut self,
        resources: &'a std::collections::HashMap<String, Vec<u8>>,
    ) -> Self {
        self.external_resources = Some(resources);
        self
    }

    /// Parse and decrypt a standalone `EncryptedData` XML fragment.
    pub fn decrypt(&self, xml: &str) -> Result<DecryptedContent, XmlEncError> {
        let budgets = DecryptionOperationBudgets::from_policy(&self.policy);
        self.process_decryption_input(
            DecryptionInput::Xml {
                source: xml,
                node_start: None,
            },
            None,
            false,
            budgets,
            |content, _| Ok(content),
        )
        .map(|processed| processed.output)
    }

    /// Decrypt an already parsed `EncryptedData` value.
    pub fn decrypt_data(&self, encrypted: &EncryptedData) -> Result<DecryptedContent, XmlEncError> {
        self.process_decryption_candidates(
            encrypted,
            None,
            false,
            DecryptionOperationBudgets::from_policy(&self.policy),
            |content, _| Ok(content),
        )
        .map(|processed| processed.output)
    }

    fn process_decryption_candidates<T>(
        &self,
        encrypted: &EncryptedData,
        document_binding: Option<(crate::DocumentIdentity, u64)>,
        mutates_document: bool,
        budgets: DecryptionOperationBudgets,
        accept: impl FnMut(DecryptedContent, &XmlParseWorkBudget) -> Result<T, XmlEncError>,
    ) -> Result<ProcessedDecryption<T>, XmlEncError> {
        self.process_decryption_input(
            DecryptionInput::Parsed(encrypted),
            document_binding,
            mutates_document,
            budgets,
            accept,
        )
    }

    fn process_decryption_input<T>(
        &self,
        input: DecryptionInput<'_>,
        document_binding: Option<(crate::DocumentIdentity, u64)>,
        mutates_document: bool,
        budgets: DecryptionOperationBudgets,
        mut accept: impl FnMut(DecryptedContent, &XmlParseWorkBudget) -> Result<T, XmlEncError>,
    ) -> Result<ProcessedDecryption<T>, XmlEncError> {
        let mut operation =
            OperationExecutionContext::new(self.policy.clone(), budgets, document_binding);
        operation.policy().resources.validate()?;
        let plan_nodes = compile_decryption_plan(&mut operation, mutates_document)?;
        let source_document = operation.run(plan_nodes.document, || match input {
            DecryptionInput::Xml { source, node_start } => {
                let settings = self.document_parse_settings();
                let document = crate::document::parse_borrowed_with_settings_and_budget(
                    source,
                    settings,
                    Some(&operation.budgets().xml_parse),
                )
                .map_err(|error| map_document_error(error, settings))?;
                Ok::<_, XmlEncError>(Some((document, node_start)))
            }
            DecryptionInput::Parsed(_) => Ok(None),
        })?;
        let reference_gate = DecryptionReferenceGate {
            operation: &operation,
            document: plan_nodes.document,
            ciphertext: plan_nodes.ciphertext,
        };
        let reference_context = super::CipherReferenceContext::new(
            operation.policy(),
            self.external_resources,
            self.xml_backend,
            self.id_attributes,
        )?
        .with_operation(&reference_gate);
        let parsed = operation.run(plan_nodes.ciphertext, || {
            // The graph gates parser work as well as cryptographic callbacks.
            // Typed inputs stay borrowed; XML inputs consume the same operation
            // parse allowance used later for plaintext and controlled mutation.
            let (mut encrypted, origins) = match input {
                DecryptionInput::Xml { .. } => {
                    let (document, node_start) =
                        source_document.as_ref().expect("XML input parsed once");
                    let selected = match *node_start {
                        Some(start) => document
                            .descendants()
                            .find(|node| node.is_element() && node.range().start == start)
                            .ok_or_else(|| {
                                XmlEncError::OperationPlan(
                                    "selected encrypted node changed during policy parsing".into(),
                                )
                            })?,
                        None => document.root_element(),
                    };
                    let (encrypted, origins) =
                        super::parse::parse_encrypted_data_node_with_origins(
                            selected,
                            operation.policy().into(),
                            false,
                            self.id_attributes,
                            self.provider,
                            Some(&reference_context),
                            Some(&operation.budgets().xml_parse),
                        )?;
                    (Cow::Owned(encrypted), origins)
                }
                DecryptionInput::Parsed(encrypted) => (Cow::Borrowed(encrypted), Vec::new()),
            };
            validate_encrypted_data_metadata(&encrypted, operation.policy())?;
            encrypted.encryption_method.validate_structure()?;
            validate_recipient_count(
                encrypted.encrypted_keys.len(),
                operation.policy().resources.max_encryption_recipients,
            )?;
            let algorithm =
                DataEncryptionAlgorithm::from_uri(&encrypted.encryption_method.algorithm)?;
            crate::policy::check_content_algorithm(
                operation.policy().data_algorithms.as_ref(),
                algorithm,
                "decryption",
            )?;
            self.provider
                .require_capability(crate::provider::ProviderCapability::Decrypt(algorithm))?;
            validate_typed_cipher_values(
                &encrypted,
                algorithm,
                operation.policy().resources.max_encryption_plaintext_bytes,
                operation.policy().resources.max_xml_document_bytes,
            )?;
            let bound_references = source_document
                .as_ref()
                .map(|(document, _)| reference_context.bind_document(document));
            let ciphertext = match (&encrypted.cipher_data, source_document.as_ref()) {
                (super::CipherData::Reference { uri, transforms }, Some((document, start))) => {
                    let source = selected_encrypted_node(document, *start)?;
                    bound_references
                        .as_ref()
                        .expect("XML source has a bound reference context")
                        .resolve_parsed(
                            cipher_reference_node(source)?,
                            uri,
                            transforms,
                            &operation.budgets().xml_parse,
                        )?
                }
                _ => encrypted.cipher_data.octets()?.into_owned(),
            };
            if let Some((document, _)) = source_document.as_ref() {
                let mut origins = origins.iter();
                resolve_nested_cipher_references(
                    &mut encrypted.to_mut().encrypted_keys,
                    document,
                    &mut origins,
                    bound_references
                        .as_ref()
                        .expect("XML source has a bound reference context"),
                    &operation.budgets().xml_parse,
                )?;
                if origins.next().is_some() {
                    return Err(XmlEncError::OperationPlan(
                        "unused encrypted key origin".into(),
                    ));
                }
            }
            validate_typed_cipher_values(
                &encrypted,
                algorithm,
                operation.policy().resources.max_encryption_plaintext_bytes,
                operation.policy().resources.max_xml_document_bytes,
            )?;
            validate_content_framing_before_resolution(
                algorithm,
                ciphertext.len(),
                &encrypted.encrypted_keys,
                operation.policy(),
            )?;
            validate_possible_plaintext_len(
                algorithm,
                ciphertext.len(),
                operation.policy().resources.max_encryption_plaintext_bytes,
            )?;
            Ok::<_, XmlEncError>((encrypted, algorithm, ciphertext, origins, bound_references))
        });
        let (encrypted, algorithm, ciphertext, origins, bound_references) = parsed?;
        let keys = operation.run(plan_nodes.key, || {
            let document = match (source_document.as_ref(), bound_references.as_ref()) {
                (Some((document, start)), Some(bound)) => Some(KeySourceDocument {
                    references: bound,
                    target: selected_encrypted_node(document, *start)?.id(),
                    origins: &origins,
                }),
                _ => None,
            };
            resolve_content_key_candidates(
                self.provider,
                algorithm,
                &encrypted,
                self.resolver,
                operation.policy(),
                &mut operation.budgets().key_candidates.borrow_mut(),
                document,
            )
        })?;
        let keys = compatible_decryption_key_candidates(algorithm, keys)?;
        validate_decryption_key_candidates(algorithm, keys.len())?;
        let output = operation.run(plan_nodes.crypto, || {
            let mut last_error = None;
            for key in keys {
                let attempt = (|| {
                    validate_content_key_len(algorithm, key.key_len())?;
                    let result = key.decrypt(self.provider, algorithm, &ciphertext);
                    // XMLEnc 1.1 §6.1.2: fallback recovery must still perform
                    // content work. Never release a CBC result merely because
                    // its unauthenticated padding happened to be valid.
                    // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-bleichenbacher-attack
                    if !key.valid() {
                        if let Ok(mut plaintext) = result {
                            zeroize::Zeroize::zeroize(&mut plaintext);
                        }
                        return Err(if algorithm.cbc_block_len().is_some() {
                            XmlEncError::InvalidPadding
                        } else {
                            XmlEncError::AeadAuthenticationFailed
                        });
                    }
                    let plaintext = result.map_err(|error| {
                        map_data_decryption_error(algorithm, ciphertext.len(), error)
                    })?;
                    validate_provider_plaintext_len(algorithm, ciphertext.len(), plaintext.len())?;
                    validate_plaintext_len(
                        plaintext.len(),
                        operation.policy().resources.max_encryption_plaintext_bytes,
                    )?;
                    let content = match encrypted.encrypted_type.as_ref() {
                        Some(EncryptedDataType::Element | EncryptedDataType::Content) => {
                            DecryptedContent::Xml(String::from_utf8(plaintext)?)
                        }
                        Some(EncryptedDataType::Other(_)) | None => {
                            DecryptedContent::Bytes(plaintext)
                        }
                    };
                    accept(content, &operation.budgets().xml_parse)
                })();
                match attempt {
                    Ok(output) => return Ok(output),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or(XmlEncError::KeyNotFound))
        })?;
        let output = operation.run(plan_nodes.evidence, || Ok::<_, XmlEncError>(output))?;
        Ok(ProcessedDecryption {
            output,
            operation,
            mutation: plan_nodes.mutation,
        })
    }

    /// Decrypt and replace one selected `EncryptedData` in a caller-owned document.
    pub fn decrypt_document(
        &self,
        xml: &str,
        encrypted_data_id: Option<&str>,
    ) -> Result<String, XmlEncError> {
        decrypt_document_with_context(
            xml,
            DocumentEncryptedDataSelector::EncryptedDataId(encrypted_data_id),
            self,
        )
    }

    /// Decrypt and replace one selected `EncryptedData` in an owned document.
    pub fn decrypt_owned_document(
        &self,
        document: &mut XmlDocument,
        encrypted_data_id: Option<&str>,
    ) -> Result<(), XmlEncError> {
        let budgets = DecryptionOperationBudgets::from_policy(&self.policy);
        decrypt_owned_document_with_context(
            document,
            DocumentEncryptedDataSelector::EncryptedDataId(encrypted_data_id),
            self,
            budgets,
        )
    }

    /// Decrypt and replace the sole `EncryptedData` below an operation start
    /// node selected by ID.
    pub fn decrypt_document_from_start_node(
        &self,
        xml: &str,
        start_node_id: Option<&str>,
    ) -> Result<String, XmlEncError> {
        decrypt_document_with_context(
            xml,
            DocumentEncryptedDataSelector::UniqueBelowStartNode(start_node_id),
            self,
        )
    }

    /// Decrypt and replace the first `EncryptedData` below an operation start
    /// node selected by ID, leaving later encrypted descendants untouched.
    pub fn decrypt_first_document_from_start_node(
        &self,
        xml: &str,
        start_node_id: Option<&str>,
    ) -> Result<String, XmlEncError> {
        decrypt_document_with_context(
            xml,
            DocumentEncryptedDataSelector::FirstBelowStartNode(start_node_id),
            self,
        )
    }
}

/// Resolver for direct, pre-shared AES content keys.
#[derive(Clone)]
pub struct SymmetricKeyDecryptor {
    key: Vec<u8>,
    kind: crate::key_manager::SymmetricKeyKind,
}

impl fmt::Debug for SymmetricKeyDecryptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SymmetricKeyDecryptor")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl SymmetricKeyDecryptor {
    /// Create a direct AES-key resolver. Key length never selects another family.
    pub fn new(key: impl Into<Vec<u8>>) -> Self {
        Self::with_kind(key, crate::key_manager::SymmetricKeyKind::Aes)
    }

    /// Bind a pre-shared key to its trusted family before reading an algorithm
    /// from the document. XMLEnc 1.1 §6.1.3 recommends key separation:
    /// https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-backwards-compatibility-attacks
    pub fn with_kind(key: impl Into<Vec<u8>>, kind: crate::key_manager::SymmetricKeyKind) -> Self {
        Self {
            key: key.into(),
            kind,
        }
    }
}

impl DecryptionKeyResolver for SymmetricKeyDecryptor {
    fn resolve_content_keys_with_policy(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
        policy: &crate::policy::DecryptionPolicy,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<crate::provider::RecoveredContentKey>, XmlEncError> {
        policy.validate()?;
        if encrypted_key.is_some() {
            return Err(XmlEncError::KeyNotFound);
        }
        budget.consume(1)?;
        Ok(vec![crate::provider::RecoveredContentKey::confirmed(
            self.resolve_key(provider, algorithm, None)?,
        )])
    }

    fn resolve_key(
        &self,
        _provider: &dyn crate::provider::CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        _encrypted_key: Option<&EncryptedKey>,
    ) -> Result<Vec<u8>, XmlEncError> {
        if self.kind != algorithm.key_kind() {
            return Err(XmlEncError::KeyNotFound);
        }
        validate_key_len(algorithm, &self.key)?;
        Ok(self.key.clone())
    }
}

/// Resolver backed by an RSA private key for OAEP-wrapped session keys.
#[derive(Clone)]
pub struct PrivateKeyDecryptor {
    key: Arc<dyn crate::provider::KeyRecoveryKey>,
}

/// Resolver backed by a pre-shared, algorithm-family-bound key-encryption key.
#[derive(Clone)]
pub struct KekDecryptor<'a> {
    kek: std::borrow::Cow<'a, [u8]>,
    kind: crate::key_manager::SymmetricKeyKind,
}

impl fmt::Debug for KekDecryptor<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KekDecryptor")
            .field("kek", &"[REDACTED]")
            .field("kind", &self.kind)
            .finish()
    }
}

impl KekDecryptor<'static> {
    /// Create a resolver for RFC 3394 AES key-wrap `EncryptedKey` elements.
    pub fn new(kek: impl Into<Vec<u8>>) -> Self {
        Self::with_kind(kek, crate::key_manager::SymmetricKeyKind::Aes)
    }

    /// Bind owned key material to its trusted family, independently of input XML.
    pub fn with_kind(kek: impl Into<Vec<u8>>, kind: crate::key_manager::SymmetricKeyKind) -> Self {
        Self {
            kek: std::borrow::Cow::Owned(kek.into()),
            kind,
        }
    }
}

impl<'a> KekDecryptor<'a> {
    /// Borrow a KEK for operation-scoped recovery without copying secret material.
    pub fn borrowed(kek: &'a [u8]) -> Self {
        Self::borrowed_with_kind(kek, crate::key_manager::SymmetricKeyKind::Aes)
    }

    /// Borrow key material while retaining its caller-declared algorithm family.
    pub fn borrowed_with_kind(kek: &'a [u8], kind: crate::key_manager::SymmetricKeyKind) -> Self {
        Self {
            kek: std::borrow::Cow::Borrowed(kek),
            kind,
        }
    }
}

impl DecryptionKeyResolver for KekDecryptor<'_> {
    fn resolve_key_encryption_keys_with_policy(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: KeyWrapAlgorithm,
        source: KeyEncryptionKeySource<'_>,
        policy: &crate::policy::DecryptionPolicy,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<crate::provider::RecoveredContentKey>, XmlEncError> {
        match source {
            KeyEncryptionKeySource::Direct => {
                if self.kind != algorithm.key_kind() || self.kek.len() != algorithm.key_len() {
                    return Err(XmlEncError::KeyNotFound);
                }
                budget.consume(1)?;
                Ok(vec![crate::provider::RecoveredContentKey::confirmed(
                    self.kek.to_vec(),
                )])
            }
            KeyEncryptionKeySource::Encrypted(key) => {
                validate_encrypted_key_policy(key, policy)?;
                budget.consume(2)?;
                Ok(vec![crate::provider::RecoveredContentKey::confirmed(
                    self.unwrap(provider, algorithm.key_len(), key)?,
                )])
            }
            _ => Err(XmlEncError::KeyNotFound),
        }
    }
    fn resolve_content_keys_with_policy(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
        policy: &crate::policy::DecryptionPolicy,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<crate::provider::RecoveredContentKey>, XmlEncError> {
        policy.validate()?;
        let encrypted_key = encrypted_key.ok_or(XmlEncError::KeyNotFound)?;
        validate_encrypted_key_policy(encrypted_key, policy)?;
        budget.consume(1)?;
        Ok(vec![crate::provider::RecoveredContentKey::confirmed(
            self.resolve_key(provider, algorithm, Some(encrypted_key))?,
        )])
    }

    fn resolve_key_candidates_with_policy(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
        policy: &crate::policy::DecryptionPolicy,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<Vec<u8>>, XmlEncError> {
        self.resolve_content_keys_with_policy(provider, algorithm, encrypted_key, policy, budget)?
            .into_iter()
            .map(|key| key.into_key().map_err(XmlEncError::from))
            .collect()
    }

    fn resolve_key(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
    ) -> Result<Vec<u8>, XmlEncError> {
        let encrypted_key = encrypted_key.ok_or(XmlEncError::KeyNotFound)?;
        let key = self.unwrap(provider, algorithm.key_len(), encrypted_key)?;
        validate_key_len(algorithm, &key)?;
        Ok(key)
    }
}

impl KekDecryptor<'_> {
    fn unwrap(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        output_len: usize,
        encrypted_key: &EncryptedKey,
    ) -> Result<Vec<u8>, XmlEncError> {
        encrypted_key.encryption_method.validate_structure()?;
        let wrap_algorithm =
            KeyWrapAlgorithm::from_uri(&encrypted_key.encryption_method.algorithm)?;
        // XMLEnc 1.1 section 6.1.3 recommends key separation between algorithms:
        // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-backwards-compatibility-attacks
        // Equal AES-192 and TripleDES widths do not establish key identity.
        if self.kind != wrap_algorithm.key_kind() {
            return Err(XmlEncError::KeyNotFound);
        }
        let wrapped = encrypted_key.cipher_data.octets()?;
        let expected_kek_len = wrap_algorithm.key_len();
        if self.kek.len() != expected_kek_len {
            return Err(XmlEncError::InvalidKekSize {
                algorithm: wrap_algorithm,
                expected: expected_kek_len,
                actual: self.kek.len(),
            });
        }
        let expected_wrapped_len = output_len + wrap_algorithm.overhead();
        if wrapped.len() != expected_wrapped_len {
            return Err(XmlEncError::InvalidWrappedKeyLength {
                expected: expected_wrapped_len,
                actual: wrapped.len(),
            });
        }
        provider.require_capability(crate::provider::ProviderCapability::KeyUnwrap(
            wrap_algorithm,
        ))?;
        let key = provider
            .unwrap_key(wrap_algorithm, &self.kek, &wrapped)
            .map_err(|error| match error {
                crate::provider::ProviderError::InvalidKeySize { expected, actual } => {
                    XmlEncError::InvalidKekSize {
                        algorithm: wrap_algorithm,
                        expected,
                        actual,
                    }
                }
                crate::provider::ProviderError::AuthenticationFailed
                | crate::provider::ProviderError::InvalidInput(
                    crate::provider::ProviderInputError::AesKeyWrapFraming,
                ) => XmlEncError::KeyWrapIntegrity,
                error => XmlEncError::Provider(error),
            })?;
        if key.len() != output_len {
            return Err(XmlEncError::InvalidWrappedKeyLength {
                expected: output_len,
                actual: key.len(),
            });
        }
        Ok(key)
    }
}

impl PrivateKeyDecryptor {
    /// Create a resolver from an already-parsed RSA private key.
    pub fn new(key: RsaPrivateKey) -> Self {
        Self::provider_key(Arc::new(crate::provider::RustCryptoRsaPrivateKey::new(key)))
    }

    /// Create a resolver from an opaque provider-owned recovery key.
    pub fn provider_key(key: Arc<dyn crate::provider::KeyRecoveryKey>) -> Self {
        Self { key }
    }
}

impl DecryptionKeyResolver for PrivateKeyDecryptor {
    fn resolve_key_encryption_keys_with_policy(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: KeyWrapAlgorithm,
        source: KeyEncryptionKeySource<'_>,
        policy: &crate::policy::DecryptionPolicy,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<crate::provider::RecoveredContentKey>, XmlEncError> {
        let KeyEncryptionKeySource::Encrypted(key) = source else {
            return Err(XmlEncError::KeyNotFound);
        };
        validate_encrypted_key_policy(key, policy)?;
        let width = policy.rsa_keys.validate_public_metadata(
            "decryption",
            self.key.rsa_modulus_bits(),
            self.key.rsa_public_exponent(),
        )?;
        let ciphertext = key.cipher_data.octets()?;
        if width != self.key.ciphertext_len() || ciphertext.len() != width {
            return Err(XmlEncError::InvalidWrappedKeyLength {
                expected: width,
                actual: ciphertext.len(),
            });
        }
        let transport = KeyTransportAlgorithm::from_uri(&key.encryption_method.algorithm)?;
        budget.consume(2)?;
        #[cfg(feature = "legacy-algorithms")]
        if transport == KeyTransportAlgorithm::RsaPkcs1v15 {
            provider.require_capability(crate::provider::ProviderCapability::Pkcs1v15Recovery)?;
            return Ok(vec![provider.recover_pkcs1v15(
                self.key.as_ref(),
                &ciphertext,
                algorithm.key_len(),
            )?]);
        }
        let method = &key.encryption_method;
        let parameters = RsaOaepParameters {
            algorithm: transport,
            digest: parse_oaep_digest(method.oaep_digest.as_deref())?,
            mgf_digest: parse_oaep_mgf_digest(method.mgf_algorithm.as_deref())?,
            label: method.oaep_params.clone().unwrap_or_default(),
        };
        provider.require_capability(crate::provider::ProviderCapability::KeyRecovery(
            &parameters,
        ))?;
        let key = zeroize::Zeroizing::new(provider.recover_key(
            self.key.as_ref(),
            &parameters,
            &ciphertext,
        )?);
        if key.len() != algorithm.key_len() {
            return Err(XmlEncError::InvalidKekSize {
                algorithm,
                expected: algorithm.key_len(),
                actual: key.len(),
            });
        }
        let mut key = key;
        Ok(vec![crate::provider::RecoveredContentKey::confirmed(
            core::mem::take(&mut *key),
        )])
    }
    fn resolve_content_keys_with_policy(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
        policy: &crate::policy::DecryptionPolicy,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<crate::provider::RecoveredContentKey>, XmlEncError> {
        policy.validate()?;
        budget.consume(1)?;
        self.resolve_key_with_policy(provider, algorithm, encrypted_key, policy)
            .map(|key| vec![key])
    }
    fn resolve_key_candidates_with_policy(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
        policy: &crate::policy::DecryptionPolicy,
        budget: &mut KeyCandidateBudget,
    ) -> Result<Vec<Vec<u8>>, XmlEncError> {
        policy.validate()?;
        budget.consume(1)?;
        self.resolve_key_with_policy(provider, algorithm, encrypted_key, policy)
            .and_then(|key| key.into_key().map_err(XmlEncError::Provider))
            .map(|key| vec![key])
    }

    fn resolve_key(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
    ) -> Result<Vec<u8>, XmlEncError> {
        self.resolve_key_with_policy(
            provider,
            algorithm,
            encrypted_key,
            &crate::policy::DecryptionPolicy::default(),
        )
        .and_then(|key| key.into_key().map_err(XmlEncError::Provider))
    }
}

impl PrivateKeyDecryptor {
    /// Recover one session key using the exact operation policy. This avoids
    /// a temporary candidate collection when composing ordered RSA key rings.
    pub fn resolve_key_with_policy(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
        policy: &crate::policy::DecryptionPolicy,
    ) -> Result<crate::provider::RecoveredContentKey, XmlEncError> {
        policy.validate()?;
        let encrypted_key = encrypted_key.ok_or(XmlEncError::KeyNotFound)?;
        validate_encrypted_key_policy(encrypted_key, policy)?;
        let width = policy.rsa_keys.validate_public_metadata(
            "decryption",
            self.key.rsa_modulus_bits(),
            self.key.rsa_public_exponent(),
        )?;
        if width != self.key.ciphertext_len() {
            return Err(crate::policy::PolicyViolation::InvalidKeyMaterial {
                operation: "decryption",
                key_type: "RSA",
                reason: "ciphertext width disagrees with modulus",
            }
            .into());
        }
        encrypted_key.encryption_method.validate_structure()?;
        let wrapped = encrypted_key.cipher_data.octets()?;
        let label = encrypted_key
            .encryption_method
            .oaep_params
            .clone()
            .unwrap_or_default();
        let transport =
            KeyTransportAlgorithm::from_uri(&encrypted_key.encryption_method.algorithm)?;
        let key = match transport {
            #[cfg(feature = "legacy-algorithms")]
            KeyTransportAlgorithm::RsaPkcs1v15 => {
                if wrapped.len() != self.key.ciphertext_len() {
                    return Err(XmlEncError::InvalidWrappedKeyLength {
                        expected: self.key.ciphertext_len(),
                        actual: wrapped.len(),
                    });
                }
                provider
                    .require_capability(crate::provider::ProviderCapability::Pkcs1v15Recovery)?;
                // Recovery conceals padding/range rejection with a random CEK;
                // only operational provider failures propagate here. The RFC
                // padding-error rule is RFC 8017 §7.2.2's note:
                // https://www.rfc-editor.org/rfc/rfc8017#section-7.2.2.
                provider
                    .recover_pkcs1v15(self.key.as_ref(), &wrapped, algorithm.key_len())
                    .map_err(XmlEncError::Provider)
            }
            KeyTransportAlgorithm::RsaOaepMgf1p => self.decrypt_oaep_mgf1p(
                provider,
                encrypted_key.encryption_method.oaep_digest.as_deref(),
                encrypted_key.encryption_method.mgf_algorithm.as_deref(),
                label,
                &wrapped,
                algorithm,
            ),
            KeyTransportAlgorithm::RsaOaep11 => self.decrypt_oaep11(
                provider,
                encrypted_key.encryption_method.oaep_digest.as_deref(),
                encrypted_key.encryption_method.mgf_algorithm.as_deref(),
                label,
                &wrapped,
                algorithm,
            ),
        }?;
        validate_content_key_len(algorithm, key.key_len())?;
        Ok(key)
    }
}

impl PrivateKeyDecryptor {
    fn decrypt_oaep_mgf1p(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        digest: Option<&str>,
        mgf: Option<&str>,
        label: Vec<u8>,
        wrapped: &[u8],
        algorithm: DataEncryptionAlgorithm,
    ) -> Result<crate::provider::RecoveredContentKey, XmlEncError> {
        let parameters = RsaOaepParameters {
            algorithm: KeyTransportAlgorithm::RsaOaepMgf1p,
            digest: parse_oaep_digest(digest)?,
            mgf_digest: parse_oaep_mgf_digest(mgf)?,
            label,
        };
        recover_rsa_oaep(provider, self.key.as_ref(), &parameters, wrapped, algorithm)
    }

    fn decrypt_oaep11(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        digest: Option<&str>,
        mgf: Option<&str>,
        label: Vec<u8>,
        wrapped: &[u8],
        algorithm: DataEncryptionAlgorithm,
    ) -> Result<crate::provider::RecoveredContentKey, XmlEncError> {
        let parameters = RsaOaepParameters {
            algorithm: KeyTransportAlgorithm::RsaOaep11,
            digest: parse_oaep_digest(digest)?,
            mgf_digest: parse_oaep_mgf_digest(mgf)?,
            label,
        };
        recover_rsa_oaep(provider, self.key.as_ref(), &parameters, wrapped, algorithm)
    }
}

fn parse_oaep_digest(uri: Option<&str>) -> Result<OaepDigestAlgorithm, XmlEncError> {
    let uri = uri.unwrap_or("http://www.w3.org/2000/09/xmldsig#sha1");
    OaepDigestAlgorithm::from_uri(uri)
        .ok_or_else(|| XmlEncError::UnsupportedAlgorithm(uri.to_owned()))
}

fn parse_oaep_mgf_digest(uri: Option<&str>) -> Result<OaepDigestAlgorithm, XmlEncError> {
    let uri = uri.unwrap_or("http://www.w3.org/2009/xmlenc11#mgf1sha1");
    OaepDigestAlgorithm::from_mgf_uri(uri)
        .ok_or_else(|| XmlEncError::UnsupportedAlgorithm(uri.to_owned()))
}

fn recover_rsa_oaep(
    provider: &dyn crate::provider::CryptoProvider,
    key: &dyn crate::provider::KeyRecoveryKey,
    parameters: &RsaOaepParameters,
    wrapped: &[u8],
    algorithm: DataEncryptionAlgorithm,
) -> Result<crate::provider::RecoveredContentKey, XmlEncError> {
    let expected = key.ciphertext_len();
    if wrapped.len() != expected {
        return Err(XmlEncError::InvalidWrappedKeyLength {
            expected,
            actual: wrapped.len(),
        });
    }
    provider.require_capability(crate::provider::ProviderCapability::KeyRecovery(parameters))?;
    provider
        .recover_content_key(key, parameters, algorithm, wrapped)
        .map_err(|error| match error {
            crate::provider::ProviderError::Random(message) => XmlEncError::Rng(message),
            error @ (crate::provider::ProviderError::AuthenticationFailed
            | crate::provider::ProviderError::InvalidInput(_)) => {
                XmlEncError::Rsa(error.to_string())
            }
            error => XmlEncError::Provider(error),
        })
}

/// Parse and decrypt a standalone `EncryptedData` XML fragment.
pub fn decrypt(
    xml: &str,
    resolver: &dyn DecryptionKeyResolver,
) -> Result<DecryptedContent, XmlEncError> {
    DecryptContext::new(resolver).decrypt(xml)
}

/// Decrypt and replace one `EncryptedData` element in a caller-owned XML document.
///
/// When `encrypted_data_id` is `None`, the document must contain exactly one
/// `EncryptedData`. The decrypted value must declare either the XMLEnc `Element`
/// or `Content` type. Plaintext is parsed inside a bounded replacement wrapper
/// before insertion, and the returned document is parsed again before exposure.
pub fn decrypt_document(
    xml: &str,
    encrypted_data_id: Option<&str>,
    resolver: &dyn DecryptionKeyResolver,
) -> Result<String, XmlEncError> {
    decrypt_document_with_options(
        xml,
        DocumentDecryptionOptions { encrypted_data_id },
        resolver,
    )
}

/// Decrypt and replace one `EncryptedData` using the default decryption policy.
///
/// Use [`DecryptContext`] when XML-input or resource policy must differ from
/// the secure defaults; options here contain request selection only.
pub fn decrypt_document_with_options(
    xml: &str,
    options: DocumentDecryptionOptions<'_>,
    resolver: &dyn DecryptionKeyResolver,
) -> Result<String, XmlEncError> {
    DecryptContext::new(resolver).decrypt_document(xml, options.encrypted_data_id)
}

#[derive(Clone, Copy)]
enum DocumentEncryptedDataSelector<'a> {
    EncryptedDataId(Option<&'a str>),
    UniqueBelowStartNode(Option<&'a str>),
    FirstBelowStartNode(Option<&'a str>),
}

fn decrypt_document_with_context(
    xml: &str,
    selector: DocumentEncryptedDataSelector<'_>,
    context: &DecryptContext<'_>,
) -> Result<String, XmlEncError> {
    context.policy.resources.validate()?;
    validate_encryption_document_len(xml.len(), &context.policy)?;
    let budgets = DecryptionOperationBudgets::from_policy(&context.policy);
    let settings = context.document_parse_settings();
    let mut document =
        XmlDocument::parse_with_settings_and_budget(xml.to_owned(), settings, &budgets.xml_parse)
            .map_err(|error| map_document_error(error, settings))?;
    decrypt_owned_document_with_context(&mut document, selector, context, budgets)?;
    Ok(document.into_xml())
}

fn decrypt_owned_document_with_context(
    document: &mut XmlDocument,
    selector: DocumentEncryptedDataSelector<'_>,
    context: &DecryptContext<'_>,
    budgets: DecryptionOperationBudgets,
) -> Result<(), XmlEncError> {
    context.policy.resources.validate()?;
    document.validate_operation_policy(&context.policy.xml, &context.policy.resources)?;
    let (target, target_len, target_start, replacement_type) = document.with_view(|view| {
        let start = match selector {
            DocumentEncryptedDataSelector::UniqueBelowStartNode(Some(id))
            | DocumentEncryptedDataSelector::FirstBelowStartNode(Some(id)) => view
                .node_for_id(id, context.id_attributes)
                .ok_or_else(|| XmlEncError::SelectedNodeUnavailable { id: id.to_owned() })
                .and_then(|identity| view.resolve_node(identity).map_err(XmlEncError::from))?,
            DocumentEncryptedDataSelector::UniqueBelowStartNode(None)
            | DocumentEncryptedDataSelector::FirstBelowStartNode(None)
            | DocumentEncryptedDataSelector::EncryptedDataId(_) => view.document().root(),
        };
        let encrypted_data_id = match selector {
            DocumentEncryptedDataSelector::EncryptedDataId(id) => id,
            DocumentEncryptedDataSelector::UniqueBelowStartNode(_)
            | DocumentEncryptedDataSelector::FirstBelowStartNode(_) => None,
        };
        let mut matches = start.descendants().filter(|node| {
            node.has_tag_name((XMLENC_NS, "EncryptedData"))
                && encrypted_data_id.is_none_or(|id| node.attribute("Id") == Some(id))
        });
        let selected = matches.next().ok_or(XmlEncError::EncryptedDataNotFound)?;
        if matches!(
            selector,
            DocumentEncryptedDataSelector::EncryptedDataId(_)
                | DocumentEncryptedDataSelector::UniqueBelowStartNode(_)
        ) && matches.next().is_some()
        {
            return Err(XmlEncError::AmbiguousEncryptedData);
        }
        Ok::<_, XmlEncError>((
            view.node_identity(selected),
            selected.range().len(),
            selected.range().start,
            match selected.attribute("Type") {
                Some("http://www.w3.org/2001/04/xmlenc#Element") => {
                    Some(EncryptedDataType::Element)
                }
                Some("http://www.w3.org/2001/04/xmlenc#Content") => {
                    Some(EncryptedDataType::Content)
                }
                _ => None,
            },
        ))
    })?;
    let document_binding = Some((document.identity(), document.generation()));
    let mut processed = context.process_decryption_input(
        DecryptionInput::Xml {
            source: document.as_xml(),
            node_start: Some(target_start),
        },
        document_binding,
        true,
        budgets,
        |candidate, operation_parse_budget| {
            let DecryptedContent::Xml(plaintext) = candidate else {
                return Err(XmlEncError::ReplacementRequiresXml);
            };
            validate_encryption_document_len(
                document
                    .as_xml()
                    .len()
                    .saturating_sub(target_len)
                    .saturating_add(plaintext.len()),
                &context.policy,
            )?;
            let settings = context.document_parse_settings();
            match replacement_type.as_ref() {
                Some(EncryptedDataType::Element) => document
                    .prepare_element_replacement_with_budget(
                        target,
                        &plaintext,
                        settings,
                        operation_parse_budget,
                    )
                    .map_err(|error| map_document_error(error, settings)),
                Some(EncryptedDataType::Content) => document
                    .prepare_node_fragment_replacement_with_budget(
                        target,
                        &plaintext,
                        settings,
                        operation_parse_budget,
                    )
                    .map_err(|error| map_document_error(error, settings)),
                Some(EncryptedDataType::Other(_)) | None => {
                    Err(XmlEncError::ReplacementRequiresXml)
                }
            }
        },
    )?;
    let mutation = processed.mutation.ok_or_else(|| {
        XmlEncError::OperationPlan("decryption mutation node is unavailable".into())
    })?;
    processed
        .operation
        .run_document_transition(mutation, document, |document, _| {
            document
                .commit_prepared(processed.output)
                .map_err(|error| map_document_error(error, context.document_parse_settings()))
        })
}

fn validate_encryption_document_len(
    actual: usize,
    policy: &crate::policy::DecryptionPolicy,
) -> Result<(), XmlEncError> {
    policy.resources.validate_xml_document_len(actual)?;
    Ok(())
}

fn validate_recipient_count(actual: usize, maximum: usize) -> Result<(), XmlEncError> {
    if actual > maximum {
        return Err(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::ENCRYPTION_RECIPIENTS,
            maximum,
            actual,
        }
        .into());
    }
    Ok(())
}

/// Decrypt an already parsed `EncryptedData` value.
pub fn decrypt_data(
    encrypted: &EncryptedData,
    resolver: &dyn DecryptionKeyResolver,
) -> Result<DecryptedContent, XmlEncError> {
    DecryptContext::new(resolver).decrypt_data(encrypted)
}

fn resolve_content_key_candidates(
    provider: &dyn crate::provider::CryptoProvider,
    algorithm: DataEncryptionAlgorithm,
    encrypted: &EncryptedData,
    resolver: &dyn DecryptionKeyResolver,
    policy: &crate::policy::DecryptionPolicy,
    budget: &mut KeyCandidateBudget,
    mut document: Option<KeySourceDocument<'_, '_>>,
) -> Result<Vec<crate::provider::RecoveredContentKey>, XmlEncError> {
    let mut last_error = None;
    let mut candidates = if encrypted.derived_keys.is_empty()
        && encrypted.agreement_methods.is_empty()
    {
        match resolve_candidates_with_budget(resolver, provider, algorithm, None, policy, budget) {
            Ok(keys) => keys,
            Err(error) => {
                record_candidate_source_error_or_fail_operation(error, &mut last_error)?;
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    for descriptor in &encrypted.agreement_methods {
        let remaining_before = budget.remaining();
        match resolver.resolve_agreement_content_keys_with_policy(
            provider, algorithm, descriptor, policy, budget,
        ) {
            Ok(keys) => {
                budget.account_returned_candidates(remaining_before, keys.len())?;
                candidates.extend(keys);
            }
            Err(error) => record_candidate_source_error_or_fail_operation(error, &mut last_error)?,
        }
    }
    for descriptor in &encrypted.derived_keys {
        if !reference_list_applies_to_target(
            descriptor.reference_list.as_ref(),
            ReferenceTarget::new(document, encrypted.id.as_deref()),
            ReferenceKind::Data,
        ) {
            continue;
        }
        let remaining_before = budget.remaining();
        match resolver.resolve_derived_content_keys_with_policy(
            provider, algorithm, descriptor, policy, budget,
        ) {
            Ok(keys) => {
                budget.account_returned_candidates(remaining_before, keys.len())?;
                candidates.extend(keys);
            }
            Err(error) => record_candidate_source_error_or_fail_operation(error, &mut last_error)?,
        }
    }
    for encrypted_key in &encrypted.encrypted_keys {
        let source = KeySourceView {
            key: encrypted_key,
            document: take_key_document(&mut document, encrypted_key)?,
        };
        if !encrypted_key_applies_to_data(
            encrypted_key,
            encrypted,
            ReferenceTarget::new(document, encrypted.id.as_deref()),
        ) {
            continue;
        }
        if let Err(error) = validate_encrypted_key_policy(encrypted_key, policy) {
            last_error = Some(error);
            continue;
        }
        let resolution = if encrypted_key.sources.is_empty() {
            resolve_candidates_with_budget(
                resolver,
                provider,
                algorithm,
                Some(encrypted_key),
                policy,
                budget,
            )
        } else {
            resolve_nested_key(
                provider,
                source,
                algorithm.key_len(),
                resolver,
                policy,
                budget,
                1,
            )
        };
        match resolution {
            Ok(keys) => candidates.extend(keys),
            Err(error) => record_candidate_source_error_or_fail_operation(error, &mut last_error)?,
        }
    }
    if candidates.is_empty() {
        Err(last_error.unwrap_or(XmlEncError::KeyNotFound))
    } else {
        Ok(candidates)
    }
}

pub(super) fn resolve_nested_cipher_references<'a>(
    keys: &mut [EncryptedKey],
    document: &crate::XmlDomDocument<'_>,
    origins: &mut core::slice::Iter<'_, Option<crate::NodeId>>,
    context: &super::cipher_reference::BoundCipherReferenceContext<'a, 'a>,
    parse: &XmlParseWorkBudget,
) -> Result<(), XmlEncError> {
    // The metadata pass already enforces the non-configurable key recursion
    // ceiling. Keep original nodes and one shared transform/resource context.
    for key in keys {
        let origin = origins
            .next()
            .ok_or_else(|| XmlEncError::OperationPlan("missing encrypted key origin".into()))?;
        if let super::CipherData::Reference { uri, transforms } = &key.cipher_data {
            let node = origin.and_then(|id| document.get_node(id)).ok_or_else(|| {
                XmlEncError::OperationPlan("unresolved foreign encrypted key origin".into())
            })?;
            key.cipher_data = super::CipherData::Bytes(context.resolve_parsed(
                cipher_reference_node(node)?,
                uri,
                transforms,
                parse,
            )?);
        }
        resolve_nested_cipher_references(
            &mut key.sources.encrypted_keys,
            document,
            origins,
            context,
            parse,
        )?;
    }
    Ok(())
}

fn resolve_nested_key(
    provider: &dyn crate::provider::CryptoProvider,
    source: KeySourceView<'_, '_>,
    output_len: usize,
    resolver: &dyn DecryptionKeyResolver,
    policy: &crate::policy::DecryptionPolicy,
    budget: &mut KeyCandidateBudget,
    depth: usize,
) -> Result<Vec<crate::provider::RecoveredContentKey>, XmlEncError> {
    let key = source.key;
    let mut document = source.document;
    let target = ReferenceTarget::new(document, key.id.as_deref());
    policy.resources.validate_key_info_reference_depth(depth)?;
    validate_encrypted_key_policy(key, policy)?;
    let wrap = KeyWrapAlgorithm::from_uri(&key.encryption_method.algorithm)?;
    provider.require_capability(crate::provider::ProviderCapability::KeyUnwrap(wrap))?;
    let ciphertext = key.cipher_data.octets()?;
    let expected = output_len + wrap.overhead();
    if ciphertext.len() != expected {
        return Err(XmlEncError::InvalidWrappedKeyLength {
            expected,
            actual: ciphertext.len(),
        });
    }
    let mut keys = Vec::new();
    let mut last_error = None;
    let mut resolve_source = |source| -> Result<(), XmlEncError> {
        let remaining = budget.remaining();
        match resolver
            .resolve_key_encryption_keys_with_policy(provider, wrap, source, policy, budget)
        {
            Ok(resolved) => {
                budget.account_returned_candidates(remaining, resolved.len())?;
                keys.extend(resolved);
                Ok(())
            }
            Err(error) => record_candidate_source_error_or_fail_operation(error, &mut last_error),
        }
    };
    for agreement in &key.sources.agreement_methods {
        resolve_source(KeyEncryptionKeySource::Agreement(agreement))?;
    }
    for derived in &key.sources.derived_keys {
        if !reference_list_applies_to_target(
            derived.reference_list.as_ref(),
            target,
            ReferenceKind::Key,
        ) {
            continue;
        }
        resolve_source(KeyEncryptionKeySource::Derived(derived))?;
    }
    for nested in &key.sources.encrypted_keys {
        let source = KeySourceView {
            key: nested,
            document: take_key_document(&mut document, nested)?,
        };
        if !reference_list_applies_to_target(
            nested.reference_list.as_ref(),
            target,
            ReferenceKind::Key,
        ) {
            continue;
        }
        let resolved = if nested.sources.is_empty() {
            budget.require_available(3)?;
            let remaining = budget.remaining();
            resolver
                .resolve_key_encryption_keys_with_policy(
                    provider,
                    wrap,
                    KeyEncryptionKeySource::Encrypted(nested),
                    policy,
                    budget,
                )
                .and_then(|resolved| {
                    budget.account_returned_candidates(remaining, resolved.len())?;
                    Ok(resolved)
                })
        } else {
            resolve_nested_key(
                provider,
                source,
                wrap.key_len(),
                resolver,
                policy,
                budget,
                depth + 1,
            )
        };
        match resolved {
            Ok(resolved) => keys.extend(resolved),
            Err(error) => record_candidate_source_error_or_fail_operation(error, &mut last_error)?,
        }
    }
    let mut outputs = Vec::new();
    // XMLEnc §3.5.1 supplies recovered octets directly to the consuming
    // EncryptionMethod. No content-algorithm proxy or base64 round trip.
    // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-EncryptedKey
    for kek in keys {
        if kek.key_len() != wrap.key_len() {
            last_error = Some(XmlEncError::InvalidKekSize {
                algorithm: wrap,
                expected: wrap.key_len(),
                actual: kek.key_len(),
            });
            continue;
        }
        budget.consume(1)?;
        match kek.unwrap_nested(provider, wrap, &ciphertext, output_len) {
            Ok(result) if result.key_len() == output_len => outputs.push(result),
            Ok(result) => {
                last_error = Some(XmlEncError::InvalidWrappedKeyLength {
                    expected: output_len,
                    actual: result.key_len(),
                })
            }
            Err(error) => last_error = Some(XmlEncError::Provider(error)),
        }
    }
    if outputs.is_empty() {
        Err(last_error.unwrap_or(XmlEncError::KeyNotFound))
    } else {
        Ok(outputs)
    }
}

#[derive(Clone, Copy)]
struct KeySourceDocument<'a, 'doc> {
    references: &'a super::cipher_reference::BoundCipherReferenceContext<'doc, 'doc>,
    target: crate::NodeId,
    origins: &'a [Option<crate::NodeId>],
}

struct KeySourceView<'a, 'doc> {
    key: &'a EncryptedKey,
    document: Option<KeySourceDocument<'a, 'doc>>,
}

fn key_origin_count(key: &EncryptedKey) -> usize {
    // Metadata validation has already bounded total candidates and recursion.
    // Each identity is counted at most once per bounded key-indirection level.
    1 + key
        .sources
        .encrypted_keys
        .iter()
        .map(key_origin_count)
        .sum::<usize>()
}

fn take_key_document<'a, 'doc>(
    document: &mut Option<KeySourceDocument<'a, 'doc>>,
    key: &EncryptedKey,
) -> Result<Option<KeySourceDocument<'a, 'doc>>, XmlEncError> {
    let Some(parent) = document else {
        return Ok(None);
    };
    let count = key_origin_count(key);
    if count > parent.origins.len() {
        return Err(XmlEncError::OperationPlan(
            "missing key association origin".into(),
        ));
    }
    let (subtree, remaining) = parent.origins.split_at(count);
    parent.origins = remaining;
    Ok(subtree[0].map(|target| KeySourceDocument {
        references: parent.references,
        target,
        origins: &subtree[1..],
    }))
}

#[derive(Clone, Copy)]
enum ReferenceTarget<'a, 'doc> {
    Document {
        references: &'a super::cipher_reference::BoundCipherReferenceContext<'doc, 'doc>,
        node: crate::NodeId,
    },
    TypedId(Option<&'a str>),
}

impl<'a, 'doc> ReferenceTarget<'a, 'doc> {
    fn new(document: Option<KeySourceDocument<'a, 'doc>>, id: Option<&'a str>) -> Self {
        match document {
            Some(source) => Self::Document {
                references: source.references,
                node: source.target,
            },
            None => Self::TypedId(id),
        }
    }

    fn matches(self, uri: &str) -> bool {
        // XMLEnc 1.1 §3.6 references objects through URIs, not specifically the
        // lexical Id attribute. XML operations retain the original document's
        // registered IDs, ambiguity checks and configured fragment grammar.
        // Typed-only requests have no DOM and can use only their explicit Id.
        // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-ReferenceList
        match self {
            Self::Document { references, node } => references
                .resolver()
                .same_document_reference_targets(uri, node),
            Self::TypedId(id) => id.is_some_and(|id| reference_targets_id(uri, id)),
        }
    }
}

enum ReferenceKind {
    Data,
    Key,
}

fn record_candidate_source_error_or_fail_operation(
    error: XmlEncError,
    last_error: &mut Option<XmlEncError>,
) -> Result<(), XmlEncError> {
    // Candidate-specific failures permit the next ordered key source. The
    // shared work ceiling is operation-wide and must never be recoverable by
    // advancing to another recipient.
    if matches!(&error, XmlEncError::Policy(_)) {
        return Err(error);
    }
    *last_error = Some(error);
    Ok(())
}

fn resolve_candidates_with_budget(
    resolver: &dyn DecryptionKeyResolver,
    provider: &dyn crate::provider::CryptoProvider,
    algorithm: DataEncryptionAlgorithm,
    encrypted_key: Option<&EncryptedKey>,
    policy: &crate::policy::DecryptionPolicy,
    budget: &mut KeyCandidateBudget,
) -> Result<Vec<crate::provider::RecoveredContentKey>, XmlEncError> {
    let remaining_before = budget.remaining();
    let keys = resolver.resolve_content_keys_with_policy(
        provider,
        algorithm,
        encrypted_key,
        policy,
        budget,
    )?;
    budget.account_returned_candidates(remaining_before, keys.len())?;
    Ok(keys)
}

fn encrypted_key_applies_to_data(
    encrypted_key: &EncryptedKey,
    encrypted_data: &EncryptedData,
    target: ReferenceTarget<'_, '_>,
) -> bool {
    // XMLEnc association metadata is optional, but authoritative when present:
    // DataReference identifies encrypted objects and CarriedKeyName identifies
    // the transported key referenced by the enclosing ds:KeyName.
    if !reference_list_applies_to_target(
        encrypted_key.reference_list.as_ref(),
        target,
        ReferenceKind::Data,
    ) {
        return false;
    }
    if let (Some(carried), Some(expected)) = (
        encrypted_key.carried_key_name.as_deref(),
        encrypted_data.key_name.as_deref(),
    ) && carried != expected
    {
        return false;
    }
    true
}

fn reference_list_applies_to_target(
    references: Option<&super::ReferenceList>,
    target: ReferenceTarget<'_, '_>,
    kind: ReferenceKind,
) -> bool {
    let Some(references) = references else {
        return true;
    };
    let uris = match kind {
        ReferenceKind::Data => &references.data_references,
        ReferenceKind::Key => &references.key_references,
    };
    if uris.is_empty() {
        return true;
    }
    for uri in uris {
        if target.matches(uri) {
            return true;
        }
    }
    false
}

fn reference_targets_id(uri: &str, id: &str) -> bool {
    let Some(fragment) = uri.strip_prefix('#') else {
        return false;
    };
    // Share XMLDSig's XPointer grammar rather than treating every fragment as
    // an ID string; XMLEnc §3.6 uses URI references for both object classes.
    // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-ReferenceList
    fragment == id || crate::xmldsig::uri::parse_xpointer_id_fragment(fragment) == Some(id)
}

fn compatible_decryption_key_candidates(
    algorithm: DataEncryptionAlgorithm,
    mut keys: Vec<crate::provider::RecoveredContentKey>,
) -> Result<Vec<crate::provider::RecoveredContentKey>, XmlEncError> {
    let mut accepted = 0;
    let mut last_error = None;
    for index in 0..keys.len() {
        let key = &keys[index];
        match validate_content_key_len(algorithm, key.key_len()) {
            Ok(())
                if !keys[..accepted]
                    .iter()
                    .any(|existing| existing.same_candidate(key)) =>
            {
                // Accepted entries form a stable prefix. Swapping an earlier
                // rejected slot never moves an unvisited entry, and avoids a
                // second allocation without changing candidate precedence.
                keys.swap(accepted, index);
                accepted += 1;
            }
            Ok(()) => {}
            Err(error) => last_error = Some(error),
        }
    }
    keys.truncate(accepted);
    if keys.is_empty() {
        return Err(last_error.unwrap_or(XmlEncError::KeyNotFound));
    }
    Ok(keys)
}

fn validate_decryption_key_candidates(
    algorithm: DataEncryptionAlgorithm,
    actual: usize,
) -> Result<(), XmlEncError> {
    let maximum = crate::hard_limits::KEY_CANDIDATE_CEILING;
    if actual > maximum {
        return Err(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::KEY_CANDIDATES,
            maximum,
            actual,
        }
        .into());
    }
    if actual > 1 && algorithm.cbc_block_len().is_some() {
        return Err(XmlEncError::AmbiguousKeyCandidates { algorithm, actual });
    }
    Ok(())
}

fn validate_encrypted_key_policy(
    encrypted_key: &EncryptedKey,
    policy: &crate::policy::DecryptionPolicy,
) -> Result<(), XmlEncError> {
    validate_key_encryption_method_policy(&encrypted_key.encryption_method, policy)
}

pub(super) fn validate_key_encryption_method_policy(
    method: &super::EncryptionMethod,
    policy: &crate::policy::DecryptionPolicy,
) -> Result<(), XmlEncError> {
    method.validate_structure()?;
    let uri = &method.algorithm;
    if let Ok(transport) = KeyTransportAlgorithm::from_uri(uri) {
        if policy
            .key_transport_algorithms
            .as_ref()
            .map_or(transport.requires_explicit_permission(), |allowed| {
                !allowed.contains(&transport)
            })
        {
            return Err(crate::policy::PolicyViolation::Algorithm {
                operation: "decryption",
                algorithm: uri.clone(),
            }
            .into());
        }
        #[cfg(feature = "legacy-algorithms")]
        if transport == KeyTransportAlgorithm::RsaPkcs1v15 {
            return Ok(());
        }
        let digest = parse_oaep_digest(method.oaep_digest.as_deref())?;
        let mgf_digest = parse_oaep_mgf_digest(method.mgf_algorithm.as_deref())?;
        let selected_algorithms = [
            (
                digest,
                method.oaep_digest.as_deref().unwrap_or(digest.uri()),
            ),
            (
                mgf_digest,
                method
                    .mgf_algorithm
                    .as_deref()
                    .unwrap_or(mgf_digest.mgf_uri()),
            ),
        ];
        for (selected, wire_uri) in selected_algorithms {
            if policy
                .oaep_digests
                .as_ref()
                .is_some_and(|allowed| !allowed.contains(&selected))
            {
                return Err(crate::policy::PolicyViolation::Algorithm {
                    operation: "decryption",
                    algorithm: wire_uri.to_owned(),
                }
                .into());
            }
        }
    } else {
        let wrap = KeyWrapAlgorithm::from_uri(uri)?;
        if policy
            .key_wrap_algorithms
            .as_ref()
            .map_or(wrap.requires_explicit_permission(), |allowed| {
                !allowed.contains(&wrap)
            })
        {
            return Err(crate::policy::PolicyViolation::Algorithm {
                operation: "decryption",
                algorithm: uri.clone(),
            }
            .into());
        }
    }
    Ok(())
}

fn validate_content_framing_before_resolution(
    algorithm: DataEncryptionAlgorithm,
    ciphertext_len: usize,
    encrypted_keys: &[EncryptedKey],
    policy: &crate::policy::DecryptionPolicy,
) -> Result<(), XmlEncError> {
    let Err(framing_error) = validate_ciphertext_framing(algorithm, ciphertext_len) else {
        return Ok(());
    };

    // If no embedded key uses a supported transport, that envelope error is
    // more specific than content framing: the ciphertext cannot be interpreted
    // under any supported key path. This inspection performs no key resolution
    // and never dispatches malformed content to a cryptographic provider.
    if !encrypted_keys.is_empty() {
        let mut last_key_error = None;
        for encrypted_key in encrypted_keys {
            match validate_encrypted_key_policy(encrypted_key, policy) {
                Ok(()) => return Err(framing_error),
                Err(error) => last_key_error = Some(error),
            }
        }
        if let Some(error) = last_key_error {
            return Err(error);
        }
    }
    Err(framing_error)
}

fn validate_typed_cipher_values(
    encrypted: &EncryptedData,
    algorithm: DataEncryptionAlgorithm,
    maximum_plaintext: usize,
    maximum_cipher_values: usize,
) -> Result<(), XmlEncError> {
    let maximum_ciphertext = algorithm
        .ciphertext_len_for_plaintext(maximum_plaintext)
        .ok_or(XmlEncError::InvalidEncryptionConfig(
            "ciphertext size overflow".into(),
        ))?;
    let projected = validate_cipher_data_len(&encrypted.cipher_data, maximum_ciphertext)?;
    if projected > maximum_ciphertext {
        return Err(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::ENCRYPTION_PLAINTEXT_BYTES,
            maximum: maximum_plaintext,
            actual: projected.saturating_sub(algorithm.minimum_ciphertext_len()),
        }
        .into());
    }

    let mut aggregate_encoded = cipher_data_storage_len(&encrypted.cipher_data);
    if aggregate_encoded > maximum_cipher_values {
        return Err(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::AGGREGATE_ENCRYPTION_CIPHER_VALUE_BYTES,
            maximum: maximum_cipher_values,
            actual: aggregate_encoded,
        }
        .into());
    }

    let maximum_wrapped_key = projected_decoded_len_for_encoded_len(MAX_CIPHER_VALUE_BASE64_LEN);
    validate_wrapped_cipher_values(
        &encrypted.encrypted_keys,
        maximum_wrapped_key,
        maximum_cipher_values,
        &mut aggregate_encoded,
    )
}

fn validate_wrapped_cipher_values(
    keys: &[EncryptedKey],
    maximum_wrapped_key: usize,
    maximum_cipher_values: usize,
    aggregate_encoded: &mut usize,
) -> Result<(), XmlEncError> {
    for encrypted_key in keys {
        validate_cipher_data_len(&encrypted_key.cipher_data, maximum_wrapped_key)?;
        *aggregate_encoded =
            aggregate_encoded.saturating_add(cipher_data_storage_len(&encrypted_key.cipher_data));
        if *aggregate_encoded > maximum_cipher_values {
            return Err(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::AGGREGATE_ENCRYPTION_CIPHER_VALUE_BYTES,
                maximum: maximum_cipher_values,
                actual: *aggregate_encoded,
            }
            .into());
        }
        validate_wrapped_cipher_values(
            &encrypted_key.sources.encrypted_keys,
            maximum_wrapped_key,
            maximum_cipher_values,
            aggregate_encoded,
        )?;
    }
    Ok(())
}

fn cipher_data_storage_len(cipher: &super::CipherData) -> usize {
    match cipher {
        super::CipherData::Value { value } => value.len(),
        super::CipherData::Bytes(bytes) => bytes.len(),
        super::CipherData::Reference { .. } => 0,
    }
}

fn validate_cipher_data_len(
    cipher: &super::CipherData,
    maximum: usize,
) -> Result<usize, XmlEncError> {
    match cipher {
        super::CipherData::Value { value } => validate_cipher_value_len(value, maximum),
        super::CipherData::Bytes(bytes) if bytes.len() <= maximum => Ok(bytes.len()),
        super::CipherData::Bytes(bytes) => Err(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::AGGREGATE_ENCRYPTION_CIPHER_VALUE_BYTES,
            maximum,
            actual: bytes.len(),
        }
        .into()),
        super::CipherData::Reference { .. } => Ok(0),
    }
}

fn validate_cipher_value_len(value: &str, maximum_decoded: usize) -> Result<usize, XmlEncError> {
    if value.len() > MAX_CIPHER_VALUE_BASE64_LEN {
        return Err(XmlEncError::InvalidStructure(format!(
            "CipherValue exceeds {MAX_CIPHER_VALUE_BASE64_LEN}-byte limit"
        )));
    }
    Ok(projected_decoded_len(value).min(maximum_decoded.saturating_add(1)))
}

fn projected_decoded_len(value: &str) -> usize {
    let padding = value
        .as_bytes()
        .iter()
        .rev()
        .take(2)
        .take_while(|byte| **byte == b'=')
        .count();
    projected_decoded_len_for_encoded_len(value.len()).saturating_sub(padding)
}

fn projected_decoded_len_for_encoded_len(encoded_len: usize) -> usize {
    encoded_len
        .checked_add(3)
        .map(|length| length / 4)
        .and_then(|quanta| quanta.checked_mul(3))
        .unwrap_or(usize::MAX)
}

pub(crate) fn validate_key_len(
    algorithm: DataEncryptionAlgorithm,
    key: &[u8],
) -> Result<(), XmlEncError> {
    validate_content_key_len(algorithm, key.len())
}

fn validate_content_key_len(
    algorithm: DataEncryptionAlgorithm,
    actual: usize,
) -> Result<(), XmlEncError> {
    if actual == algorithm.key_len() {
        Ok(())
    } else {
        Err(XmlEncError::InvalidKeySize {
            algorithm,
            expected: algorithm.key_len(),
            actual,
        })
    }
}

fn validate_possible_plaintext_len(
    algorithm: DataEncryptionAlgorithm,
    ciphertext_len: usize,
    maximum: usize,
) -> Result<(), XmlEncError> {
    // CBC's minimum includes an IV and one padded block; using that
    // maximum-padding case yields the safe pre-decryption plaintext lower bound.
    let framing = algorithm.minimum_ciphertext_len();
    validate_plaintext_len(ciphertext_len.saturating_sub(framing), maximum)
}

fn validate_provider_plaintext_len(
    algorithm: DataEncryptionAlgorithm,
    ciphertext_len: usize,
    plaintext_len: usize,
) -> Result<(), XmlEncError> {
    use crate::provider::{ProviderError, ProviderOperation};

    match algorithm.cbc_block_len() {
        None => {
            let expected = ciphertext_len - algorithm.minimum_ciphertext_len();
            if plaintext_len != expected {
                return Err(ProviderError::InvalidOutputSize {
                    operation: ProviderOperation::Decrypt,
                    expected,
                    actual: plaintext_len,
                }
                .into());
            }
        }
        Some(block) => {
            let padded_len = ciphertext_len - block;
            let minimum = padded_len - block;
            let maximum = padded_len - 1;
            if !(minimum..=maximum).contains(&plaintext_len) {
                return Err(ProviderError::InvalidOutputSizeRange {
                    operation: ProviderOperation::Decrypt,
                    minimum,
                    maximum,
                    actual: plaintext_len,
                }
                .into());
            }
        }
    }
    Ok(())
}

fn validate_plaintext_len(actual: usize, maximum: usize) -> Result<(), XmlEncError> {
    if actual <= maximum {
        Ok(())
    } else {
        Err(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::ENCRYPTION_PLAINTEXT_BYTES,
            maximum,
            actual,
        }
        .into())
    }
}

fn map_data_decryption_error(
    algorithm: DataEncryptionAlgorithm,
    ciphertext_len: usize,
    error: crate::provider::ProviderError,
) -> XmlEncError {
    use crate::provider::ProviderError;

    match error {
        ProviderError::AuthenticationFailed if algorithm.cbc_block_len().is_none() => {
            XmlEncError::AeadAuthenticationFailed
        }
        ProviderError::InvalidInput(crate::provider::ProviderInputError::AesGcmFraming)
            if algorithm.cbc_block_len().is_none() =>
        {
            XmlEncError::DataTooShort {
                algorithm: "AES-GCM",
                minimum: 28,
                actual: ciphertext_len,
            }
        }
        error @ ProviderError::InvalidInput(crate::provider::ProviderInputError::AesCbcFraming)
            if algorithm.cbc_block_len().is_some() =>
        {
            match super::types::validate_ciphertext_framing(algorithm, ciphertext_len) {
                Err(error) => error,
                Ok(()) => XmlEncError::Provider(error),
            }
        }
        ProviderError::InvalidInput(crate::provider::ProviderInputError::AesCbcCiphertext)
            if algorithm.cbc_block_len().is_some() =>
        {
            XmlEncError::InvalidPadding
        }
        error => XmlEncError::Provider(error),
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "legacy-algorithms")]
    #[test]
    fn legacy_cbc_rejects_ambiguous_candidates_before_decryption() {
        // CBC has no authentication tag: selecting a candidate by padding
        // success is unsafe for DES and AES-192 just as for existing AES modes.
        for algorithm in [
            super::DataEncryptionAlgorithm::TripleDesCbc,
            super::DataEncryptionAlgorithm::Aes192Cbc,
        ] {
            assert!(matches!(
                super::validate_decryption_key_candidates(algorithm, 2),
                Err(super::XmlEncError::AmbiguousKeyCandidates { actual: 2, .. })
            ));
        }
    }
    use std::cell::{Cell, RefCell};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::rsa_encoding::RsaPrivateKeyEncoding as _;
    use aes_gcm::{
        Aes128Gcm,
        aead::{AeadInOut, KeyInit},
    };
    use aes_kw::KwAes128;
    use base64::engine::general_purpose::STANDARD;
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
    use rsa::{Oaep, RsaPublicKey};
    use sha1::Sha1;
    use sha2::{Sha256, Sha384};

    use super::*;
    use crate::xmlenc::{CipherData, EncryptionMethod};

    struct RecipientKeyResolver {
        recipient: &'static str,
        key: Vec<u8>,
    }

    struct CountingResolver {
        candidate_calls: Cell<usize>,
        key: Vec<u8>,
    }

    struct AllCallsResolver {
        calls: Cell<usize>,
        key: Vec<u8>,
    }

    struct CandidateResolver {
        keys: Vec<Vec<u8>>,
    }

    #[test]
    fn policy_unaware_recipient_resolver_is_not_dispatched() {
        // An already-recovered AES key cannot prove that its RSA source met
        // the operation's minimum. Reject the legacy recipient path before
        // lookup, while keeping direct symmetric resolution available.
        struct LegacyRecipient {
            recipient_calls: Cell<usize>,
            key: Vec<u8>,
        }
        impl DecryptionKeyResolver for LegacyRecipient {
            fn resolve_key(
                &self,
                _provider: &dyn crate::provider::CryptoProvider,
                _algorithm: DataEncryptionAlgorithm,
                encrypted_key: Option<&EncryptedKey>,
            ) -> Result<Vec<u8>, XmlEncError> {
                if encrypted_key.is_none() {
                    return Err(XmlEncError::KeyNotFound);
                }
                self.recipient_calls.set(self.recipient_calls.get() + 1);
                Ok(self.key.clone())
            }
        }
        let resolver = LegacyRecipient {
            recipient_calls: Cell::new(0),
            key: vec![0x63; 16],
        };
        let encrypted = encrypted_data_with_recipients(
            &resolver.key,
            vec![associated_encrypted_key("recipient", None, None)],
            None,
        );
        assert!(matches!(
            DecryptContext::new(&resolver).decrypt_data(&encrypted),
            Err(XmlEncError::KeyNotFound)
        ));
        assert_eq!(resolver.recipient_calls.get(), 0);

        let direct = SymmetricKeyDecryptor::new(resolver.key.clone());
        let mut budget = KeyCandidateBudget::with_limit(1);
        assert!(matches!(
            resolver.resolve_key_candidates_with_policy(
                crate::provider::default_provider(),
                DataEncryptionAlgorithm::Aes128Gcm,
                encrypted.encrypted_keys.first(),
                &crate::policy::DecryptionPolicy::default(),
                &mut budget,
            ),
            Err(XmlEncError::KeyNotFound)
        ));
        assert_eq!(budget.remaining(), 1, "no recipient work was performed");
        assert_eq!(
            DecryptContext::new(&direct)
                .decrypt_data(&encrypted)
                .expect("direct AES does not require RSA metadata"),
            DecryptedContent::Bytes(b"payload".to_vec())
        );
    }

    #[test]
    fn document_decryption_initial_parse_uses_the_policy_work_budget() {
        // Candidate retries and replacement validation must inherit the same
        // allowance consumed by the caller document's initial parse.
        let xml = "<root/>";
        let policy = crate::policy::DecryptionPolicy {
            resources: crate::policy::ResourcePolicy {
                max_xml_parse_work_bytes: 0,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::DecryptionPolicy::default()
        };
        let resolver = SymmetricKeyDecryptor::new([0_u8; 16]);

        let error = DecryptContext::new(&resolver)
            .policy(policy)
            .decrypt_document(xml, None)
            .expect_err("a zero parse-work budget must reject the input parse");

        assert!(matches!(
            error,
            XmlEncError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_PARSE_WORK_BYTES,
                maximum: 0,
                actual,
            }) if actual == xml.len()
        ));
    }

    struct AggregateRecipientResolver {
        attempts: Cell<usize>,
        key: Vec<u8>,
    }

    struct AssociationRecordingResolver {
        visited: RefCell<Vec<String>>,
        key: Vec<u8>,
    }

    struct OrderedRecipientResolver {
        wrong: Vec<u8>,
        correct: Vec<u8>,
    }

    struct DirectAndRecipientResolver {
        direct: Vec<u8>,
        recipient: Vec<u8>,
    }

    struct FailingDirectResolver {
        recipient: Vec<u8>,
    }

    struct PolicyRejectingDirectResolver {
        recipient: Vec<u8>,
    }

    struct MislabelledExhaustionResolver {
        direct: Vec<u8>,
    }

    impl DecryptionKeyResolver for DirectAndRecipientResolver {
        fn resolve_key_candidates_with_policy(
            &self,
            provider: &dyn crate::provider::CryptoProvider,
            algorithm: DataEncryptionAlgorithm,
            encrypted_key: Option<&EncryptedKey>,
            policy: &crate::policy::DecryptionPolicy,
            budget: &mut KeyCandidateBudget,
        ) -> Result<Vec<Vec<u8>>, XmlEncError> {
            // Prepared test keys simulate source ordering, not RSA recovery.
            policy.validate()?;
            self.resolve_key_candidates(provider, algorithm, encrypted_key, budget)
        }

        fn resolve_key(
            &self,
            _provider: &dyn crate::provider::CryptoProvider,
            _algorithm: DataEncryptionAlgorithm,
            encrypted_key: Option<&EncryptedKey>,
        ) -> Result<Vec<u8>, XmlEncError> {
            Ok(if encrypted_key.is_some() {
                self.recipient.clone()
            } else {
                self.direct.clone()
            })
        }
    }

    impl DecryptionKeyResolver for FailingDirectResolver {
        fn resolve_key_candidates_with_policy(
            &self,
            provider: &dyn crate::provider::CryptoProvider,
            algorithm: DataEncryptionAlgorithm,
            encrypted_key: Option<&EncryptedKey>,
            policy: &crate::policy::DecryptionPolicy,
            budget: &mut KeyCandidateBudget,
        ) -> Result<Vec<Vec<u8>>, XmlEncError> {
            // Prepared test keys simulate lookup errors, not RSA recovery.
            policy.validate()?;
            self.resolve_key_candidates(provider, algorithm, encrypted_key, budget)
        }

        fn resolve_key(
            &self,
            _provider: &dyn crate::provider::CryptoProvider,
            algorithm: DataEncryptionAlgorithm,
            encrypted_key: Option<&EncryptedKey>,
        ) -> Result<Vec<u8>, XmlEncError> {
            if encrypted_key.is_some() {
                Ok(self.recipient.clone())
            } else {
                Err(XmlEncError::InvalidKeySize {
                    algorithm,
                    expected: 16,
                    actual: 8,
                })
            }
        }
    }

    impl DecryptionKeyResolver for PolicyRejectingDirectResolver {
        fn resolve_key(
            &self,
            _provider: &dyn crate::provider::CryptoProvider,
            _algorithm: DataEncryptionAlgorithm,
            encrypted_key: Option<&EncryptedKey>,
        ) -> Result<Vec<u8>, XmlEncError> {
            if encrypted_key.is_some() {
                Ok(self.recipient.clone())
            } else {
                Err(crate::policy::PolicyViolation::KeyTrust {
                    reason: "test resolver rejected the operation",
                }
                .into())
            }
        }
    }

    impl DecryptionKeyResolver for MislabelledExhaustionResolver {
        fn resolve_key(
            &self,
            _provider: &dyn crate::provider::CryptoProvider,
            _algorithm: DataEncryptionAlgorithm,
            _encrypted_key: Option<&EncryptedKey>,
        ) -> Result<Vec<u8>, XmlEncError> {
            Err(XmlEncError::KeyNotFound)
        }

        fn resolve_key_candidates_with_policy(
            &self,
            _provider: &dyn crate::provider::CryptoProvider,
            _algorithm: DataEncryptionAlgorithm,
            encrypted_key: Option<&EncryptedKey>,
            policy: &crate::policy::DecryptionPolicy,
            budget: &mut KeyCandidateBudget,
        ) -> Result<Vec<Vec<u8>>, XmlEncError> {
            // Prepared test keys exercise operation-wide candidate accounting.
            policy.validate()?;
            if encrypted_key.is_none() {
                budget.consume(1)?;
                return Ok(vec![self.direct.clone()]);
            }
            budget.consume(budget.remaining().saturating_add(1))?;
            unreachable!("candidate budget exhaustion must return first")
        }
    }

    impl DecryptionKeyResolver for OrderedRecipientResolver {
        fn resolve_key(
            &self,
            _provider: &dyn crate::provider::CryptoProvider,
            _algorithm: DataEncryptionAlgorithm,
            _encrypted_key: Option<&EncryptedKey>,
        ) -> Result<Vec<u8>, XmlEncError> {
            Err(XmlEncError::KeyNotFound)
        }

        fn resolve_key_candidates_with_policy(
            &self,
            _provider: &dyn crate::provider::CryptoProvider,
            _algorithm: DataEncryptionAlgorithm,
            encrypted_key: Option<&EncryptedKey>,
            policy: &crate::policy::DecryptionPolicy,
            budget: &mut KeyCandidateBudget,
        ) -> Result<Vec<Vec<u8>>, XmlEncError> {
            // Prepared test keys simulate authenticated candidate ordering.
            policy.validate()?;
            budget.consume(1)?;
            match encrypted_key.and_then(|key| key.id.as_deref()) {
                Some("first") => Ok(vec![self.wrong.clone()]),
                Some("second") => Ok(vec![self.correct.clone()]),
                _ => Err(XmlEncError::KeyNotFound),
            }
        }
    }

    impl DecryptionKeyResolver for CandidateResolver {
        fn resolve_key(
            &self,
            _provider: &dyn crate::provider::CryptoProvider,
            _algorithm: DataEncryptionAlgorithm,
            _encrypted_key: Option<&EncryptedKey>,
        ) -> Result<Vec<u8>, XmlEncError> {
            Err(XmlEncError::KeyNotFound)
        }

        fn resolve_key_candidates(
            &self,
            _provider: &dyn crate::provider::CryptoProvider,
            _algorithm: DataEncryptionAlgorithm,
            encrypted_key: Option<&EncryptedKey>,
            budget: &mut KeyCandidateBudget,
        ) -> Result<Vec<Vec<u8>>, XmlEncError> {
            if encrypted_key.is_none() {
                budget.consume(self.keys.len())?;
                Ok(self.keys.clone())
            } else {
                Err(XmlEncError::KeyNotFound)
            }
        }
    }

    impl DecryptionKeyResolver for AggregateRecipientResolver {
        fn resolve_key(
            &self,
            _provider: &dyn crate::provider::CryptoProvider,
            _algorithm: DataEncryptionAlgorithm,
            _encrypted_key: Option<&EncryptedKey>,
        ) -> Result<Vec<u8>, XmlEncError> {
            Err(XmlEncError::KeyNotFound)
        }

        fn resolve_key_candidates_with_policy(
            &self,
            _provider: &dyn crate::provider::CryptoProvider,
            _algorithm: DataEncryptionAlgorithm,
            encrypted_key: Option<&EncryptedKey>,
            policy: &crate::policy::DecryptionPolicy,
            budget: &mut KeyCandidateBudget,
        ) -> Result<Vec<Vec<u8>>, XmlEncError> {
            // Prepared test keys isolate aggregate work from RSA primitives.
            policy.validate()?;
            let encrypted_key = encrypted_key.ok_or(XmlEncError::KeyNotFound)?;
            let attempts = budget.remaining();
            if attempts == 0 {
                budget.consume(1)?;
            }
            budget.consume(attempts)?;
            self.attempts.set(self.attempts.get() + attempts);
            if encrypted_key.id.as_deref() == Some("first") {
                Err(XmlEncError::KeyNotFound)
            } else {
                Ok(vec![self.key.clone()])
            }
        }
    }

    impl DecryptionKeyResolver for AssociationRecordingResolver {
        fn resolve_key(
            &self,
            _provider: &dyn crate::provider::CryptoProvider,
            _algorithm: DataEncryptionAlgorithm,
            _encrypted_key: Option<&EncryptedKey>,
        ) -> Result<Vec<u8>, XmlEncError> {
            Err(XmlEncError::KeyNotFound)
        }

        fn resolve_key_candidates_with_policy(
            &self,
            _provider: &dyn crate::provider::CryptoProvider,
            _algorithm: DataEncryptionAlgorithm,
            encrypted_key: Option<&EncryptedKey>,
            policy: &crate::policy::DecryptionPolicy,
            budget: &mut KeyCandidateBudget,
        ) -> Result<Vec<Vec<u8>>, XmlEncError> {
            // Prepared test keys isolate XMLEnc association selection.
            policy.validate()?;
            let encrypted_key = encrypted_key.ok_or(XmlEncError::KeyNotFound)?;
            budget.consume(1)?;
            self.visited
                .borrow_mut()
                .push(encrypted_key.id.clone().unwrap_or_default());
            Ok(vec![self.key.clone()])
        }
    }

    fn associated_encrypted_key(
        id: &str,
        data_reference: Option<&str>,
        carried_key_name: Option<&str>,
    ) -> EncryptedKey {
        EncryptedKey {
            id: Some(id.into()),
            sources: Default::default(),
            recipient: None,
            key_name: None,
            encryption_method: EncryptionMethod {
                algorithm: KeyTransportAlgorithm::RsaOaep11.uri().into(),
                key_size_bits: None,
                oaep_digest: None,
                mgf_algorithm: None,
                oaep_params: None,
            },
            cipher_data: CipherData::Value {
                value: STANDARD.encode([0_u8; 256]),
            },
            reference_list: data_reference.map(|uri| crate::xmlenc::ReferenceList {
                data_references: vec![uri.into()],
                key_references: Vec::new(),
            }),
            carried_key_name: carried_key_name.map(str::to_owned),
        }
    }

    fn encrypted_data_with_recipients(
        key: &[u8],
        encrypted_keys: Vec<EncryptedKey>,
        key_name: Option<&str>,
    ) -> EncryptedData {
        EncryptedData {
            id: Some("target".into()),
            derived_keys: Vec::new(),
            agreement_methods: Vec::new(),
            encrypted_type: None,
            encryption_method: EncryptionMethod {
                algorithm: DataEncryptionAlgorithm::Aes128Gcm.uri().into(),
                key_size_bits: None,
                oaep_digest: None,
                mgf_algorithm: None,
                oaep_params: None,
            },
            key_name: key_name.map(str::to_owned),
            encrypted_keys,
            cipher_data: CipherData::Value {
                value: STANDARD.encode(
                    crate::provider::default_provider()
                        .encrypt_data(DataEncryptionAlgorithm::Aes128Gcm, key, b"payload")
                        .expect("test encryption must succeed"),
                ),
            },
        }
    }

    #[derive(Debug, Default)]
    struct PermissiveUnwrapProvider {
        decrypt_calls: AtomicUsize,
        unwrap_calls: AtomicUsize,
        recover_calls: AtomicUsize,
        plaintext: Vec<u8>,
        candidate_plaintexts: Vec<Vec<u8>>,
    }

    struct OpaqueRecoveryKey;

    impl crate::provider::KeyRecoveryKey for OpaqueRecoveryKey {
        fn rsa_modulus_bits(&self) -> usize {
            2048
        }
        fn rsa_public_exponent(&self) -> Option<u64> {
            Some(65537)
        }
        fn ciphertext_len(&self) -> usize {
            256
        }

        fn recover_with_provider(
            &self,
            _provider: &dyn crate::provider::CryptoProvider,
            _parameters: &RsaOaepParameters,
            _ciphertext: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            panic!("custom provider must own recovery for its opaque key")
        }
    }

    impl crate::provider::CryptoProvider for PermissiveUnwrapProvider {
        #[cfg(feature = "legacy-algorithms")]
        fn recover_pkcs1v15(
            &self,
            key: &dyn crate::provider::KeyRecoveryKey,
            ciphertext: &[u8],
            key_len: usize,
        ) -> Result<crate::provider::RecoveredContentKey, crate::provider::ProviderError> {
            key.recover_pkcs1v15(self, ciphertext, key_len)
        }
        fn name(&self) -> &'static str {
            "permissive-unwrap-test"
        }

        fn supports(&self, capability: crate::provider::ProviderCapability<'_>) -> bool {
            crate::provider::CryptoProvider::supports(
                &crate::provider::RustCryptoProvider,
                capability,
            )
        }

        fn fill_random(&self, output: &mut [u8]) -> Result<(), crate::provider::ProviderError> {
            crate::provider::CryptoProvider::fill_random(
                &crate::provider::RustCryptoProvider,
                output,
            )
        }

        fn derive_key(
            &self,
            parameters: &crate::provider::KdfParameters<'_>,
            secret: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            crate::provider::RustCryptoProvider.derive_key(parameters, secret)
        }

        #[cfg(feature = "xmldsig")]
        fn digest(
            &self,
            algorithm: crate::xmldsig::DigestAlgorithm,
            data: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            crate::provider::CryptoProvider::digest(
                &crate::provider::RustCryptoProvider,
                algorithm,
                data,
            )
        }

        #[cfg(feature = "xmldsig")]
        fn sign(
            &self,
            key: &dyn crate::xmldsig::SigningKey,
            algorithm: crate::xmldsig::SignatureAlgorithm,
            data: &[u8],
        ) -> Result<Vec<u8>, crate::xmldsig::SigningKeyError> {
            crate::provider::CryptoProvider::sign(
                &crate::provider::RustCryptoProvider,
                key,
                algorithm,
                data,
            )
        }

        #[cfg(feature = "xmldsig")]
        fn verify(
            &self,
            key: &dyn crate::xmldsig::VerifyingKey,
            algorithm: crate::xmldsig::SignatureAlgorithm,
            data: &[u8],
            signature: &[u8],
        ) -> Result<bool, crate::xmldsig::DsigError> {
            crate::provider::CryptoProvider::verify(
                &crate::provider::RustCryptoProvider,
                key,
                algorithm,
                data,
                signature,
            )
        }

        fn encrypt_data(
            &self,
            algorithm: DataEncryptionAlgorithm,
            key: &[u8],
            plaintext: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            crate::provider::CryptoProvider::encrypt_data(
                &crate::provider::RustCryptoProvider,
                algorithm,
                key,
                plaintext,
            )
        }

        fn decrypt_data(
            &self,
            _algorithm: DataEncryptionAlgorithm,
            _key: &[u8],
            _ciphertext: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            let index = self.decrypt_calls.fetch_add(1, Ordering::Relaxed);
            Ok(self
                .candidate_plaintexts
                .get(index)
                .unwrap_or(&self.plaintext)
                .clone())
        }

        fn wrap_key(
            &self,
            algorithm: KeyWrapAlgorithm,
            kek: &[u8],
            key: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            crate::provider::CryptoProvider::wrap_key(
                &crate::provider::RustCryptoProvider,
                algorithm,
                kek,
                key,
            )
        }

        fn unwrap_key(
            &self,
            _algorithm: KeyWrapAlgorithm,
            _kek: &[u8],
            _wrapped: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            self.unwrap_calls.fetch_add(1, Ordering::Relaxed);
            Ok(vec![0_u8; 16])
        }

        fn transport_key(
            &self,
            key: &dyn crate::provider::KeyTransportKey,
            parameters: &RsaOaepParameters,
            plaintext: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            crate::provider::CryptoProvider::transport_key(
                &crate::provider::RustCryptoProvider,
                key,
                parameters,
                plaintext,
            )
        }

        fn recover_key(
            &self,
            _key: &dyn crate::provider::KeyRecoveryKey,
            _parameters: &RsaOaepParameters,
            _ciphertext: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            self.recover_calls.fetch_add(1, Ordering::Relaxed);
            Ok(vec![0_u8; 16])
        }
    }

    impl DecryptionKeyResolver for CountingResolver {
        fn resolve_key_candidates_with_policy(
            &self,
            provider: &dyn crate::provider::CryptoProvider,
            algorithm: DataEncryptionAlgorithm,
            encrypted_key: Option<&EncryptedKey>,
            policy: &crate::policy::DecryptionPolicy,
            budget: &mut KeyCandidateBudget,
        ) -> Result<Vec<Vec<u8>>, XmlEncError> {
            // Prepared test keys isolate validation-before-lookup ordering.
            policy.validate()?;
            self.resolve_key_candidates(provider, algorithm, encrypted_key, budget)
        }

        fn resolve_key(
            &self,
            _provider: &dyn crate::provider::CryptoProvider,
            _algorithm: DataEncryptionAlgorithm,
            encrypted_key: Option<&EncryptedKey>,
        ) -> Result<Vec<u8>, XmlEncError> {
            if encrypted_key.is_some() {
                self.candidate_calls.set(self.candidate_calls.get() + 1);
                Ok(self.key.clone())
            } else {
                Err(XmlEncError::KeyNotFound)
            }
        }
    }

    impl DecryptionKeyResolver for AllCallsResolver {
        fn resolve_key(
            &self,
            _provider: &dyn crate::provider::CryptoProvider,
            _algorithm: DataEncryptionAlgorithm,
            _encrypted_key: Option<&EncryptedKey>,
        ) -> Result<Vec<u8>, XmlEncError> {
            self.calls.set(self.calls.get() + 1);
            Ok(self.key.clone())
        }
    }

    impl DecryptionKeyResolver for RecipientKeyResolver {
        fn resolve_key_candidates_with_policy(
            &self,
            provider: &dyn crate::provider::CryptoProvider,
            algorithm: DataEncryptionAlgorithm,
            encrypted_key: Option<&EncryptedKey>,
            policy: &crate::policy::DecryptionPolicy,
            budget: &mut KeyCandidateBudget,
        ) -> Result<Vec<Vec<u8>>, XmlEncError> {
            // Prepared test keys simulate recipient labels, not RSA recovery.
            policy.validate()?;
            self.resolve_key_candidates(provider, algorithm, encrypted_key, budget)
        }

        fn resolve_key(
            &self,
            _provider: &dyn crate::provider::CryptoProvider,
            _algorithm: DataEncryptionAlgorithm,
            encrypted_key: Option<&EncryptedKey>,
        ) -> Result<Vec<u8>, XmlEncError> {
            if encrypted_key.and_then(|key| key.recipient.as_deref()) == Some(self.recipient) {
                Ok(self.key.clone())
            } else {
                Err(XmlEncError::KeyNotFound)
            }
        }
    }

    #[test]
    fn decrypts_gcm_and_rejects_tampering() {
        // Authentication must cover the complete ciphertext and tag before plaintext returns.
        let key = [7_u8; 16];
        let nonce = [9_u8; 12];
        let mut ciphertext = b"<Assertion>trusted</Assertion>".to_vec();
        Aes128Gcm::new_from_slice(&key)
            .expect("fixed key length")
            .encrypt_in_place(&nonce.into(), b"", &mut ciphertext)
            .expect("test encryption must succeed");
        let mut wire = nonce.to_vec();
        wire.extend_from_slice(&ciphertext);
        let xml = format!(
            "<xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"/><xenc:CipherData><xenc:CipherValue>{}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>",
            STANDARD.encode(&wire)
        );
        let decrypted = decrypt(&xml, &SymmetricKeyDecryptor::new(key))
            .expect("valid AES-GCM XML must decrypt");
        assert_eq!(
            decrypted,
            DecryptedContent::Xml("<Assertion>trusted</Assertion>".into())
        );
        let last = wire.len() - 1;
        wire[last] ^= 1;
        let tampered = xml.replace(&STANDARD.encode(ciphertext), &STANDARD.encode(&wire[12..]));
        assert!(matches!(
            decrypt(&tampered, &SymmetricKeyDecryptor::new(key)),
            Err(XmlEncError::AeadAuthenticationFailed)
        ));
    }

    #[test]
    fn candidate_keys_retry_only_authenticated_decryption() {
        // Candidate selection belongs inside one prepared decryption operation:
        // structural validation and ciphertext decoding must not be repeated.
        let key = [7_u8; 16];
        let nonce = [9_u8; 12];
        let mut ciphertext = b"candidate plaintext".to_vec();
        Aes128Gcm::new_from_slice(&key)
            .expect("fixed key length")
            .encrypt_in_place(&nonce.into(), b"", &mut ciphertext)
            .expect("test encryption must succeed");
        let mut wire = nonce.to_vec();
        wire.extend_from_slice(&ciphertext);
        let encrypted = EncryptedData {
            id: None,
            derived_keys: Vec::new(),
            agreement_methods: Vec::new(),
            encrypted_type: None,
            encryption_method: EncryptionMethod {
                algorithm: DataEncryptionAlgorithm::Aes128Gcm.uri().into(),
                key_size_bits: None,
                oaep_digest: None,
                mgf_algorithm: None,
                oaep_params: None,
            },
            key_name: None,
            encrypted_keys: Vec::new(),
            cipher_data: CipherData::Value {
                value: STANDARD.encode(wire),
            },
        };
        let resolver = CandidateResolver {
            keys: vec![vec![1_u8; 16], key.to_vec()],
        };

        let decrypted = DecryptContext::new(&resolver)
            .decrypt_data(&encrypted)
            .expect("a later authenticated candidate must decrypt");

        assert_eq!(
            decrypted,
            DecryptedContent::Bytes(b"candidate plaintext".to_vec())
        );
    }

    #[test]
    fn standalone_decryption_stops_after_first_successful_candidate() {
        // A successful authenticated candidate is the final standalone result;
        // later keys must not cause redundant decryptions or retained plaintexts.
        let provider = PermissiveUnwrapProvider {
            plaintext: b"accepted".to_vec(),
            ..PermissiveUnwrapProvider::default()
        };
        let resolver = CandidateResolver {
            keys: vec![vec![1_u8; 16], vec![2_u8; 16], vec![3_u8; 16]],
        };
        let encrypted = EncryptedData {
            id: None,
            derived_keys: Vec::new(),
            agreement_methods: Vec::new(),
            encrypted_type: None,
            encryption_method: EncryptionMethod {
                algorithm: DataEncryptionAlgorithm::Aes128Gcm.uri().into(),
                key_size_bits: None,
                oaep_digest: None,
                mgf_algorithm: None,
                oaep_params: None,
            },
            key_name: None,
            encrypted_keys: Vec::new(),
            cipher_data: CipherData::Value {
                value: STANDARD.encode([0_u8; 36]),
            },
        };

        let result = DecryptContext::new(&resolver)
            .provider(&provider)
            .decrypt_data(&encrypted)
            .expect("the first successful candidate must be returned");

        assert_eq!(result, DecryptedContent::Bytes(b"accepted".to_vec()));
        assert_eq!(provider.decrypt_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn document_decryption_discards_rejected_plaintext_before_next_candidate() {
        // Replacement validation may reject authenticated plaintext. The next
        // key is then tried, but candidates after the first valid XML stay unused.
        let provider = PermissiveUnwrapProvider {
            candidate_plaintexts: vec![b"<bad".to_vec(), b"<x/>".to_vec(), b"<u/>".to_vec()],
            ..PermissiveUnwrapProvider::default()
        };
        let resolver = CandidateResolver {
            keys: vec![vec![1_u8; 16], vec![2_u8; 16], vec![3_u8; 16]],
        };
        let encrypted = format!(
            "<xenc:EncryptedData xmlns:xenc=\"{XMLENC_NS}\" Type=\"{XMLENC_NS}Element\"><xenc:EncryptionMethod Algorithm=\"{}\"/><xenc:CipherData><xenc:CipherValue>{}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>",
            DataEncryptionAlgorithm::Aes128Gcm.uri(),
            STANDARD.encode([0_u8; 32]),
        );

        let result = DecryptContext::new(&resolver)
            .provider(&provider)
            .decrypt_document(&encrypted, None)
            .expect("a later candidate with valid replacement XML must succeed");

        assert_eq!(result, "<x/>");
        assert_eq!(provider.decrypt_calls.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn cbc_rejects_multiple_unordered_key_candidates() {
        // CBC padding cannot authenticate which candidate key is correct. A
        // resolver must select one key from trusted metadata before decryption.
        let encrypted = EncryptedData {
            id: None,
            derived_keys: Vec::new(),
            agreement_methods: Vec::new(),
            encrypted_type: None,
            encryption_method: EncryptionMethod {
                algorithm: DataEncryptionAlgorithm::Aes128Cbc.uri().into(),
                key_size_bits: None,
                oaep_digest: None,
                mgf_algorithm: None,
                oaep_params: None,
            },
            key_name: None,
            encrypted_keys: Vec::new(),
            cipher_data: CipherData::Value {
                value: STANDARD.encode(
                    crate::provider::default_provider()
                        .encrypt_data(
                            DataEncryptionAlgorithm::Aes128Cbc,
                            &[7_u8; 16],
                            b"opaque plaintext",
                        )
                        .expect("test encryption must succeed"),
                ),
            },
        };
        let resolver = CandidateResolver {
            keys: vec![vec![1_u8; 16], vec![7_u8; 16]],
        };

        let error = DecryptContext::new(&resolver)
            .decrypt_data(&encrypted)
            .expect_err("unauthenticated CBC must not guess among candidate keys");

        assert!(matches!(
            error,
            XmlEncError::AmbiguousKeyCandidates {
                algorithm: DataEncryptionAlgorithm::Aes128Cbc,
                actual: 2,
            }
        ));
    }

    #[test]
    fn cbc_accepts_duplicate_copies_of_one_key_identity() {
        // Repeated sources containing the same key do not create the ambiguity
        // that unauthenticated CBC must reject between distinct key identities.
        let key = vec![0x27_u8; 16];
        let encrypted = EncryptedData {
            id: None,
            derived_keys: Vec::new(),
            agreement_methods: Vec::new(),
            encrypted_type: None,
            encryption_method: EncryptionMethod {
                algorithm: DataEncryptionAlgorithm::Aes128Cbc.uri().into(),
                key_size_bits: None,
                oaep_digest: None,
                mgf_algorithm: None,
                oaep_params: None,
            },
            key_name: None,
            encrypted_keys: Vec::new(),
            cipher_data: CipherData::Value {
                value: STANDARD.encode(
                    crate::provider::default_provider()
                        .encrypt_data(
                            DataEncryptionAlgorithm::Aes128Cbc,
                            &key,
                            b"duplicate identity",
                        )
                        .expect("test encryption must succeed"),
                ),
            },
        };
        let resolver = CandidateResolver {
            keys: vec![key.clone(), key],
        };

        assert_eq!(
            DecryptContext::new(&resolver)
                .decrypt_data(&encrypted)
                .expect("one distinct CBC key identity must decrypt"),
            DecryptedContent::Bytes(b"duplicate identity".to_vec())
        );
    }

    #[test]
    fn candidate_keys_are_bounded_before_cryptographic_processing() {
        // A resolver is caller-controlled; its result cannot multiply one
        // prepared operation beyond the implementation safety ceiling.
        let encrypted = EncryptedData {
            id: None,
            derived_keys: Vec::new(),
            agreement_methods: Vec::new(),
            encrypted_type: None,
            encryption_method: EncryptionMethod {
                algorithm: DataEncryptionAlgorithm::Aes128Gcm.uri().into(),
                key_size_bits: None,
                oaep_digest: None,
                mgf_algorithm: None,
                oaep_params: None,
            },
            key_name: None,
            encrypted_keys: Vec::new(),
            cipher_data: CipherData::Value {
                value: STANDARD.encode(vec![0_u8; 28]),
            },
        };
        let actual = crate::hard_limits::KEY_CANDIDATE_CEILING + 1;
        let resolver = CandidateResolver {
            keys: vec![vec![0_u8; 16]; actual],
        };

        let error = DecryptContext::new(&resolver)
            .decrypt_data(&encrypted)
            .expect_err("oversized candidate sets must fail before decryption");

        assert!(matches!(
            error,
            XmlEncError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::KEY_CANDIDATES,
                maximum: crate::hard_limits::KEY_CANDIDATE_CEILING,
                actual: observed,
            }) if observed == actual
        ));
    }

    #[test]
    fn operation_policy_controls_candidate_budget() {
        // A deployment-selected ceiling must reach resolver accounting; the
        // hard implementation ceiling is not the effective runtime policy.
        let encrypted = EncryptedData {
            id: None,
            derived_keys: Vec::new(),
            agreement_methods: Vec::new(),
            encrypted_type: None,
            encryption_method: EncryptionMethod {
                algorithm: DataEncryptionAlgorithm::Aes128Gcm.uri().into(),
                key_size_bits: None,
                oaep_digest: None,
                mgf_algorithm: None,
                oaep_params: None,
            },
            key_name: None,
            encrypted_keys: Vec::new(),
            cipher_data: CipherData::Value {
                value: STANDARD.encode(vec![0_u8; 28]),
            },
        };
        let resolver = CandidateResolver {
            keys: vec![vec![0_u8; 16]; 3],
        };
        let mut policy = crate::policy::DecryptionPolicy::default();
        policy.resources.max_key_candidates = 2;

        let error = DecryptContext::new(&resolver)
            .policy(policy)
            .decrypt_data(&encrypted)
            .expect_err("candidate accounting must use the operation policy ceiling");

        assert!(matches!(
            error,
            XmlEncError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::KEY_CANDIDATES,
                maximum: 2,
                actual: 3,
            })
        ));
    }

    #[test]
    fn candidate_work_ceiling_is_shared_across_recipients() {
        // The candidate ceiling bounds the complete decryption operation, not
        // each EncryptedKey independently.
        let key = vec![0x39_u8; 16];
        let resolver = AggregateRecipientResolver {
            attempts: Cell::new(0),
            key: key.clone(),
        };
        let encrypted = encrypted_data_with_recipients(
            &key,
            vec![
                associated_encrypted_key("first", None, None),
                associated_encrypted_key("second", None, None),
            ],
            None,
        );

        DecryptContext::new(&resolver)
            .decrypt_data(&encrypted)
            .expect_err("a second recipient must not receive a fresh candidate allowance");
        assert_eq!(
            resolver.attempts.get(),
            crate::hard_limits::KEY_CANDIDATE_CEILING
        );
    }

    #[test]
    fn candidate_budget_exhaustion_is_fatal_after_a_key_was_found() {
        // Candidate exhaustion must remain terminal even when it occurs in a
        // resolver path dedicated to one particular key family.
        let key = vec![0x49_u8; 16];
        let resolver = MislabelledExhaustionResolver {
            direct: key.clone(),
        };
        let encrypted = encrypted_data_with_recipients(
            &key,
            vec![associated_encrypted_key("recipient", None, None)],
            None,
        );

        let error = DecryptContext::new(&resolver)
            .decrypt_data(&encrypted)
            .expect_err("candidate exhaustion must override an earlier usable key");

        assert!(matches!(
            error,
            XmlEncError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: "key candidates",
                maximum: crate::hard_limits::KEY_CANDIDATE_CEILING,
                actual,
            }) if actual == crate::hard_limits::KEY_CANDIDATE_CEILING + 1
        ));
    }

    #[test]
    fn authenticated_decryption_continues_after_wrong_unwrapped_recipient_key() {
        // A same-width key can unwrap successfully yet fail GCM authentication;
        // later applicable recipients must remain available to the data cipher.
        let correct = vec![0x53_u8; 16];
        let encrypted = encrypted_data_with_recipients(
            &correct,
            vec![
                associated_encrypted_key("first", None, None),
                associated_encrypted_key("second", None, None),
            ],
            None,
        );
        let resolver = OrderedRecipientResolver {
            wrong: vec![0x11_u8; 16],
            correct,
        };

        let plaintext = DecryptContext::new(&resolver)
            .decrypt_data(&encrypted)
            .expect("the second recipient key must authenticate");
        assert_eq!(plaintext, DecryptedContent::Bytes(b"payload".to_vec()));
    }

    #[test]
    fn authenticated_decryption_continues_from_direct_key_to_recipient() {
        // Direct candidates and embedded recipients are one ordered lookup
        // space; a wrong direct GCM key must not hide a valid wrapped key.
        let correct = vec![0x63_u8; 16];
        let encrypted = encrypted_data_with_recipients(
            &correct,
            vec![associated_encrypted_key("recipient", None, None)],
            None,
        );
        let resolver = DirectAndRecipientResolver {
            direct: vec![0x19_u8; 16],
            recipient: correct,
        };

        let plaintext = DecryptContext::new(&resolver)
            .decrypt_data(&encrypted)
            .expect("the embedded recipient must remain available after a direct candidate");

        assert_eq!(plaintext, DecryptedContent::Bytes(b"payload".to_vec()));
    }

    #[test]
    fn authenticated_decryption_continues_after_direct_lookup_error() {
        // A candidate-local direct lookup failure must not suppress a valid
        // embedded recipient from the same ordered key-resolution operation.
        let correct = vec![0x64_u8; 16];
        let encrypted = encrypted_data_with_recipients(
            &correct,
            vec![associated_encrypted_key("recipient", None, None)],
            None,
        );
        let resolver = FailingDirectResolver { recipient: correct };

        let plaintext = DecryptContext::new(&resolver)
            .decrypt_data(&encrypted)
            .expect("recipient lookup must follow a candidate-local direct error");

        assert_eq!(plaintext, DecryptedContent::Bytes(b"payload".to_vec()));
    }

    #[test]
    fn resolver_policy_rejection_stops_before_later_recipient() {
        // A custom resolver's typed policy rejection is operation-wide; trying
        // a later recipient after it would allow key-source policy bypass.
        let correct = vec![0x65_u8; 16];
        let encrypted = encrypted_data_with_recipients(
            &correct,
            vec![associated_encrypted_key("recipient", None, None)],
            None,
        );
        let resolver = PolicyRejectingDirectResolver { recipient: correct };

        let error = DecryptContext::new(&resolver)
            .decrypt_data(&encrypted)
            .expect_err("operation policy rejection must be fatal");

        assert!(matches!(
            error,
            XmlEncError::Policy(crate::policy::PolicyViolation::KeyTrust {
                reason: "test resolver rejected the operation",
            })
        ));
    }

    #[test]
    fn cbc_rejects_distinct_direct_and_recipient_candidates() {
        // Combining lookup sources must not make unauthenticated CBC choose the
        // direct key merely because it was resolved before the recipient key.
        let recipient = vec![0x73_u8; 16];
        let mut encrypted = encrypted_data_with_recipients(
            &recipient,
            vec![associated_encrypted_key("recipient", None, None)],
            None,
        );
        encrypted.encryption_method.algorithm = DataEncryptionAlgorithm::Aes128Cbc.uri().into();
        *encrypted
            .cipher_data
            .inline_value_mut()
            .expect("inline ciphertext") = STANDARD.encode(
            crate::provider::default_provider()
                .encrypt_data(DataEncryptionAlgorithm::Aes128Cbc, &recipient, b"payload")
                .expect("test encryption must succeed"),
        );
        let resolver = DirectAndRecipientResolver {
            direct: vec![0x29_u8; 16],
            recipient,
        };

        let error = DecryptContext::new(&resolver)
            .decrypt_data(&encrypted)
            .expect_err("CBC must not guess between direct and recipient keys");

        assert!(matches!(
            error,
            XmlEncError::AmbiguousKeyCandidates {
                algorithm: DataEncryptionAlgorithm::Aes128Cbc,
                actual: 2,
            }
        ));
    }

    #[test]
    fn cbc_ambiguity_ignores_algorithm_incompatible_key_widths() {
        // A wrong-width key cannot reach AES-CBC and therefore cannot make one
        // width-compatible candidate ambiguous.
        let key = vec![0x47_u8; 16];
        let ciphertext = crate::provider::default_provider()
            .encrypt_data(DataEncryptionAlgorithm::Aes128Cbc, &key, b"payload")
            .expect("test encryption must succeed");
        let encrypted = EncryptedData {
            id: None,
            derived_keys: Vec::new(),
            agreement_methods: Vec::new(),
            encrypted_type: None,
            encryption_method: EncryptionMethod {
                algorithm: DataEncryptionAlgorithm::Aes128Cbc.uri().into(),
                key_size_bits: None,
                oaep_digest: None,
                mgf_algorithm: None,
                oaep_params: None,
            },
            key_name: None,
            encrypted_keys: Vec::new(),
            cipher_data: CipherData::Value {
                value: STANDARD.encode(ciphertext),
            },
        };
        let resolver = CandidateResolver {
            keys: vec![vec![0_u8; 32], key],
        };

        assert_eq!(
            DecryptContext::new(&resolver)
                .decrypt_data(&encrypted)
                .expect("the sole width-compatible CBC key must be selected"),
            DecryptedContent::Bytes(b"payload".to_vec())
        );
    }

    #[test]
    fn data_reference_selects_the_associated_encrypted_key() {
        // An explicit DataReference to another object contradicts this
        // EncryptedData even when that recipient can be unwrapped.
        let key = vec![0x51_u8; 16];
        let resolver = AssociationRecordingResolver {
            visited: RefCell::new(Vec::new()),
            key: key.clone(),
        };
        let encrypted = encrypted_data_with_recipients(
            &key,
            vec![
                associated_encrypted_key("unrelated", Some("#other"), None),
                associated_encrypted_key("matching", Some("#target"), None),
            ],
            None,
        );

        DecryptContext::new(&resolver)
            .decrypt_data(&encrypted)
            .expect("the associated recipient must decrypt");
        assert_eq!(resolver.visited.into_inner(), ["matching"]);
    }

    #[test]
    fn carried_key_name_selects_the_named_content_key() {
        // CarriedKeyName identifies the transported key named by the enclosing
        // EncryptedData KeyInfo; a contradictory label must be skipped.
        let key = vec![0x52_u8; 16];
        let resolver = AssociationRecordingResolver {
            visited: RefCell::new(Vec::new()),
            key: key.clone(),
        };
        let encrypted = encrypted_data_with_recipients(
            &key,
            vec![
                associated_encrypted_key("unrelated", None, Some("other")),
                associated_encrypted_key("matching", None, Some("wanted")),
            ],
            Some("wanted"),
        );

        DecryptContext::new(&resolver)
            .decrypt_data(&encrypted)
            .expect("the matching carried key name must decrypt");
        assert_eq!(resolver.visited.into_inner(), ["matching"]);
    }

    #[test]
    fn contradictory_encrypted_key_associations_fail_closed() {
        // Association metadata is authoritative when present. The resolver must
        // not see a recipient that explicitly names another encrypted object.
        let key = vec![0x53_u8; 16];
        let resolver = AssociationRecordingResolver {
            visited: RefCell::new(Vec::new()),
            key: key.clone(),
        };
        let encrypted = encrypted_data_with_recipients(
            &key,
            vec![associated_encrypted_key("unrelated", Some("#other"), None)],
            None,
        );

        assert!(matches!(
            DecryptContext::new(&resolver).decrypt_data(&encrypted),
            Err(XmlEncError::KeyNotFound)
        ));
        assert!(resolver.visited.into_inner().is_empty());
    }

    #[test]
    fn direct_symmetric_key_ignores_embedded_key_hints() {
        // A caller-supplied content key is authoritative for this resolver;
        // unrelated recipient hints must not disable direct-key decryption.
        let key = [0x28_u8; 16];
        let unrelated = EncryptedKey {
            sources: Default::default(),
            id: None,
            recipient: Some("other-recipient".into()),
            key_name: None,
            encryption_method: super::super::EncryptionMethod {
                algorithm: "urn:unrelated:key-transport".into(),
                key_size_bits: None,
                oaep_digest: None,
                mgf_algorithm: None,
                oaep_params: None,
            },
            cipher_data: super::super::CipherData::Value {
                value: STANDARD.encode([0_u8; 24]),
            },
            reference_list: None,
            carried_key_name: None,
        };

        assert_eq!(
            SymmetricKeyDecryptor::new(key)
                .resolve_key(
                    crate::provider::default_provider(),
                    DataEncryptionAlgorithm::Aes128Gcm,
                    Some(&unrelated)
                )
                .expect("direct key must ignore unrelated embedded hints"),
            key
        );
    }

    #[test]
    fn decrypts_with_the_matching_recipient_key() {
        // Multi-recipient KeyInfo must retain document order and continue after a
        // malformed unrelated key before accepting the intended one.
        let key = [0x29_u8; 16];
        let plaintext = "recipient-specific plaintext";
        let encrypted = encrypted_gcm_element("", plaintext, None, true, &key);
        let recipient_key = |recipient: &str, method: &str| {
            format!(
                "<xenc:EncryptedKey Recipient=\"{recipient}\"><xenc:EncryptionMethod Algorithm=\"{method}\">{}</xenc:EncryptionMethod><xenc:CipherData><xenc:CipherValue>YQ==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>",
                if recipient == "alice" {
                    "<ds:DigestMethod Algorithm=\"urn:unsupported:digest\"/>"
                } else {
                    ""
                }
            )
        };
        let key_info = format!(
            "<ds:KeyInfo xmlns:ds=\"{}\">{}{}</ds:KeyInfo>",
            crate::xmlenc::types::XMLDSIG_NS,
            recipient_key("alice", KeyTransportAlgorithm::RsaOaep11.uri()),
            recipient_key("bob", KeyWrapAlgorithm::AesKw128.uri())
        );
        let xml = encrypted.replacen(
            "<xenc:CipherData>",
            &format!("{key_info}<xenc:CipherData>"),
            1,
        );
        let resolver = RecipientKeyResolver {
            recipient: "bob",
            key: key.to_vec(),
        };

        assert_eq!(
            decrypt(&xml, &resolver).expect("second recipient key must be tried"),
            DecryptedContent::Bytes(plaintext.as_bytes().to_vec())
        );
    }

    #[test]
    fn decryption_policy_bounds_recipients_before_key_resolution() {
        // Both XML parsing and caller-constructed typed input must reject an
        // oversized recipient set before any resolver can inspect candidates.
        let key = [0x29_u8; 16];
        let encrypted = encrypted_gcm_element("", "bounded recipients", None, true, &key);
        let recipient_key = |recipient: &str| {
            format!(
                "<xenc:EncryptedKey Recipient=\"{recipient}\"><xenc:EncryptionMethod Algorithm=\"urn:test:key\"/><xenc:CipherData><xenc:CipherValue>YQ==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>"
            )
        };
        let key_info = format!(
            "<ds:KeyInfo xmlns:ds=\"{}\">{}{}</ds:KeyInfo>",
            crate::xmlenc::types::XMLDSIG_NS,
            recipient_key("alice"),
            recipient_key("bob")
        );
        let xml = encrypted.replacen(
            "<xenc:CipherData>",
            &format!("{key_info}<xenc:CipherData>"),
            1,
        );
        let parsed = parse_encrypted_data(&xml).expect("default parser accepts two recipients");
        let policy = crate::policy::DecryptionPolicy {
            resources: crate::policy::ResourcePolicy {
                max_encryption_recipients: 1,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::DecryptionPolicy::default()
        };
        let resolver = SymmetricKeyDecryptor::new(key);
        let context = DecryptContext::new(&resolver).policy(policy);

        for error in [
            context
                .decrypt(&xml)
                .expect_err("XML recipient collection must be bounded"),
            context
                .decrypt_data(&parsed)
                .expect_err("typed recipient collection must be bounded"),
        ] {
            assert!(matches!(
                error,
                XmlEncError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::ENCRYPTION_RECIPIENTS,
                    maximum: 1,
                    actual: 2,
                })
            ));
        }
    }

    #[test]
    fn decrypts_session_key_wrapped_with_aes_kw() {
        // RFC 3394 unwrap must recover exactly the content algorithm's key length.
        let kek = [3_u8; 16];
        let session_key = [4_u8; 16];
        let mut wrapped = [0_u8; 24];
        KwAes128::new_from_slice(&kek)
            .expect("fixed KEK length")
            .wrap_key(&session_key, &mut wrapped)
            .expect("RFC 3394 test wrapping must succeed");
        let encrypted_key = EncryptedKey {
            id: None,
            sources: Default::default(),
            recipient: None,
            key_name: None,
            encryption_method: super::super::EncryptionMethod {
                algorithm: "http://www.w3.org/2001/04/xmlenc#kw-aes128".into(),
                key_size_bits: None,
                oaep_digest: None,
                mgf_algorithm: None,
                oaep_params: None,
            },
            cipher_data: super::super::CipherData::Value {
                value: STANDARD.encode(wrapped),
            },
            reference_list: None,
            carried_key_name: None,
        };
        let resolved = KekDecryptor::new(kek)
            .resolve_key(
                crate::provider::default_provider(),
                DataEncryptionAlgorithm::Aes128Gcm,
                Some(&encrypted_key),
            )
            .expect("wrapped session key must resolve");
        assert_eq!(resolved, session_key);
    }

    #[test]
    fn rejects_invalid_kek_before_custom_provider_dispatch() {
        // KEK length is part of the XMLEnc algorithm contract, not a provider
        // preference. A permissive provider must not bypass facade validation.
        let encrypted_key = EncryptedKey {
            id: None,
            sources: Default::default(),
            recipient: None,
            key_name: None,
            encryption_method: super::super::EncryptionMethod {
                algorithm: KeyWrapAlgorithm::AesKw128.uri().into(),
                key_size_bits: None,
                oaep_digest: None,
                mgf_algorithm: None,
                oaep_params: None,
            },
            cipher_data: super::super::CipherData::Value {
                value: STANDARD.encode([0_u8; 24]),
            },
            reference_list: None,
            carried_key_name: None,
        };
        let provider = PermissiveUnwrapProvider::default();

        assert!(matches!(
            KekDecryptor::new([0_u8; 32]).resolve_key(
                &provider,
                DataEncryptionAlgorithm::Aes128Gcm,
                Some(&encrypted_key),
            ),
            Err(XmlEncError::InvalidKekSize {
                algorithm: KeyWrapAlgorithm::AesKw128,
                expected: 16,
                actual: 32,
            })
        ));
        assert_eq!(provider.unwrap_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn rejects_content_ciphertext_framing_before_resolution_or_provider_dispatch() {
        // Algorithm framing belongs to the XMLEnc facade. A permissive provider
        // and resolver must never observe malformed standard CipherValue bytes.
        for (algorithm, ciphertext_len) in [
            (DataEncryptionAlgorithm::Aes128Gcm, 27),
            (DataEncryptionAlgorithm::Aes128Cbc, 33),
        ] {
            let resolver = AllCallsResolver {
                calls: Cell::new(0),
                key: vec![0_u8; algorithm.key_len()],
            };
            let provider = PermissiveUnwrapProvider::default();
            let encrypted = EncryptedData {
                id: None,
                derived_keys: Vec::new(),
                agreement_methods: Vec::new(),
                encrypted_type: None,
                key_name: None,
                encryption_method: super::super::EncryptionMethod {
                    algorithm: algorithm.uri().into(),
                    key_size_bits: None,
                    oaep_digest: None,
                    mgf_algorithm: None,
                    oaep_params: None,
                },
                encrypted_keys: Vec::new(),
                cipher_data: super::super::CipherData::Value {
                    value: STANDARD.encode(vec![0_u8; ciphertext_len]),
                },
            };

            assert!(
                DecryptContext::new(&resolver)
                    .provider(&provider)
                    .decrypt_data(&encrypted)
                    .is_err()
            );
            assert_eq!(resolver.calls.get(), 0);
            assert_eq!(provider.decrypt_calls.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn rejects_custom_provider_plaintext_outside_algorithm_bounds() {
        // A provider success result is still untrusted: GCM fixes the plaintext
        // length exactly, while CBC padding permits only one block-sized range.
        for (algorithm, ciphertext_len, plaintext_len) in [
            (DataEncryptionAlgorithm::Aes128Gcm, 32, 5),
            (DataEncryptionAlgorithm::Aes128Cbc, 32, 16),
        ] {
            let resolver = AllCallsResolver {
                calls: Cell::new(0),
                key: vec![0_u8; algorithm.key_len()],
            };
            let provider = PermissiveUnwrapProvider {
                plaintext: vec![0_u8; plaintext_len],
                ..PermissiveUnwrapProvider::default()
            };
            let encrypted = EncryptedData {
                id: None,
                derived_keys: Vec::new(),
                agreement_methods: Vec::new(),
                encrypted_type: None,
                key_name: None,
                encryption_method: super::super::EncryptionMethod {
                    algorithm: algorithm.uri().into(),
                    key_size_bits: None,
                    oaep_digest: None,
                    mgf_algorithm: None,
                    oaep_params: None,
                },
                encrypted_keys: Vec::new(),
                cipher_data: super::super::CipherData::Value {
                    value: STANDARD.encode(vec![0_u8; ciphertext_len]),
                },
            };

            let error = DecryptContext::new(&resolver)
                .provider(&provider)
                .decrypt_data(&encrypted)
                .expect_err("impossible provider output length must fail");
            match algorithm {
                DataEncryptionAlgorithm::Aes128Gcm => assert!(matches!(
                    error,
                    XmlEncError::Provider(crate::provider::ProviderError::InvalidOutputSize {
                        operation: crate::provider::ProviderOperation::Decrypt,
                        expected: 4,
                        actual: 5,
                    })
                )),
                DataEncryptionAlgorithm::Aes128Cbc => assert!(matches!(
                    error,
                    XmlEncError::Provider(crate::provider::ProviderError::InvalidOutputSizeRange {
                        operation: crate::provider::ProviderOperation::Decrypt,
                        minimum: 0,
                        maximum: 15,
                        actual: 16,
                    })
                )),
                _ => unreachable!("the regression table covers one GCM and one CBC algorithm"),
            }
            assert_eq!(provider.decrypt_calls.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn rejects_malformed_aes_kw_before_custom_provider_dispatch() {
        // RFC 3394 adds exactly eight bytes to the transported content key;
        // permissive custom providers must not redefine that wire contract.
        let provider = PermissiveUnwrapProvider::default();
        for actual in [0, 23, 25] {
            let encrypted_key = EncryptedKey {
                sources: Default::default(),
                id: None,
                recipient: None,
                key_name: None,
                encryption_method: super::super::EncryptionMethod {
                    algorithm: KeyWrapAlgorithm::AesKw128.uri().into(),
                    key_size_bits: None,
                    oaep_digest: None,
                    mgf_algorithm: None,
                    oaep_params: None,
                },
                cipher_data: super::super::CipherData::Value {
                    value: STANDARD.encode(vec![0_u8; actual]),
                },
                reference_list: None,
                carried_key_name: None,
            };
            assert!(matches!(
                KekDecryptor::new([0_u8; 16]).resolve_key(
                    &provider,
                    DataEncryptionAlgorithm::Aes128Gcm,
                    Some(&encrypted_key),
                ),
                Err(XmlEncError::InvalidWrappedKeyLength {
                    expected: 24,
                    actual: output_len,
                }) if output_len == actual
            ));
        }
        assert_eq!(provider.unwrap_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn rejects_malformed_rsa_oaep_before_custom_provider_dispatch() {
        // RSA ciphertext width is the private modulus width, so malformed
        // transport bytes must be rejected before provider-owned recovery.
        let private_key = RsaPrivateKey::from_pkcs8_pem(include_str!(
            "../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
        ))
        .expect("RSA donor private key must parse");
        let provider = PermissiveUnwrapProvider::default();
        for actual in [0, 255, 257] {
            assert!(matches!(
                recover_rsa_oaep(
                    &provider,
                    &private_key,
                    &RsaOaepParameters::default(),
                    &vec![0_u8; actual],
                    DataEncryptionAlgorithm::Aes128Gcm,
                ),
                Err(XmlEncError::InvalidWrappedKeyLength {
                    expected: 256,
                    actual: output_len,
                }) if output_len == actual
            ));
        }
        assert_eq!(provider.recover_calls.load(Ordering::Relaxed), 0);
    }

    #[cfg(feature = "legacy-algorithms")]
    #[test]
    fn invalid_rsa_recovery_cannot_release_successful_cbc_plaintext() {
        // Force the CBC provider to accept its padding, making this regression
        // deterministic instead of waiting for random fallback plaintext.
        let key = RsaPrivateKey::from_pkcs8_pem(include_str!(
            "../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
        ))
        .expect("valid RSA fixture");
        let resolver = PrivateKeyDecryptor::new(key);
        for algorithm in [
            DataEncryptionAlgorithm::Aes128Cbc,
            DataEncryptionAlgorithm::Aes192Cbc,
            DataEncryptionAlgorithm::Aes256Cbc,
            DataEncryptionAlgorithm::TripleDesCbc,
            DataEncryptionAlgorithm::Aes128Gcm,
        ] {
            let provider = PermissiveUnwrapProvider {
                plaintext: b"accepted CBC plaintext".to_vec(),
                ..PermissiveUnwrapProvider::default()
            };
            let mut encrypted = encrypted_data_with_recipients(
                &[0; 16],
                vec![associated_encrypted_key("recipient", None, None)],
                None,
            );
            encrypted.encryption_method.algorithm = algorithm.uri().into();
            *encrypted
                .cipher_data
                .inline_value_mut()
                .expect("inline ciphertext") =
                STANDARD.encode(vec![
                    0;
                    algorithm
                        .ciphertext_len_for_plaintext(provider.plaintext.len())
                        .expect("bounded test frame")
                ]);
            encrypted.encrypted_keys[0].encryption_method.algorithm =
                KeyTransportAlgorithm::RsaPkcs1v15.uri().into();
            *encrypted.encrypted_keys[0]
                .cipher_data
                .inline_value_mut()
                .expect("inline wrapped key") = STANDARD.encode([0; 256]);
            let result = DecryptContext::new(&resolver)
                .provider(&provider)
                .policy(crate::policy::DecryptionPolicy {
                    data_algorithms: Some([algorithm].into()),
                    key_transport_algorithms: Some([KeyTransportAlgorithm::RsaPkcs1v15].into()),
                    ..crate::policy::DecryptionPolicy::default()
                })
                .decrypt_data(&encrypted);
            assert!(
                result.is_err(),
                "invalid RSA padding must never release fallback plaintext"
            );
            assert_eq!(
                provider.decrypt_calls.load(Ordering::Relaxed),
                1,
                "content decryption must run before rejecting the recovery"
            );
        }
    }

    #[test]
    fn candidate_filter_reuses_storage_and_preserves_precedence() {
        // Compact invalid widths and non-adjacent duplicates in place without
        // reordering distinct candidates or allocating a second candidate list.
        let keys = [
            vec![0; 8],
            vec![2; 16],
            vec![3; 16],
            vec![2; 16],
            vec![4; 32],
            vec![5; 16],
        ]
        .into_iter()
        .map(crate::provider::RecoveredContentKey::confirmed)
        .collect::<Vec<_>>();
        let allocation = keys.as_ptr();
        let keys = compatible_decryption_key_candidates(DataEncryptionAlgorithm::Aes128Gcm, keys)
            .expect("compatible candidates survive");
        assert_eq!(keys.as_ptr(), allocation);
        assert_eq!(keys.len(), 3);
        for (key, expected) in keys.iter().zip([2, 3, 5]) {
            assert_eq!(key.bytes(), &[expected; 16]);
        }
    }

    #[test]
    fn custom_provider_recovers_with_an_opaque_private_key() {
        // The resolver knows only the public ciphertext width; private key
        // material remains entirely behind the provider/key-handle boundary.
        let encrypted_key = EncryptedKey {
            id: None,
            sources: Default::default(),
            recipient: None,
            key_name: None,
            encryption_method: super::super::EncryptionMethod {
                algorithm: KeyTransportAlgorithm::RsaOaep11.uri().into(),
                key_size_bits: None,
                oaep_digest: Some(OaepDigestAlgorithm::Sha256.uri().into()),
                mgf_algorithm: Some(OaepDigestAlgorithm::Sha256.mgf_uri().into()),
                oaep_params: None,
            },
            cipher_data: super::super::CipherData::Value {
                value: STANDARD.encode(vec![0x5a; 256]),
            },
            reference_list: None,
            carried_key_name: None,
        };
        let provider = PermissiveUnwrapProvider::default();
        let decryptor = PrivateKeyDecryptor::provider_key(Arc::new(OpaqueRecoveryKey));

        let key = decryptor
            .resolve_key(
                &provider,
                DataEncryptionAlgorithm::Aes128Gcm,
                Some(&encrypted_key),
            )
            .expect("custom provider must recover through its opaque private key");

        assert_eq!(key, vec![0_u8; 16]);
        assert_eq!(provider.recover_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn rejects_truncated_gcm_and_invalid_wrapped_key() {
        // Framing and key-wrap integrity failures must occur before content is exposed.
        assert!(matches!(
            crate::provider::default_provider().decrypt_data(
                DataEncryptionAlgorithm::Aes128Gcm,
                &[0_u8; 16],
                &[0_u8; 27],
            ),
            Err(crate::provider::ProviderError::InvalidInput(
                crate::provider::ProviderInputError::AesGcmFraming
            ))
        ));
        let truncated = EncryptedData {
            id: None,
            derived_keys: Vec::new(),
            agreement_methods: Vec::new(),
            encrypted_type: None,
            key_name: None,
            encryption_method: super::super::EncryptionMethod {
                algorithm: DataEncryptionAlgorithm::Aes128Gcm.uri().into(),
                key_size_bits: None,
                oaep_digest: None,
                mgf_algorithm: None,
                oaep_params: None,
            },
            encrypted_keys: Vec::new(),
            cipher_data: super::super::CipherData::Value {
                value: STANDARD.encode([0_u8; 27]),
            },
        };
        assert!(matches!(
            DecryptContext::new(&SymmetricKeyDecryptor::new([0_u8; 16])).decrypt_data(&truncated),
            Err(XmlEncError::DataTooShort {
                algorithm: "AES-GCM",
                actual: 27,
                ..
            })
        ));
        let encrypted_key = EncryptedKey {
            id: None,
            sources: Default::default(),
            recipient: None,
            key_name: None,
            encryption_method: super::super::EncryptionMethod {
                algorithm: "http://www.w3.org/2001/04/xmlenc#kw-aes128".into(),
                key_size_bits: None,
                oaep_digest: None,
                mgf_algorithm: None,
                oaep_params: None,
            },
            cipher_data: super::super::CipherData::Value {
                value: STANDARD.encode([0_u8; 24]),
            },
            reference_list: None,
            carried_key_name: None,
        };
        assert!(matches!(
            KekDecryptor::new([0_u8; 16]).resolve_key(
                crate::provider::default_provider(),
                DataEncryptionAlgorithm::Aes128Gcm,
                Some(&encrypted_key)
            ),
            Err(XmlEncError::KeyWrapIntegrity)
        ));
        assert!(matches!(
            KekDecryptor::new([0_u8; 32]).resolve_key(
                crate::provider::default_provider(),
                DataEncryptionAlgorithm::Aes128Gcm,
                Some(&encrypted_key)
            ),
            Err(XmlEncError::InvalidKekSize {
                algorithm: KeyWrapAlgorithm::AesKw128,
                expected: 16,
                actual: 32
            })
        ));
    }

    #[test]
    fn decrypts_oaep11_with_independent_digest_and_mgf() {
        // XMLEnc 1.1 permits the OAEP digest and MGF1 digest to differ.
        let private_key = RsaPrivateKey::from_pkcs8_pem(include_str!(
            "../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
        ))
        .expect("RSA donor private key must parse");
        let public_key = RsaPublicKey::from(&private_key);
        let session_key = [6_u8; 16];
        let label = b"xmlenc-label".to_vec();
        let wrapped = public_key
            .encrypt(
                &mut ChaCha20Rng::from_seed([17_u8; 32]),
                Oaep::<Sha256, Sha384>::new_with_mgf_hash_and_label(label.clone()),
                &session_key,
            )
            .expect("OAEP test wrapping must succeed");
        let encrypted_key = EncryptedKey {
            id: Some("wrapped-key".into()),
            sources: Default::default(),
            recipient: Some("recipient-a".into()),
            key_name: None,
            encryption_method: super::super::EncryptionMethod {
                algorithm: "http://www.w3.org/2009/xmlenc11#rsa-oaep".into(),
                key_size_bits: None,
                oaep_digest: Some("http://www.w3.org/2001/04/xmlenc#sha256".into()),
                mgf_algorithm: Some("http://www.w3.org/2009/xmlenc11#mgf1sha384".into()),
                oaep_params: Some(label),
            },
            cipher_data: super::super::CipherData::Value {
                value: STANDARD.encode(wrapped),
            },
            reference_list: None,
            carried_key_name: None,
        };
        let resolved = PrivateKeyDecryptor::new(private_key)
            .resolve_key(
                crate::provider::default_provider(),
                DataEncryptionAlgorithm::Aes128Gcm,
                Some(&encrypted_key),
            )
            .expect("OAEP 1.1 wrapped key must resolve");
        assert_eq!(resolved, session_key);
    }

    #[test]
    fn decrypts_legacy_oaep_uri_with_sha256_digest() {
        // The legacy URI defaults MGF1 to SHA-1 when no xenc11:MGF child is present.
        let private_key = RsaPrivateKey::from_pkcs8_pem(include_str!(
            "../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
        ))
        .expect("RSA donor private key must parse");
        let public_key = RsaPublicKey::from(&private_key);
        let session_key = [8_u8; 16];
        let wrapped = public_key
            .encrypt(
                &mut ChaCha20Rng::from_seed([19_u8; 32]),
                Oaep::<Sha256, Sha1>::new_with_mgf_hash(),
                &session_key,
            )
            .expect("legacy OAEP URI test wrapping must succeed");
        let encrypted_key = EncryptedKey {
            id: None,
            sources: Default::default(),
            recipient: None,
            key_name: None,
            encryption_method: super::super::EncryptionMethod {
                algorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p".into(),
                key_size_bits: None,
                oaep_digest: Some("http://www.w3.org/2001/04/xmlenc#sha256".into()),
                mgf_algorithm: None,
                oaep_params: None,
            },
            cipher_data: super::super::CipherData::Value {
                value: STANDARD.encode(wrapped),
            },
            reference_list: None,
            carried_key_name: None,
        };
        let resolved = PrivateKeyDecryptor::new(private_key)
            .resolve_key(
                crate::provider::default_provider(),
                DataEncryptionAlgorithm::Aes128Gcm,
                Some(&encrypted_key),
            )
            .expect("legacy OAEP URI with SHA-256 must resolve");
        assert_eq!(resolved, session_key);
    }

    #[test]
    fn decrypts_sha384_oaep_with_the_xmlenc_digest_uri() {
        // XML Encryption 1.1 reserves xmlenc#sha384 for SHA-384. Exercise both
        // OAEP algorithm URIs with their absent/explicit MGF1-SHA1 forms.
        let private_key = RsaPrivateKey::from_pkcs8_pem(include_str!(
            "../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
        ))
        .expect("RSA donor private key must parse");
        let public_key = RsaPublicKey::from(&private_key);
        let session_key = [9_u8; 16];
        let digest = "http://www.w3.org/2001/04/xmlenc#sha384";

        for (algorithm, mgf_algorithm) in [
            ("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p", None),
            (
                "http://www.w3.org/2009/xmlenc11#rsa-oaep",
                Some("http://www.w3.org/2009/xmlenc11#mgf1sha1"),
            ),
        ] {
            let wrapped = public_key
                .encrypt(
                    &mut ChaCha20Rng::from_seed([23_u8; 32]),
                    Oaep::<Sha384, Sha1>::new_with_mgf_hash(),
                    &session_key,
                )
                .expect("SHA-384 OAEP test wrapping must succeed");
            let encrypted_key = EncryptedKey {
                id: None,
                sources: Default::default(),
                recipient: None,
                key_name: None,
                encryption_method: super::super::EncryptionMethod {
                    algorithm: algorithm.into(),
                    key_size_bits: None,
                    oaep_digest: Some(digest.into()),
                    mgf_algorithm: mgf_algorithm.map(str::to_owned),
                    oaep_params: None,
                },
                cipher_data: super::super::CipherData::Value {
                    value: STANDARD.encode(wrapped),
                },
                reference_list: None,
                carried_key_name: None,
            };
            let resolved = PrivateKeyDecryptor::new(private_key.clone())
                .resolve_key(
                    crate::provider::default_provider(),
                    DataEncryptionAlgorithm::Aes128Gcm,
                    Some(&encrypted_key),
                )
                .expect("official XMLENC SHA-384 URI must resolve");
            assert_eq!(resolved, session_key);
        }
    }

    #[test]
    fn rejects_unknown_oaep_digest_and_mgf_as_unsupported() {
        // Unknown algorithm URIs are declaration errors, not generic RSA failures.
        let private_key = RsaPrivateKey::from_pkcs8_pem(include_str!(
            "../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
        ))
        .expect("RSA donor private key must parse");
        let decryptor = PrivateKeyDecryptor::new(private_key);
        let mut encrypted_key = EncryptedKey {
            sources: Default::default(),
            id: None,
            recipient: None,
            key_name: None,
            encryption_method: super::super::EncryptionMethod {
                algorithm: "http://www.w3.org/2009/xmlenc11#rsa-oaep".into(),
                key_size_bits: None,
                oaep_digest: Some("urn:unsupported:digest".into()),
                mgf_algorithm: Some("http://www.w3.org/2009/xmlenc11#mgf1sha1".into()),
                oaep_params: None,
            },
            cipher_data: super::super::CipherData::Value {
                value: STANDARD.encode([0_u8; 256]),
            },
            reference_list: None,
            carried_key_name: None,
        };
        assert!(matches!(
            decryptor.resolve_key(crate::provider::default_provider(), DataEncryptionAlgorithm::Aes128Gcm, Some(&encrypted_key)),
            Err(XmlEncError::UnsupportedAlgorithm(uri)) if uri == "urn:unsupported:digest"
        ));

        encrypted_key.encryption_method.oaep_digest = None;
        encrypted_key.encryption_method.mgf_algorithm = Some("urn:unsupported:mgf".into());
        assert!(matches!(
            decryptor.resolve_key(crate::provider::default_provider(), DataEncryptionAlgorithm::Aes128Gcm, Some(&encrypted_key)),
            Err(XmlEncError::UnsupportedAlgorithm(uri)) if uri == "urn:unsupported:mgf"
        ));
    }

    #[test]
    fn decryption_policy_enforces_oaep_digest_and_plaintext_limits() {
        // Algorithm and allocation policies are checked before key resolution
        // or plaintext materialization, including the document-declared MGF.
        let encrypted_key = EncryptedKey {
            id: None,
            recipient: Some("selected".into()),
            sources: Default::default(),
            key_name: None,
            encryption_method: super::super::EncryptionMethod {
                algorithm: KeyTransportAlgorithm::RsaOaepMgf1p.uri().into(),
                key_size_bits: None,
                oaep_digest: Some(OaepDigestAlgorithm::Sha256.uri().into()),
                mgf_algorithm: Some(OaepDigestAlgorithm::Sha384.mgf_uri().into()),
                oaep_params: None,
            },
            cipher_data: super::super::CipherData::Value {
                value: STANDARD.encode([0_u8; 256]),
            },
            reference_list: None,
            carried_key_name: None,
        };
        let encrypted = EncryptedData {
            id: None,
            derived_keys: Vec::new(),
            agreement_methods: Vec::new(),
            encrypted_type: None,
            key_name: None,
            encryption_method: super::super::EncryptionMethod {
                algorithm: DataEncryptionAlgorithm::Aes128Gcm.uri().into(),
                key_size_bits: None,
                oaep_digest: None,
                mgf_algorithm: None,
                oaep_params: None,
            },
            encrypted_keys: vec![encrypted_key],
            cipher_data: super::super::CipherData::Value {
                value: STANDARD.encode([0_u8; 28]),
            },
        };
        let policy = crate::policy::DecryptionPolicy {
            oaep_digests: Some(std::collections::HashSet::from([
                OaepDigestAlgorithm::Sha256,
            ])),
            ..crate::policy::DecryptionPolicy::default()
        };
        assert!(matches!(
            DecryptContext::new(&RecipientKeyResolver {
                recipient: "selected",
                key: vec![0_u8; 16],
            })
            .policy(policy)
            .decrypt_data(&encrypted),
            Err(XmlEncError::Policy(
                crate::policy::PolicyViolation::Algorithm { algorithm, .. }
            )) if algorithm == OaepDigestAlgorithm::Sha384.mgf_uri()
        ));

        let ciphertext = crate::provider::default_provider()
            .encrypt_data(DataEncryptionAlgorithm::Aes128Gcm, &[0_u8; 16], b"four")
            .expect("test encryption must succeed");
        let bounded = EncryptedData {
            encrypted_keys: Vec::new(),
            cipher_data: super::super::CipherData::Value {
                value: STANDARD.encode(ciphertext),
            },
            ..encrypted
        };
        let policy = crate::policy::DecryptionPolicy {
            resources: crate::policy::ResourcePolicy {
                max_encryption_plaintext_bytes: 3,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::DecryptionPolicy::default()
        };
        assert!(matches!(
            DecryptContext::new(&SymmetricKeyDecryptor::new([0_u8; 16]))
                .policy(policy)
                .decrypt_data(&bounded),
            Err(XmlEncError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::ENCRYPTION_PLAINTEXT_BYTES,
                    maximum: 3,
                    actual: 4
                }
            ))
        ));

        let cbc_ciphertext = crate::provider::default_provider()
            .encrypt_data(DataEncryptionAlgorithm::Aes128Cbc, &[0_u8; 16], b"four")
            .expect("test CBC encryption must succeed");
        let bounded_cbc = EncryptedData {
            encryption_method: super::super::EncryptionMethod {
                algorithm: DataEncryptionAlgorithm::Aes128Cbc.uri().into(),
                key_size_bits: None,
                oaep_digest: None,
                mgf_algorithm: None,
                oaep_params: None,
            },
            encrypted_keys: Vec::new(),
            cipher_data: super::super::CipherData::Value {
                value: STANDARD.encode(cbc_ciphertext),
            },
            ..bounded
        };
        let policy = crate::policy::DecryptionPolicy {
            resources: crate::policy::ResourcePolicy {
                max_encryption_plaintext_bytes: 4,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::DecryptionPolicy::default()
        };
        assert_eq!(
            DecryptContext::new(&SymmetricKeyDecryptor::new([0_u8; 16]))
                .policy(policy)
                .decrypt_data(&bounded_cbc)
                .expect("CBC plaintext at the configured limit must decrypt"),
            DecryptedContent::Bytes(b"four".to_vec())
        );
    }

    #[test]
    fn typed_decryption_input_cannot_bypass_metadata_policy() {
        // Callers may construct EncryptedData directly instead of using the XML
        // parser, so the operation boundary must enforce the same metadata cap.
        let ciphertext = crate::provider::default_provider()
            .encrypt_data(DataEncryptionAlgorithm::Aes128Gcm, &[0_u8; 16], b"data")
            .expect("test encryption must succeed");
        let encrypted = EncryptedData {
            id: Some("oversized".into()),
            derived_keys: Vec::new(),
            agreement_methods: Vec::new(),
            encrypted_type: None,
            key_name: None,
            encryption_method: super::super::EncryptionMethod {
                algorithm: DataEncryptionAlgorithm::Aes128Gcm.uri().into(),
                key_size_bits: None,
                oaep_digest: None,
                mgf_algorithm: None,
                oaep_params: None,
            },
            encrypted_keys: Vec::new(),
            cipher_data: super::super::CipherData::Value {
                value: STANDARD.encode(ciphertext),
            },
        };
        let policy = crate::policy::DecryptionPolicy {
            resources: crate::policy::ResourcePolicy {
                max_encryption_metadata_bytes: 8,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::DecryptionPolicy::default()
        };

        let resolver = AllCallsResolver {
            calls: Cell::new(0),
            key: vec![0_u8; 16],
        };
        assert!(matches!(
            DecryptContext::new(&resolver)
                .policy(policy)
                .decrypt_data(&encrypted),
            Err(XmlEncError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::ENCRYPTION_METADATA_BYTES,
                    maximum: 8,
                    actual: 9,
                }
            ))
        ));
        assert_eq!(
            resolver.calls.get(),
            0,
            "metadata preflight must gate resolver-controlled work"
        );
    }

    #[test]
    fn typed_cipher_values_are_bounded_before_decode_or_resolution() {
        // Public typed input bypasses the XML parser, so the decryption boundary
        // must re-establish both content and recipient CipherValue size invariants.
        let key = [0x41_u8; 16];
        let ciphertext = crate::provider::default_provider()
            .encrypt_data(DataEncryptionAlgorithm::Aes128Gcm, &key, b"data")
            .expect("test encryption must succeed");
        let mut encrypted = EncryptedData {
            id: None,
            derived_keys: Vec::new(),
            agreement_methods: Vec::new(),
            encrypted_type: None,
            key_name: None,
            encryption_method: super::super::EncryptionMethod {
                algorithm: DataEncryptionAlgorithm::Aes128Gcm.uri().into(),
                key_size_bits: None,
                oaep_digest: None,
                mgf_algorithm: None,
                oaep_params: None,
            },
            encrypted_keys: Vec::new(),
            cipher_data: super::super::CipherData::Value {
                value: STANDARD.encode(ciphertext),
            },
        };
        let policy = crate::policy::DecryptionPolicy {
            resources: crate::policy::ResourcePolicy {
                max_encryption_plaintext_bytes: 4,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::DecryptionPolicy::default()
        };
        *encrypted
            .cipher_data
            .inline_value_mut()
            .expect("inline ciphertext") = "A".repeat(48);
        assert!(matches!(
            DecryptContext::new(&SymmetricKeyDecryptor::new(key))
                .policy(policy)
                .decrypt_data(&encrypted),
            Err(XmlEncError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::ENCRYPTION_PLAINTEXT_BYTES,
                    ..
                }
            ))
        ));

        *encrypted
            .cipher_data
            .inline_value_mut()
            .expect("inline ciphertext") = STANDARD.encode([0_u8; 28]);
        encrypted.encrypted_keys.push(EncryptedKey {
            sources: Default::default(),
            id: None,
            recipient: None,
            key_name: None,
            encryption_method: super::super::EncryptionMethod {
                algorithm: KeyWrapAlgorithm::AesKw128.uri().into(),
                key_size_bits: None,
                oaep_digest: None,
                mgf_algorithm: None,
                oaep_params: None,
            },
            cipher_data: super::super::CipherData::Value {
                value: "A".repeat(MAX_CIPHER_VALUE_BASE64_LEN + 4),
            },
            reference_list: None,
            carried_key_name: None,
        });
        let resolver = CountingResolver {
            candidate_calls: Cell::new(0),
            key: key.to_vec(),
        };
        assert!(matches!(
            DecryptContext::new(&resolver).decrypt_data(&encrypted),
            Err(XmlEncError::InvalidStructure(_))
        ));
        assert_eq!(resolver.candidate_calls.get(), 0);

        *encrypted.encrypted_keys[0]
            .cipher_data
            .inline_value_mut()
            .expect("inline wrapped key") = "AAAA".into();
        let aggregate_encoded_len = encrypted
            .cipher_data
            .inline_value()
            .expect("inline ciphertext")
            .len()
            + encrypted.encrypted_keys[0]
                .cipher_data
                .inline_value()
                .expect("inline wrapped key")
                .len();
        let policy = crate::policy::DecryptionPolicy {
            resources: crate::policy::ResourcePolicy {
                max_encryption_plaintext_bytes: 4,
                max_xml_document_bytes: aggregate_encoded_len - 1,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::DecryptionPolicy::default()
        };
        let resolver = CountingResolver {
            candidate_calls: Cell::new(0),
            key: key.to_vec(),
        };
        assert!(matches!(
            DecryptContext::new(&resolver)
                .policy(policy)
                .decrypt_data(&encrypted),
            Err(XmlEncError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource:
                        crate::policy::resource_name::AGGREGATE_ENCRYPTION_CIPHER_VALUE_BYTES,
                    maximum,
                    actual,
                }
            )) if maximum == aggregate_encoded_len - 1 && actual == aggregate_encoded_len
        ));
        assert_eq!(resolver.candidate_calls.get(), 0);
    }

    #[test]
    fn typed_legacy_oaep_accepts_explicit_mgf() {
        // The legacy URI defaults to MGF1-SHA1 when MGF is absent, but
        // libxmlsec1 also accepts the XMLEnc 1.1 child explicitly.
        let key = [0x43_u8; 16];
        let ciphertext = crate::provider::default_provider()
            .encrypt_data(DataEncryptionAlgorithm::Aes128Gcm, &key, b"data")
            .expect("test encryption must succeed");
        let encrypted = EncryptedData {
            id: None,
            derived_keys: Vec::new(),
            agreement_methods: Vec::new(),
            encrypted_type: None,
            key_name: None,
            encryption_method: super::super::EncryptionMethod {
                algorithm: DataEncryptionAlgorithm::Aes128Gcm.uri().into(),
                key_size_bits: None,
                oaep_digest: None,
                mgf_algorithm: None,
                oaep_params: None,
            },
            encrypted_keys: vec![EncryptedKey {
                sources: Default::default(),
                id: None,
                recipient: None,
                key_name: None,
                encryption_method: super::super::EncryptionMethod {
                    algorithm: KeyTransportAlgorithm::RsaOaepMgf1p.uri().into(),
                    key_size_bits: None,
                    oaep_digest: Some(OaepDigestAlgorithm::Sha256.uri().into()),
                    mgf_algorithm: Some(OaepDigestAlgorithm::Sha384.mgf_uri().into()),
                    oaep_params: None,
                },
                cipher_data: super::super::CipherData::Value {
                    value: STANDARD.encode([0_u8; 256]),
                },
                reference_list: None,
                carried_key_name: None,
            }],
            cipher_data: super::super::CipherData::Value {
                value: STANDARD.encode(ciphertext),
            },
        };
        let resolver = CountingResolver {
            candidate_calls: Cell::new(0),
            key: key.to_vec(),
        };

        assert_eq!(
            DecryptContext::new(&resolver)
                .decrypt_data(&encrypted)
                .expect("explicit legacy OAEP MGF must reach key resolution"),
            DecryptedContent::Bytes(b"data".to_vec())
        );
        assert_eq!(resolver.candidate_calls.get(), 1);
    }

    #[test]
    fn typed_zero_key_size_is_rejected_before_key_resolution() {
        // Parsed KeySize values are positive. Caller-constructed values must
        // preserve the same invariant for algorithms without a fixed AES width.
        let key = [0x45_u8; 16];
        let ciphertext = crate::provider::default_provider()
            .encrypt_data(DataEncryptionAlgorithm::Aes128Gcm, &key, b"data")
            .expect("test encryption must succeed");
        let encrypted = EncryptedData {
            id: None,
            derived_keys: Vec::new(),
            agreement_methods: Vec::new(),
            encrypted_type: None,
            key_name: None,
            encryption_method: super::super::EncryptionMethod {
                algorithm: DataEncryptionAlgorithm::Aes128Gcm.uri().into(),
                key_size_bits: None,
                oaep_digest: None,
                mgf_algorithm: None,
                oaep_params: None,
            },
            encrypted_keys: vec![EncryptedKey {
                id: None,
                sources: Default::default(),
                recipient: None,
                key_name: None,
                encryption_method: super::super::EncryptionMethod {
                    algorithm: KeyTransportAlgorithm::RsaOaep11.uri().into(),
                    key_size_bits: Some(0),
                    oaep_digest: Some(OaepDigestAlgorithm::Sha256.uri().into()),
                    mgf_algorithm: Some(OaepDigestAlgorithm::Sha256.mgf_uri().into()),
                    oaep_params: None,
                },
                cipher_data: super::super::CipherData::Value {
                    value: STANDARD.encode([0_u8; 256]),
                },
                reference_list: None,
                carried_key_name: None,
            }],
            cipher_data: super::super::CipherData::Value {
                value: STANDARD.encode(ciphertext),
            },
        };
        let resolver = CountingResolver {
            candidate_calls: Cell::new(0),
            key: key.to_vec(),
        };

        assert!(matches!(
            DecryptContext::new(&resolver).decrypt_data(&encrypted),
            Err(XmlEncError::InvalidStructure(message))
                if message == "KeySize must be a positive integer"
        ));
        assert_eq!(resolver.candidate_calls.get(), 0);
    }

    #[test]
    fn typed_content_method_is_validated_before_key_resolution() {
        // Caller-constructed values bypass XML parsing, so a fixed-size AES
        // KeySize mismatch must fail at the operation boundary.
        let key = [0x44_u8; 16];
        let ciphertext = crate::provider::default_provider()
            .encrypt_data(DataEncryptionAlgorithm::Aes128Gcm, &key, b"data")
            .expect("test encryption must succeed");
        let encrypted = EncryptedData {
            id: None,
            derived_keys: Vec::new(),
            agreement_methods: Vec::new(),
            encrypted_type: None,
            key_name: None,
            encryption_method: super::super::EncryptionMethod {
                algorithm: DataEncryptionAlgorithm::Aes128Gcm.uri().into(),
                key_size_bits: Some(256),
                oaep_digest: None,
                mgf_algorithm: None,
                oaep_params: None,
            },
            encrypted_keys: Vec::new(),
            cipher_data: super::super::CipherData::Value {
                value: STANDARD.encode(ciphertext),
            },
        };
        let resolver = AllCallsResolver {
            calls: Cell::new(0),
            key: key.to_vec(),
        };

        assert!(matches!(
            DecryptContext::new(&resolver).decrypt_data(&encrypted),
            Err(XmlEncError::InvalidStructure(message))
                if message.contains("requires KeySize 128, got 256")
        ));
        assert_eq!(resolver.calls.get(), 0);
    }

    #[test]
    fn unknown_encrypted_key_algorithm_never_reaches_resolver() {
        // Extension URIs cannot bypass transport/wrap allowlists by relying on
        // an application resolver that happens to return usable key bytes.
        let key = [0x42_u8; 16];
        let ciphertext = crate::provider::default_provider()
            .encrypt_data(DataEncryptionAlgorithm::Aes128Gcm, &key, b"data")
            .expect("test encryption must succeed");
        let encrypted = EncryptedData {
            id: None,
            derived_keys: Vec::new(),
            agreement_methods: Vec::new(),
            encrypted_type: None,
            key_name: None,
            encryption_method: super::super::EncryptionMethod {
                algorithm: DataEncryptionAlgorithm::Aes128Gcm.uri().into(),
                key_size_bits: None,
                oaep_digest: None,
                mgf_algorithm: None,
                oaep_params: None,
            },
            encrypted_keys: vec![EncryptedKey {
                id: None,
                recipient: None,
                sources: Default::default(),
                key_name: None,
                encryption_method: super::super::EncryptionMethod {
                    algorithm: "urn:example:unknown-key-algorithm".into(),
                    key_size_bits: None,
                    oaep_digest: None,
                    mgf_algorithm: None,
                    oaep_params: None,
                },
                cipher_data: super::super::CipherData::Value {
                    value: STANDARD.encode([0_u8; 24]),
                },
                reference_list: None,
                carried_key_name: None,
            }],
            cipher_data: super::super::CipherData::Value {
                value: STANDARD.encode(ciphertext),
            },
        };
        let resolver = CountingResolver {
            candidate_calls: Cell::new(0),
            key: key.to_vec(),
        };

        assert!(matches!(
            DecryptContext::new(&resolver).decrypt_data(&encrypted),
            Err(XmlEncError::UnsupportedAlgorithm(_))
        ));
        assert_eq!(resolver.candidate_calls.get(), 0);
    }

    #[test]
    fn cbc_padding_errors_do_not_expose_decrypted_octets() {
        // The error contract hides padding details, but callers still need an
        // authenticated envelope or a policy that rejects unauthenticated CBC.
        let error = map_data_decryption_error(
            DataEncryptionAlgorithm::Aes128Cbc,
            32,
            crate::provider::ProviderError::InvalidInput(
                crate::provider::ProviderInputError::AesCbcCiphertext,
            ),
        );

        assert_eq!(error.to_string(), "invalid XMLEnc padding");
    }

    #[test]
    fn replaces_element_and_content_in_caller_owned_documents() {
        // Element plaintext replaces the encrypted node itself, while Content
        // plaintext becomes children of the existing parent element.
        let key = [0x31_u8; 16];
        let element = encrypted_gcm_element(
            "http://www.w3.org/2001/04/xmlenc#Element",
            "<secret id=\"visible\">value</secret>",
            None,
            true,
            &key,
        );
        assert_eq!(
            decrypt_document(&element, None, &SymmetricKeyDecryptor::new(key))
                .expect("root Element replacement must succeed"),
            "<secret id=\"visible\">value</secret>"
        );

        let content = encrypted_gcm_element(
            "http://www.w3.org/2001/04/xmlenc#Content",
            "before<child/>after",
            None,
            false,
            &key,
        );
        let document =
            format!("<root xmlns:xenc=\"{XMLENC_NS}\"><prefix/>{content}<suffix/></root>");
        let replaced = decrypt_document(&document, None, &SymmetricKeyDecryptor::new(key))
            .expect("nested Content replacement must succeed");
        assert_eq!(
            replaced,
            format!(
                "<root xmlns:xenc=\"{XMLENC_NS}\"><prefix/>before<child/>after<suffix/></root>"
            )
        );
    }

    #[test]
    fn accepts_whitespace_and_comments_around_element_plaintext() {
        // Element serialization may carry harmless boundary whitespace/comments;
        // they must be preserved while the fragment still contains one element.
        let key = [0x34_u8; 16];
        let plaintext = "\n<!--before--><secret/><!--after-->\n";
        let encrypted = encrypted_gcm_element(
            "http://www.w3.org/2001/04/xmlenc#Element",
            plaintext,
            None,
            true,
            &key,
        );

        assert_eq!(
            decrypt_document(&encrypted, None, &SymmetricKeyDecryptor::new(key))
                .expect("one element with boundary trivia must be accepted"),
            plaintext
        );
    }

    #[test]
    fn decrypts_unknown_and_empty_type_hints_as_opaque_bytes() {
        // Type is an application hint, not an algorithm constraint. Unknown and
        // empty values must not prevent decryption of otherwise valid binary data.
        let key = [0x35_u8; 16];
        let plaintext = "\0opaque\u{ff}bytes";
        let unknown = encrypted_gcm_element("urn:example:binary", plaintext, None, true, &key);
        let empty = encrypted_gcm_element("", plaintext, None, true, &key).replacen(
            "<xenc:EncryptedData",
            "<xenc:EncryptedData Type=\"\"",
            1,
        );

        let parsed = parse_encrypted_data(&unknown).expect("unknown Type must remain parseable");
        assert_eq!(
            parsed.encrypted_type,
            Some(EncryptedDataType::Other("urn:example:binary".into()))
        );
        assert!(matches!(
            decrypt_document(&unknown, None, &SymmetricKeyDecryptor::new(key)),
            Err(XmlEncError::ReplacementRequiresXml)
        ));

        for encrypted in [unknown, empty] {
            assert_eq!(
                decrypt(&encrypted, &SymmetricKeyDecryptor::new(key))
                    .expect("opaque Type hints must not block decryption"),
                DecryptedContent::Bytes(plaintext.as_bytes().to_vec())
            );
        }
    }

    #[test]
    fn selects_document_encrypted_data_by_id_and_rejects_ambiguity() {
        // Selection must never decrypt an arbitrary first match when a document
        // contains multiple encrypted regions.
        let key = [0x32_u8; 16];
        let first = encrypted_gcm_element(
            "http://www.w3.org/2001/04/xmlenc#Content",
            "first",
            Some("first"),
            false,
            &key,
        );
        let second = encrypted_gcm_element(
            "http://www.w3.org/2001/04/xmlenc#Content",
            "second",
            Some("second"),
            false,
            &key,
        );
        let document = format!("<root xmlns:xenc=\"{XMLENC_NS}\">{first}{second}</root>");
        let resolver = SymmetricKeyDecryptor::new(key);
        assert!(matches!(
            decrypt_document(&document, None, &resolver),
            Err(XmlEncError::AmbiguousEncryptedData)
        ));
        let replaced = decrypt_document(&document, Some("second"), &resolver)
            .expect("Id selection must choose exactly one encrypted region");
        assert!(replaced.contains("second"));
        assert!(replaced.contains("Id=\"first\""));
        assert!(matches!(
            decrypt_document(&document, Some("missing"), &resolver),
            Err(XmlEncError::EncryptedDataNotFound)
        ));
    }

    #[test]
    fn selects_encrypted_data_below_a_unique_operation_start_node() {
        // CLI-compatible selection starts at an arbitrary ID-bearing ancestor;
        // missing/duplicate IDs and multiple encrypted descendants fail closed.
        let key = [0x42_u8; 16];
        let first = encrypted_gcm_element(
            "http://www.w3.org/2001/04/xmlenc#Content",
            "first",
            None,
            false,
            &key,
        );
        let second = encrypted_gcm_element(
            "http://www.w3.org/2001/04/xmlenc#Content",
            "second",
            None,
            false,
            &key,
        );
        let document = format!(
            "<root xmlns:xenc=\"{XMLENC_NS}\"><scope Id=\"first\">{first}</scope><scope Id=\"second\">{second}</scope></root>"
        );
        let resolver = SymmetricKeyDecryptor::new(key);
        let context = DecryptContext::new(&resolver);
        let replaced = context
            .decrypt_document_from_start_node(&document, Some("second"))
            .expect("ancestor ID must select its encrypted descendant");
        assert!(replaced.contains("<scope Id=\"second\">second</scope>"));
        assert!(replaced.contains("<scope Id=\"first\"><xenc:EncryptedData"));

        assert!(matches!(
            context.decrypt_document_from_start_node(&document, Some("missing")),
            Err(XmlEncError::SelectedNodeUnavailable { id }) if id == "missing"
        ));
        let duplicate = document.replace("Id=\"second\"", "Id=\"first\"");
        assert!(matches!(
            context.decrypt_document_from_start_node(&duplicate, Some("first")),
            Err(XmlEncError::SelectedNodeUnavailable { id }) if id == "first"
        ));
        let ambiguous = format!(
            "<root xmlns:xenc=\"{XMLENC_NS}\"><scope Id=\"selected\">{first}{second}</scope></root>"
        );
        assert!(matches!(
            context.decrypt_document_from_start_node(&ambiguous, Some("selected")),
            Err(XmlEncError::AmbiguousEncryptedData)
        ));

        let first_replaced = context
            .decrypt_first_document_from_start_node(&ambiguous, Some("selected"))
            .expect("first-match selection must leave later encrypted descendants untouched");
        assert!(first_replaced.contains("<scope Id=\"selected\">first<xenc:EncryptedData"));
        let replaced_document =
            Document::parse(&first_replaced).expect("first-match output must remain valid XML");
        assert_eq!(
            replaced_document
                .descendants()
                .filter(|node| node.has_tag_name((XMLENC_NS, "EncryptedData")))
                .count(),
            1
        );
    }

    #[test]
    fn rejects_non_xml_or_malformed_document_replacement_plaintext() {
        // The document API must not expose binary content or return a document
        // made malformed by unauthenticated structure assumptions.
        let key = [0x33_u8; 16];
        let binary = encrypted_gcm_element("", "binary", None, true, &key);
        assert!(matches!(
            decrypt_document(&binary, None, &SymmetricKeyDecryptor::new(key)),
            Err(XmlEncError::ReplacementRequiresXml)
        ));

        let malformed = encrypted_gcm_element(
            "http://www.w3.org/2001/04/xmlenc#Element",
            "<unclosed>",
            None,
            true,
            &key,
        );
        assert!(matches!(
            decrypt_document(&malformed, None, &SymmetricKeyDecryptor::new(key)),
            Err(XmlEncError::XmlParse(_))
        ));

        for invalid_element in ["text-only", "<first/><second/>"] {
            let encrypted = encrypted_gcm_element(
                "http://www.w3.org/2001/04/xmlenc#Element",
                invalid_element,
                None,
                false,
                &key,
            );
            let document = format!("<root xmlns:xenc=\"{XMLENC_NS}\">{encrypted}</root>");
            assert!(
                decrypt_document(&document, None, &SymmetricKeyDecryptor::new(key)).is_err(),
                "Element plaintext must contain exactly one element: {invalid_element}"
            );
        }

        let content = encrypted_gcm_element(
            "http://www.w3.org/2001/04/xmlenc#Content",
            "plaintext",
            None,
            false,
            &key,
        );
        let with_dtd = format!(
            "<!DOCTYPE root [<!ATTLIST root Id ID #IMPLIED>]><root xmlns:xenc=\"{XMLENC_NS}\">{content}</root>"
        );
        assert!(matches!(
            decrypt_document(&with_dtd, None, &SymmetricKeyDecryptor::new(key)),
            Err(XmlEncError::XmlParse(
                crate::xml::dom::ParseError::DtdDetected
            ))
        ));
        let mut policy = crate::policy::DecryptionPolicy::default();
        policy.xml.allow_internal_dtd = true;
        assert!(
            DecryptContext::new(&SymmetricKeyDecryptor::new(key))
                .policy(policy)
                .decrypt_document(&with_dtd, None)
                .expect("explicit internal-DTD opt-in must decrypt")
                .contains("plaintext")
        );
    }

    #[test]
    fn rejects_plaintext_markup_that_crosses_the_encrypted_region() {
        // Parsing only after raw splicing is insufficient: balanced close/reopen
        // tags can keep the document valid while moving attacker nodes outside the
        // element whose encrypted child is being replaced.
        let key = [0x36_u8; 16];
        let crossing_markup = "</parent><attacker/><parent>";
        for type_uri in [
            "http://www.w3.org/2001/04/xmlenc#Content",
            "http://www.w3.org/2001/04/xmlenc#Element",
        ] {
            let encrypted = encrypted_gcm_element(type_uri, crossing_markup, None, false, &key);
            let document =
                format!("<outer xmlns:xenc=\"{XMLENC_NS}\"><parent>{encrypted}</parent></outer>");
            assert!(
                decrypt_document(&document, None, &SymmetricKeyDecryptor::new(key)).is_err(),
                "{type_uri} plaintext must not escape its replacement boundary"
            );
        }
    }

    #[test]
    fn document_decryption_applies_byte_and_node_policy_before_parsing() {
        // Caller-owned XML must meet the compiled resource policy before the
        // initial DOM allocation; reparsed output uses the same node ceiling.
        let key = [0x38_u8; 16];
        let encrypted = encrypted_gcm_element(
            "http://www.w3.org/2001/04/xmlenc#Content",
            "plaintext",
            None,
            false,
            &key,
        );
        let document = format!("<root xmlns:xenc=\"{XMLENC_NS}\"><a/>{encrypted}</root>");
        let byte_policy = crate::policy::DecryptionPolicy {
            resources: crate::policy::ResourcePolicy {
                max_xml_document_bytes: document.len() - 1,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::DecryptionPolicy::default()
        };
        assert!(matches!(
            DecryptContext::new(&SymmetricKeyDecryptor::new(key))
                .policy(byte_policy)
                .decrypt_document(&document, None),
            Err(XmlEncError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_DOCUMENT,
                maximum,
                actual,
            })) if maximum == document.len() - 1 && actual == document.len()
        ));

        let node_policy = crate::policy::DecryptionPolicy {
            resources: crate::policy::ResourcePolicy {
                max_xml_nodes: 3,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::DecryptionPolicy::default()
        };
        assert!(matches!(
            DecryptContext::new(&SymmetricKeyDecryptor::new(key))
                .policy(node_policy)
                .decrypt_document(&document, None),
            Err(XmlEncError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_NODES,
                    maximum: 3,
                    actual: 4,
                }
            ))
        ));
    }

    #[test]
    fn decryption_entry_points_enforce_policy_depth() {
        // Depth validation precedes EncryptedData selection for both borrowed
        // and retained documents, including inputs parsed under wider defaults.
        let xml = "<root><child><leaf/></child></root>";
        let policy = crate::policy::DecryptionPolicy {
            resources: crate::policy::ResourcePolicy {
                max_xml_depth: 2,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::DecryptionPolicy::default()
        };
        let resolver = SymmetricKeyDecryptor::new([0_u8; 16]);
        let mut document = XmlDocument::parse(xml).expect("wide retained fixture must parse");

        assert!(matches!(
            DecryptContext::new(&resolver)
                .policy(policy.clone())
                .decrypt_document(xml, None),
            Err(XmlEncError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_DEPTH,
                    maximum: 2,
                    actual: 3,
                }
            ))
        ));
        assert!(matches!(
            DecryptContext::new(&resolver)
                .policy(policy)
                .decrypt_owned_document(&mut document, None),
            Err(XmlEncError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_DEPTH,
                    maximum: 2,
                    actual: 3,
                }
            ))
        ));
    }

    #[test]
    fn fragment_validation_does_not_charge_its_internal_wrapper_node() {
        // The caller's node ceiling applies to input and output XML, not the
        // implementation-only element used to prove replacement boundaries.
        let key = [0x39_u8; 16];
        let plaintext = "<item/>".repeat(20);
        let encrypted = encrypted_gcm_element(
            "http://www.w3.org/2001/04/xmlenc#Content",
            &plaintext,
            None,
            false,
            &key,
        );
        let document = format!("<root xmlns:xenc=\"{XMLENC_NS}\">{encrypted}</root>");
        let resolver = SymmetricKeyDecryptor::new(key);
        let expected = decrypt_document(&document, None, &resolver)
            .expect("unbounded setup decryption must succeed");
        let exact_output_nodes = Document::parse(&expected)
            .expect("decrypted output must parse")
            .descendants()
            .count();
        let policy = crate::policy::DecryptionPolicy {
            resources: crate::policy::ResourcePolicy {
                max_xml_nodes: exact_output_nodes,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::DecryptionPolicy::default()
        };

        assert_eq!(
            DecryptContext::new(&resolver)
                .policy(policy)
                .decrypt_document(&document, None)
                .expect("temporary wrapper must not consume caller node budget"),
            expected
        );
    }

    #[test]
    fn owned_decryption_rejects_projected_node_limit_atomically() {
        // The owned document may have been parsed under a broader ceiling than
        // this operation; expanded plaintext must be bounded before mutation.
        let key = [0x3a_u8; 16];
        let plaintext = "<item/>".repeat(64);
        let encrypted = encrypted_gcm_element(
            "http://www.w3.org/2001/04/xmlenc#Content",
            &plaintext,
            None,
            false,
            &key,
        );
        let mut document = XmlDocument::parse(format!(
            "<root xmlns:xenc=\"{XMLENC_NS}\">{encrypted}</root>"
        ))
        .expect("owned encrypted fixture must parse");
        let input_nodes = document.with_view(|view| view.node_count());
        let before = document.as_xml().to_owned();
        let policy = crate::policy::DecryptionPolicy {
            resources: crate::policy::ResourcePolicy {
                max_xml_nodes: input_nodes,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::DecryptionPolicy::default()
        };

        let error = DecryptContext::new(&SymmetricKeyDecryptor::new(key))
            .policy(policy)
            .decrypt_owned_document(&mut document, None)
            .expect_err("expanded plaintext must exceed the operation node ceiling");

        assert!(matches!(
            error,
            XmlEncError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_NODES,
                maximum,
                ..
            }) if maximum == input_nodes
        ));
        assert_eq!(document.as_xml(), before);
        assert_eq!(document.generation(), 0);
    }

    #[test]
    fn owned_decryption_reports_decrypted_depth_as_policy() {
        // The encrypted envelope can satisfy the active depth policy while its
        // plaintext replacement exceeds it. That rejection must retain the
        // typed policy contract and leave the owned document untouched.
        let key = [0x3b_u8; 16];
        let plaintext = format!("{}value{}", "<nested>".repeat(32), "</nested>".repeat(32));
        let encrypted = encrypted_gcm_element(
            "http://www.w3.org/2001/04/xmlenc#Element",
            &plaintext,
            None,
            false,
            &key,
        );
        let mut document = XmlDocument::parse(format!(
            "<root xmlns:xenc=\"{XMLENC_NS}\">{encrypted}</root>"
        ))
        .expect("encrypted fixture must parse");
        let input_depth = document.with_view(|view| view.max_depth());
        let before = document.as_xml().to_owned();
        let policy = crate::policy::DecryptionPolicy {
            resources: crate::policy::ResourcePolicy {
                max_xml_depth: input_depth,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::DecryptionPolicy::default()
        };

        let error = DecryptContext::new(&SymmetricKeyDecryptor::new(key))
            .policy(policy)
            .decrypt_owned_document(&mut document, None)
            .expect_err("deep plaintext must exceed the active depth policy");

        assert!(matches!(
            error,
            XmlEncError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_DEPTH,
                maximum,
                actual,
            }) if maximum == input_depth && actual > maximum
        ));
        assert_eq!(document.as_xml(), before);
        assert_eq!(document.generation(), 0);
    }

    #[test]
    fn validates_replacement_plaintext_in_its_namespace_context() {
        // Decrypted fragments inherit namespaces from the encrypted node's
        // ancestors, so boundary validation must occur inside the source document.
        let key = [0x37_u8; 16];
        let encrypted = encrypted_gcm_element(
            "http://www.w3.org/2001/04/xmlenc#Content",
            "<shared:child/>",
            None,
            false,
            &key,
        );
        let document = format!(
            "<root xmlns:xenc=\"{XMLENC_NS}\" xmlns:shared=\"urn:shared\">{encrypted}</root>"
        );
        let decrypted = decrypt_document(&document, None, &SymmetricKeyDecryptor::new(key))
            .expect("inherited namespace prefixes must remain valid");
        assert_eq!(
            decrypted,
            format!(
                "<root xmlns:xenc=\"{XMLENC_NS}\" xmlns:shared=\"urn:shared\"><shared:child/></root>"
            )
        );
    }

    fn encrypted_gcm_element(
        type_uri: &str,
        plaintext: &str,
        id: Option<&str>,
        declare_namespace: bool,
        key: &[u8; 16],
    ) -> String {
        let nonce = [0x44_u8; 12];
        let mut ciphertext = plaintext.as_bytes().to_vec();
        Aes128Gcm::new_from_slice(key)
            .expect("fixed content key length")
            .encrypt_in_place(&nonce.into(), b"", &mut ciphertext)
            .expect("test encryption must succeed");
        let mut wire = nonce.to_vec();
        wire.extend_from_slice(&ciphertext);
        let namespace = declare_namespace
            .then_some(format!(" xmlns:xenc=\"{XMLENC_NS}\""))
            .unwrap_or_default();
        let data_type = (!type_uri.is_empty())
            .then_some(format!(" Type=\"{type_uri}\""))
            .unwrap_or_default();
        let id = id
            .map(|value| format!(" Id=\"{value}\""))
            .unwrap_or_default();
        format!(
            "<xenc:EncryptedData{namespace}{data_type}{id}><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"/><xenc:CipherData><xenc:CipherValue>{}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>",
            STANDARD.encode(wire)
        )
    }
}
