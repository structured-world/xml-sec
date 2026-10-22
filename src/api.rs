//! Cohesive, policy-bound XML Security operations.
//!
//! [`XmlSecurity`] borrows one compiled policy and explicitly selected provider.
//! Operation handles expose request data, never policy replacement or provider
//! fallback. Advanced APIs remain in [`crate::xmldsig`], [`crate::c14n`] and
//! the feature-gated `xmlenc` module.
#![doc = include_str!("../docs/rust-api.md")]

use crate::key_manager::KeyInventory;
use crate::policy::CompiledPolicies;
use crate::provider::CryptoProvider;
use crate::xmldsig::{
    KeyInfoWriter, KeyResolver, SignContext, SignatureAlgorithm, SignatureBuilder,
    SignatureTemplateSelection, SigningKey, VerificationRequest, VerifyContext, VerifyEvidence,
    VerifyResult, VerifyingKey,
};
use crate::{IdAttributeRegistration, XmlBackend, XmlDocument, XmlSecError};
use std::collections::HashMap;

/// The operation whose immutable policy governs document preparation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Operation {
    /// XMLDSig verification.
    Verify,
    /// XMLDSig signature generation.
    Sign,
    /// XML Encryption generation.
    #[cfg(feature = "xmlenc")]
    Encrypt,
    /// XML Encryption recovery.
    #[cfg(feature = "xmlenc")]
    Decrypt,
}

/// Reusable immutable binding, with no keys, documents or ambient I/O.
///
/// The binding is `Send + Sync`; operation handles retain the thread-safety of
/// their caller-supplied keys/resolvers. Cloning this binding copies references,
/// not policy sets, keys or provider reference counts. The caller keeps both
/// borrowed objects alive; it may hold them in its own `Arc` if needed.
#[derive(Clone, Copy)]
pub struct XmlSecurity<'a> {
    policies: &'a CompiledPolicies,
    provider: &'a dyn CryptoProvider,
    backend: XmlBackend,
}

impl<'a> XmlSecurity<'a> {
    /// Bind compiled permissions to the actual provider, validating capabilities
    /// before parsing or key selection. No default engine is selected here.
    pub fn new(
        policies: &'a CompiledPolicies,
        provider: &'a dyn CryptoProvider,
    ) -> Result<Self, XmlSecError> {
        policies.validate_provider(provider)?;
        Ok(Self {
            policies,
            provider,
            backend: XmlBackend::default(),
        })
    }

    /// Select a compiled parser implementation, not a different XML policy.
    #[must_use]
    pub fn xml_backend(mut self, backend: XmlBackend) -> Self {
        self.backend = backend;
        self
    }

    /// Prepare an owned document under one enabled operation's XML policy.
    ///
    /// An owned `String` moves into the document. Preparation is a separate
    /// operation; subsequent retained-document calls validate its provenance.
    /// For a single parse+operation budget use the string operation entry points.
    pub fn parse_document(
        &self,
        xml: impl AsRef<str> + Into<String>,
        operation: Operation,
    ) -> Result<XmlDocument, XmlSecError> {
        let missing = XmlSecError::OperationDisabled(operation);
        Ok(match operation {
            Operation::Verify => XmlDocument::parse_with_policy_and_backend(
                xml,
                self.policies.verification().ok_or(missing)?,
                self.backend,
            )?,
            Operation::Sign => XmlDocument::parse_with_policy_and_backend(
                xml,
                self.policies.signing().ok_or(missing)?,
                self.backend,
            )?,
            #[cfg(feature = "xmlenc")]
            Operation::Encrypt => XmlDocument::parse_with_policy_and_backend(
                xml,
                self.policies.encryption().ok_or(missing)?,
                self.backend,
            )?,
            #[cfg(feature = "xmlenc")]
            Operation::Decrypt => XmlDocument::parse_with_policy_and_backend(
                xml,
                self.policies.decryption().ok_or(missing)?,
                self.backend,
            )?,
        })
    }

    /// Begin verification. Caller keys and request targets remain explicit.
    pub fn verifier(&self) -> Result<Verifier<'_>, XmlSecError> {
        let policy = self
            .policies
            .verification()
            .ok_or(XmlSecError::OperationDisabled(Operation::Verify))?;
        Ok(Verifier {
            context: VerifyContext::new()
                .policy(policy.clone())
                .provider(self.provider)
                .xml_backend(self.backend),
        })
    }

    /// Begin signing with an opaque caller-owned key.
    pub fn signer<'s>(&'s self, key: &'s dyn SigningKey) -> Result<Signer<'s>, XmlSecError> {
        let policy = self
            .policies
            .signing()
            .ok_or(XmlSecError::OperationDisabled(Operation::Sign))?;
        Ok(Signer {
            context: SignContext::new(key)
                .policy(policy.clone())
                .provider(self.provider)
                .xml_backend(self.backend),
        })
    }

    /// Select/import an authorized named key using the same provider and policy.
    pub fn signing_key(
        &self,
        inventory: &KeyInventory,
        name: &str,
        algorithm: SignatureAlgorithm,
    ) -> Result<Box<dyn SigningKey>, XmlSecError> {
        let policy = self
            .policies
            .signing()
            .ok_or(XmlSecError::OperationDisabled(Operation::Sign))?;
        Ok(inventory.signing_key_with_provider(name, algorithm, policy, self.provider)?)
    }

    /// Bind encryption request material without cloning its keys or recipients.
    /// The compiled snapshot overrides any policy/provider stored in the builder.
    #[cfg(feature = "xmlenc")]
    pub fn encryptor<'b>(
        &'b self,
        builder: &'b crate::xmlenc::EncryptedDataBuilder,
    ) -> Result<Encryptor<'b>, XmlSecError> {
        let policy = self
            .policies
            .encryption()
            .ok_or(XmlSecError::OperationDisabled(Operation::Encrypt))?;
        Ok(Encryptor {
            execution: builder.bind(policy, self.provider, self.backend),
        })
    }

    /// Begin decryption with a caller-owned resolver; never discover keys or I/O.
    #[cfg(feature = "xmlenc")]
    pub fn decryptor<'s>(
        &'s self,
        resolver: &'s dyn crate::xmlenc::DecryptionKeyResolver,
    ) -> Result<Decryptor<'s>, XmlSecError> {
        let policy = self
            .policies
            .decryption()
            .ok_or(XmlSecError::OperationDisabled(Operation::Decrypt))?;
        Ok(Decryptor {
            context: crate::xmlenc::DecryptContext::new(resolver)
                .policy(policy.clone())
                .provider(self.provider)
                .xml_backend(self.backend),
        })
    }

    /// Select a named recovery key with the bound provider and decryption policy.
    #[cfg(feature = "xmlenc")]
    pub fn decryption_key(
        &self,
        inventory: &KeyInventory,
        name: &str,
    ) -> Result<Box<dyn crate::xmlenc::DecryptionKeyResolver>, XmlSecError> {
        let policy = self
            .policies
            .decryption()
            .ok_or(XmlSecError::OperationDisabled(Operation::Decrypt))?;
        Ok(inventory.decryption_resolver_with_provider(name, policy, self.provider)?)
    }
}

/// Verification request binding. It cannot replace the compiled policy/provider.
pub struct Verifier<'a> {
    context: VerifyContext<'a>,
}

impl<'a> Verifier<'a> {
    /// Supply an explicitly caller-trusted verification key.
    #[must_use]
    pub fn key(mut self, key: &'a dyn VerifyingKey) -> Self {
        self.context = self.context.key(key);
        self
    }
    /// Supply an existing policy-aware resolver, including an inventory adapter.
    #[must_use]
    pub fn key_resolver(mut self, resolver: &'a dyn KeyResolver) -> Self {
        self.context = self.context.key_resolver(resolver);
        self
    }
    /// Supply caller-declared ID spellings, without changing XML allowances.
    #[must_use]
    pub fn id_attributes(mut self, attributes: &'a [IdAttributeRegistration]) -> Self {
        self.context = self.context.id_attributes(attributes);
        self
    }
    /// Supply application-owned UTC history for certificate validation.
    #[must_use]
    pub fn utc_facts(mut self, facts: structured_pkix::temporal::LeapTable<'a>) -> Self {
        self.context = self.context.utc_facts(facts);
        self
    }
    /// Verify all selected request requirements against the retained generation.
    /// `Ok` is not acceptance: call `evidence.accepted(document)` and consume only
    /// caller-selected, authenticated targets. Invalid signatures remain evidence.
    pub fn verify(
        &self,
        document: &XmlDocument,
        request: &VerificationRequest<'_>,
    ) -> Result<VerifyEvidence, XmlSecError> {
        Ok(self.context.verify_request(document, request)?)
    }
    /// Verify one signature with the existing borrowed XML pipeline.
    /// This returns mathematical diagnostics, not expected-target authorization;
    /// use `verify` for application acceptance and multiple signatures.
    pub fn verify_signature_xml(&self, xml: &str) -> Result<VerifyResult, XmlSecError> {
        Ok(self.context.verify(xml)?)
    }
}

/// Signing request binding over the existing operation-plan/mutation pipeline.
pub struct Signer<'a> {
    context: SignContext<'a>,
}

impl<'a> Signer<'a> {
    /// Fill a template's KeyInfo placeholder through its existing writer.
    /// Builder-based calls must request that placeholder with `key_info(true)`.
    #[must_use]
    pub fn key_info_writer(mut self, writer: &'a dyn KeyInfoWriter) -> Self {
        self.context = self.context.key_info_writer(writer);
        self
    }
    /// Borrow detached inputs; the compiled URI policy remains authoritative.
    #[must_use]
    pub fn external_resources(mut self, resources: &'a HashMap<String, Vec<u8>>) -> Self {
        self.context = self.context.external_resources(resources);
        self
    }
    /// Add explicit ID registrations for target selection and dereferencing.
    #[must_use]
    pub fn id_attributes(mut self, attributes: &'a [IdAttributeRegistration]) -> Self {
        self.context = self.context.id_attributes(attributes);
        self
    }
    /// Select the caller's append/template scope by ID.
    #[must_use]
    pub fn start_node_id(mut self, id: &'a str) -> Self {
        self.context = self.context.start_node_id(id);
        self
    }
    /// Select an existing template, not an algorithm or policy exception.
    #[must_use]
    pub fn template_selection(mut self, selection: SignatureTemplateSelection) -> Self {
        self.context = self.context.signature_template_selection(selection);
        self
    }
    /// Stage and commit a signature as one document generation on success.
    pub fn sign(
        &self,
        document: &mut XmlDocument,
        builder: &SignatureBuilder,
    ) -> Result<(), XmlSecError> {
        Ok(self.context.sign_document_with_builder(document, builder)?)
    }
    /// Parse, sign and return XML through the same cumulative-budget pipeline.
    pub fn sign_xml(&self, xml: &str, builder: &SignatureBuilder) -> Result<String, XmlSecError> {
        Ok(self.context.sign_with_builder(xml, builder)?)
    }
    /// Fill an existing template in a retained document atomically.
    pub fn sign_template(&self, document: &mut XmlDocument) -> Result<(), XmlSecError> {
        Ok(self.context.sign_document(document)?)
    }
    /// Fill an existing template using the string convenience path.
    pub fn sign_template_xml(&self, xml: &str) -> Result<String, XmlSecError> {
        Ok(self.context.sign_template(xml)?)
    }
}

/// Encryption execution borrows all request keys and the selected provider.
#[cfg(feature = "xmlenc")]
pub struct Encryptor<'a> {
    execution: crate::xmlenc::BoundEncryption<'a>,
}

#[cfg(feature = "xmlenc")]
impl Encryptor<'_> {
    /// Encrypt and commit one selected retained-document target.
    pub fn encrypt(
        &self,
        document: &mut XmlDocument,
        options: crate::xmlenc::DocumentEncryptionOptions<'_>,
    ) -> Result<(), XmlSecError> {
        Ok(self.execution.encrypt_owned_document(document, options)?)
    }
    /// Parse, replace and return a complete encrypted document.
    pub fn encrypt_xml(
        &self,
        xml: &str,
        options: crate::xmlenc::DocumentEncryptionOptions<'_>,
    ) -> Result<String, XmlSecError> {
        Ok(self.execution.encrypt_document(xml, options)?)
    }
    /// Encrypt a standalone XML element/content fragment without insertion.
    pub fn encrypt_fragment(
        &self,
        xml: &str,
    ) -> Result<crate::xmlenc::EncryptionResult, XmlSecError> {
        Ok(self.execution.encrypt_xml(xml)?)
    }
    /// Encrypt borrowed opaque bytes, not an XML document.
    pub fn encrypt_binary(
        &self,
        bytes: &[u8],
    ) -> Result<crate::xmlenc::EncryptionResult, XmlSecError> {
        Ok(self.execution.encrypt_binary(bytes)?)
    }
}

/// Decryption request binding; failures never commit a partial document mutation.
#[cfg(feature = "xmlenc")]
pub struct Decryptor<'a> {
    context: crate::xmlenc::DecryptContext<'a>,
}

#[cfg(feature = "xmlenc")]
impl<'a> Decryptor<'a> {
    /// Borrow external ciphertext inputs under the original URI/transform policy.
    #[must_use]
    pub fn external_resources(mut self, resources: &'a HashMap<String, Vec<u8>>) -> Self {
        self.context = self.context.external_resources(resources);
        self
    }
    /// Register explicit ID spellings for ciphertext and key references.
    /// The `decrypt` selector still names the schema's `EncryptedData/@Id`.
    #[must_use]
    pub fn id_attributes(mut self, attributes: &'a [IdAttributeRegistration]) -> Self {
        self.context = self.context.id_attributes(attributes);
        self
    }
    /// Recover and atomically replace one retained EncryptedData target.
    /// `id` optionally selects its schema `Id` attribute, not another ID spelling.
    pub fn decrypt(&self, document: &mut XmlDocument, id: Option<&str>) -> Result<(), XmlSecError> {
        Ok(self.context.decrypt_owned_document(document, id)?)
    }
    /// Parse, recover and return a complete document.
    pub fn decrypt_xml(&self, xml: &str, id: Option<&str>) -> Result<String, XmlSecError> {
        Ok(self.context.decrypt_document(xml, id)?)
    }
    /// Recover a standalone EncryptedData fragment without document insertion.
    pub fn decrypt_fragment(
        &self,
        xml: &str,
    ) -> Result<crate::xmlenc::DecryptedContent, XmlSecError> {
        Ok(self.context.decrypt(xml)?)
    }
}
