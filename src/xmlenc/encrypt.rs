//! XMLEnc content encryption, key wrapping, and XML generation.

use std::{fmt, sync::Arc};

use crate::xml::dom::{Document, Node};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use quick_xml::{
    Writer,
    events::{BytesEnd, BytesStart, BytesText, Event},
};
use rsa::RsaPublicKey;

use crate::document::{
    DocumentParseSettings, XmlDocument, XmlDocumentError, XmlParseWorkBudget,
    parse_borrowed_with_settings_and_budget,
};
use crate::operation::{
    OperationExecutionContext, OperationNodeId, OperationNodeKind, OperationPlanError,
    OperationResourceIdentity, OperationStage,
};
use crate::xml::{is_xml_1_0_character, is_xml_ncname};

use super::types::{XMLDSIG_NS, XMLENC_NS, XMLENC11_NS};
use super::{
    DataEncryptionAlgorithm, DocumentEncryptionOptions, EncryptedDataType, EncryptionRecipient,
    EncryptionResult, KeyWrapAlgorithm, ReplacementMode, RsaOaepParameters, XmlEncError,
    has_single_element_with_boundary_trivia, map_document_error,
};

const XML_WHITESPACE: &[char] = &[' ', '\t', '\n', '\r'];

/// Validate an RSA recipient key against the compiled encryption policy.
///
/// Key registries can use this preflight before selecting a candidate, ensuring
/// ordered searches skip keys that the encryption operation would reject.
pub fn validate_rsa_recipient_key(
    key: &RsaPublicKey,
    policy: &crate::policy::EncryptionPolicy,
) -> Result<(), XmlEncError> {
    validate_key_transport_recipient(key, policy)
}

/// Validate an opaque RSA transport key against the compiled encryption policy.
///
/// The handle's public metadata must identify the exact key used by the
/// selected provider. This preflight lets provider-owned key registries apply
/// the same policy as [`EncryptedDataBuilder`] before selecting a candidate.
pub fn validate_key_transport_recipient(
    key: &dyn crate::provider::KeyTransportKey,
    policy: &crate::policy::EncryptionPolicy,
) -> Result<(), XmlEncError> {
    let modulus = key.rsa_modulus();
    let exponent = key.rsa_exponent();
    policy
        .rsa_keys
        .validate_components("encryption", &modulus, &exponent)?;
    Ok(())
}

/// Builder for complete `EncryptedData` fragments and document replacement.
#[derive(Clone)]
pub struct EncryptedDataBuilder {
    algorithm: DataEncryptionAlgorithm,
    encrypted_type: EncryptedDataType,
    id: Option<String>,
    direct_key: Option<Vec<u8>>,
    direct_key_name: Option<String>,
    recipients: Vec<EncryptionRecipient>,
    policy: crate::policy::EncryptionPolicy,
    provider: Arc<dyn crate::provider::CryptoProvider>,
    xml_backend: crate::XmlBackend,
}

struct GeneratedEncryption {
    result: EncryptionResult,
    xml_nodes: usize,
    mutation: Option<OperationNodeId>,
}

struct EncryptionPlanNodes {
    document: OperationNodeId,
    keys: Vec<OperationNodeId>,
    crypto: OperationNodeId,
    evidence: OperationNodeId,
    mutation: Option<OperationNodeId>,
}

struct EncryptionOperationBudgets {
    xml_parse: XmlParseWorkBudget,
}

impl EncryptionOperationBudgets {
    fn from_policy(policy: &crate::policy::EncryptionPolicy) -> Self {
        Self {
            xml_parse: XmlParseWorkBudget::from_resources(&policy.resources),
        }
    }
}

fn compile_encryption_plan(
    operation: &mut OperationExecutionContext<
        crate::policy::EncryptionPolicy,
        EncryptionOperationBudgets,
    >,
    key_count: usize,
    mutation: bool,
    input_resource: OperationResourceIdentity,
) -> Result<EncryptionPlanNodes, XmlEncError> {
    let document = operation.add_node(
        OperationNodeKind::Document,
        OperationStage::Parse,
        Some(input_resource),
    );
    let mut keys = Vec::with_capacity(key_count.max(1));
    for index in 0..key_count.max(1) {
        let key = operation.add_node(
            OperationNodeKind::Key { index },
            OperationStage::Resolve,
            None,
        );
        operation
            .add_dependency(key, document)
            .map_err(map_encryption_plan_error)?;
        keys.push(key);
    }
    let crypto = operation.add_node(OperationNodeKind::Crypto, OperationStage::Crypto, None);
    for key in &keys {
        operation
            .add_dependency(crypto, *key)
            .map_err(map_encryption_plan_error)?;
    }
    let evidence = operation.add_node(OperationNodeKind::Evidence, OperationStage::Evidence, None);
    operation
        .add_dependency(evidence, crypto)
        .map_err(map_encryption_plan_error)?;
    let mutation = mutation.then(|| {
        let node = operation.add_node(OperationNodeKind::Mutation, OperationStage::Mutation, None);
        operation
            .add_dependency(node, evidence)
            .expect("evidence-to-mutation stage order is fixed");
        node
    });
    operation.compile().map_err(map_encryption_plan_error)?;
    Ok(EncryptionPlanNodes {
        document,
        keys,
        crypto,
        evidence,
        mutation,
    })
}

fn map_encryption_plan_error(error: OperationPlanError) -> XmlEncError {
    XmlEncError::InvalidStructure(format!("invalid encryption operation plan: {error}"))
}

impl fmt::Debug for EncryptedDataBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedDataBuilder")
            .field("algorithm", &self.algorithm)
            .field("encrypted_type", &self.encrypted_type)
            .field("id", &self.id)
            .field(
                "direct_key",
                &self.direct_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("direct_key_name", &self.direct_key_name)
            .field("recipients", &self.recipients)
            .field("policy", &self.policy)
            .field("provider", &self.provider.name())
            .finish()
    }
}

impl EncryptedDataBuilder {
    /// Create a builder for a content-encryption algorithm.
    pub fn new(algorithm: DataEncryptionAlgorithm) -> Self {
        Self {
            algorithm,
            encrypted_type: EncryptedDataType::Element,
            id: None,
            direct_key: None,
            direct_key_name: None,
            recipients: Vec::new(),
            policy: crate::policy::EncryptionPolicy::default(),
            provider: Arc::new(crate::provider::RustCryptoProvider),
            xml_backend: crate::XmlBackend::default(),
        }
    }

    /// Replace the complete immutable encryption policy snapshot.
    pub fn policy(mut self, policy: crate::policy::EncryptionPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Select the cryptographic provider for this operation context.
    pub fn provider(mut self, provider: Arc<dyn crate::provider::CryptoProvider>) -> Self {
        self.provider = provider;
        self
    }

    /// Select the compiled XML parser backend for encryption document work.
    pub fn xml_backend(mut self, backend: crate::XmlBackend) -> Self {
        self.xml_backend = backend;
        self
    }

    fn document_parse_settings(&self) -> DocumentParseSettings {
        DocumentParseSettings::from_policy(&self.policy.xml, &self.policy.resources)
            .with_backend(self.xml_backend)
    }

    /// Set whether XML encryption covers one element or its child content.
    pub fn encryption_type(mut self, encrypted_type: EncryptedDataType) -> Self {
        self.encrypted_type = encrypted_type;
        self
    }

    /// Set the generated `EncryptedData` identifier.
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Use a caller-managed content key instead of generating and wrapping one.
    pub fn direct_key(mut self, key: impl Into<Vec<u8>>) -> Self {
        self.direct_key = Some(key.into());
        self
    }

    /// Emit a direct `KeyName` hint for a caller-managed content key.
    pub fn direct_key_name(mut self, key_name: impl Into<String>) -> Self {
        self.direct_key_name = Some(key_name.into());
        self
    }

    /// Add one independently wrapped recipient of the generated content key.
    pub fn add_recipient(mut self, recipient: EncryptionRecipient) -> Self {
        self.recipients.push(recipient);
        self
    }

    /// Add an RSA-OAEP recipient using secure XMLEnc 1.1 defaults.
    pub fn recipient_rsa_oaep(self, public_key: RsaPublicKey) -> Self {
        self.add_recipient(EncryptionRecipient::rsa_oaep(public_key))
    }

    /// Add an RSA-OAEP recipient backed by an opaque provider key handle.
    pub fn recipient_key_transport(
        self,
        public_key: Arc<dyn crate::provider::KeyTransportKey>,
    ) -> Self {
        self.add_recipient(EncryptionRecipient::provider_key_transport(public_key))
    }

    /// Add an AES Key Wrap recipient.
    pub fn recipient_aes_kw(self, kek: impl Into<Vec<u8>>, algorithm: KeyWrapAlgorithm) -> Self {
        self.add_recipient(EncryptionRecipient::aes_key_wrap(kek, algorithm))
    }

    /// Encrypt one complete XML element or an XML content fragment.
    pub fn encrypt_xml(&self, xml: &str) -> Result<EncryptionResult, XmlEncError> {
        self.policy.validate()?;
        self.validate_plaintext_len(xml.len())?;
        let mut operation = OperationExecutionContext::new(
            self.policy.clone(),
            EncryptionOperationBudgets::from_policy(&self.policy),
            None,
        );
        validate_xml_plaintext(
            xml,
            &self.encrypted_type,
            &self.policy,
            &operation.budgets().xml_parse,
            self.xml_backend,
        )?;
        let generated = self.encrypt_payload_with_operation(
            xml.as_bytes(),
            Some(self.encrypted_type.clone()),
            &mut operation,
            false,
        )?;
        validate_standalone_encrypted_data_nodes(
            generated.xml_nodes,
            self.policy.resources.effective_xml_nodes() as usize,
        )?;
        Ok(generated.result)
    }

    /// Encrypt opaque bytes, preserving a configured non-XML `Type` hint.
    ///
    /// Element and Content are XML replacement semantics and are omitted from
    /// binary output. Any other URI remains application metadata.
    pub fn encrypt_binary(&self, data: &[u8]) -> Result<EncryptionResult, XmlEncError> {
        self.policy.validate()?;
        let mut operation = OperationExecutionContext::new(
            self.policy.clone(),
            EncryptionOperationBudgets::from_policy(&self.policy),
            None,
        );
        let encrypted_type = match &self.encrypted_type {
            EncryptedDataType::Other(uri) => Some(EncryptedDataType::Other(uri.clone())),
            EncryptedDataType::Element | EncryptedDataType::Content => None,
        };
        let generated =
            self.encrypt_payload_with_operation(data, encrypted_type, &mut operation, false)?;
        validate_standalone_encrypted_data_nodes(
            generated.xml_nodes,
            self.policy.resources.effective_xml_nodes() as usize,
        )?;
        Ok(generated.result)
    }

    /// Encrypt and replace the document root or one element selected by XML ID.
    pub fn encrypt_document(
        &self,
        xml: &str,
        options: DocumentEncryptionOptions<'_>,
    ) -> Result<String, XmlEncError> {
        self.policy.validate()?;
        self.validate_document_len(xml.len())?;
        let budgets = EncryptionOperationBudgets::from_policy(&self.policy);
        let settings = self.document_parse_settings();
        let mut document = XmlDocument::parse_with_settings_and_budget(
            xml.to_owned(),
            settings,
            &budgets.xml_parse,
        )
        .map_err(|error| map_document_error(error, settings))?;
        self.encrypt_owned_document_with_budgets(&mut document, options, budgets)?;
        Ok(document.into_xml())
    }

    /// Encrypt and replace a node in a reusable owned XML document.
    ///
    /// Successful mutation advances the document generation and invalidates
    /// identities captured before this call.
    pub fn encrypt_owned_document(
        &self,
        document: &mut XmlDocument,
        options: DocumentEncryptionOptions<'_>,
    ) -> Result<(), XmlEncError> {
        self.encrypt_owned_document_with_budgets(
            document,
            options,
            EncryptionOperationBudgets::from_policy(&self.policy),
        )
    }

    fn encrypt_owned_document_with_budgets(
        &self,
        document: &mut XmlDocument,
        options: DocumentEncryptionOptions<'_>,
        budgets: EncryptionOperationBudgets,
    ) -> Result<(), XmlEncError> {
        self.policy.validate()?;
        document.validate_operation_policy(&self.policy.xml, &self.policy.resources)?;
        let document_nodes = document.with_view(|view| view.node_count());
        let (target, source, content_boundaries, selected_nodes) = document.with_view(|view| {
            let selected = select_encryption_target(view.document(), options.element_id)?;
            let source = &view.xml()[selected.range()];
            let content_boundaries = match self.encrypted_type {
                EncryptedDataType::Element => {
                    self.validate_plaintext_len(source.len())?;
                    None
                }
                EncryptedDataType::Content => {
                    let boundaries = element_content_boundaries(source)?;
                    self.validate_plaintext_len(boundaries.content.len())?;
                    Some(boundaries)
                }
                EncryptedDataType::Other(_) => None,
            };
            Ok::<_, XmlEncError>((
                view.node_identity(selected),
                source.to_owned(),
                content_boundaries,
                selected.descendants().count(),
            ))
        })?;
        let mut operation = OperationExecutionContext::new(
            self.policy.clone(),
            budgets,
            Some((document.identity(), document.generation())),
        );
        document
            .with_view(|view| operation.validate_document_view(view))
            .map_err(map_encryption_plan_error)?;

        match self.encrypted_type {
            EncryptedDataType::Element => {
                let generated = self.encrypt_payload_with_operation(
                    source.as_bytes(),
                    Some(EncryptedDataType::Element),
                    &mut operation,
                    true,
                )?;
                let result = generated.result;
                validate_replacement_document_len(
                    document.as_xml().len(),
                    source.len(),
                    result.encrypted_data_xml.len(),
                    self.policy.resources.max_xml_document_bytes,
                )?;
                validate_replacement_node_counts(
                    document_nodes,
                    selected_nodes,
                    generated.xml_nodes,
                    ReplacementMode::ReplaceElement,
                    self.policy.resources.effective_xml_nodes() as usize,
                )?;
                let settings = self.document_parse_settings();
                if let Some(mutation) = generated.mutation {
                    operation.run_document_transition(
                        mutation,
                        document,
                        |document, budgets| {
                            document
                                .replace_element_with_budget(
                                    target,
                                    &result.encrypted_data_xml,
                                    settings,
                                    &budgets.xml_parse,
                                )
                                .map_err(|error| map_document_error(error, settings))
                        },
                    )?;
                }
                Ok(())
            }
            EncryptedDataType::Content => {
                let boundaries = content_boundaries.ok_or_else(|| {
                    XmlEncError::InvalidStructure(
                        "content encryption target boundaries are unavailable".into(),
                    )
                })?;
                let plaintext = &source[boundaries.content.clone()];
                let generated = self.encrypt_payload_with_operation(
                    plaintext.as_bytes(),
                    Some(EncryptedDataType::Content),
                    &mut operation,
                    true,
                )?;
                let result = generated.result;
                let (removed, inserted) = if boundaries.self_closing {
                    let slash = source[..boundaries.start_tag_end]
                        .rfind('/')
                        .ok_or_else(|| {
                            XmlEncError::InvalidStructure("self-closing tag has no slash".into())
                        })?;
                    (
                        source.len(),
                        slash
                            .saturating_add(result.encrypted_data_xml.len())
                            .saturating_add(boundaries.qualified_name.len())
                            .saturating_add(4),
                    )
                } else {
                    (boundaries.content.len(), result.encrypted_data_xml.len())
                };
                validate_replacement_document_len(
                    document.as_xml().len(),
                    removed,
                    inserted,
                    self.policy.resources.max_xml_document_bytes,
                )?;
                validate_replacement_node_counts(
                    document_nodes,
                    selected_nodes,
                    generated.xml_nodes,
                    ReplacementMode::ReplaceContent,
                    self.policy.resources.effective_xml_nodes() as usize,
                )?;
                let settings = self.document_parse_settings();
                if let Some(mutation) = generated.mutation {
                    operation.run_document_transition(
                        mutation,
                        document,
                        |document, budgets| {
                            document
                                .replace_content_with_budget(
                                    target,
                                    &result.encrypted_data_xml,
                                    settings,
                                    &budgets.xml_parse,
                                )
                                .map_err(|error| map_document_error(error, settings))
                        },
                    )?;
                }
                Ok(())
            }
            EncryptedDataType::Other(_) => Err(XmlEncError::InvalidEncryptionConfig(
                "document encryption requires Element or Content Type".into(),
            )),
        }
    }

    fn encrypt_payload_with_operation(
        &self,
        plaintext: &[u8],
        encrypted_type: Option<EncryptedDataType>,
        operation: &mut OperationExecutionContext<
            crate::policy::EncryptionPolicy,
            EncryptionOperationBudgets,
        >,
        mutates_document: bool,
    ) -> Result<GeneratedEncryption, XmlEncError> {
        let input_resource = OperationResourceIdentity::external("encryption-input", plaintext);
        let plan = compile_encryption_plan(
            operation,
            self.recipients.len() + usize::from(self.direct_key.is_some()),
            mutates_document,
            input_resource,
        )?;
        let observed_input = OperationResourceIdentity::external("encryption-input", plaintext);
        operation.run_with_resource(plan.document, &observed_input, || {
            self.validate_plaintext_len(plaintext.len())?;
            self.validate_configuration()
        })?;

        let (content_key, encrypted_keys) = operation.run_batch(&plan.keys, || {
            let content_key = if let Some(key) = &self.direct_key {
                validate_content_key(self.algorithm, key)?;
                key.clone()
            } else {
                random_bytes(self.provider.as_ref(), self.algorithm.key_len())?
            };
            let encrypted_keys = self
                .recipients
                .iter()
                .map(|recipient| wrap_content_key(self.provider.as_ref(), recipient, &content_key))
                .collect::<Result<Vec<_>, _>>()?;
            Ok::<_, XmlEncError>((content_key, encrypted_keys))
        })?;
        let ciphertext = operation.run(plan.crypto, || {
            encrypt_content(
                self.provider.as_ref(),
                self.algorithm,
                &content_key,
                plaintext,
            )
        })?;
        let (encrypted_data_xml, xml_nodes) = operation.run(plan.evidence, || {
            let encrypted_data_xml = render_encrypted_data(
                self.algorithm,
                encrypted_type.as_ref(),
                self.id.as_deref(),
                self.direct_key_name.as_deref(),
                &encrypted_keys,
                &ciphertext,
            )?;
            self.validate_document_len(encrypted_data_xml.len())?;
            let xml_nodes = count_generated_encrypted_data_nodes(
                &encrypted_data_xml,
                &self.policy,
                &operation.budgets().xml_parse,
                self.xml_backend,
            )?;
            Ok::<_, XmlEncError>((encrypted_data_xml, xml_nodes))
        })?;
        let replacement = match encrypted_type {
            Some(EncryptedDataType::Content) => ReplacementMode::ReplaceContent,
            Some(EncryptedDataType::Element | EncryptedDataType::Other(_)) | None => {
                ReplacementMode::ReplaceElement
            }
        };
        Ok(GeneratedEncryption {
            result: EncryptionResult {
                encrypted_data_xml,
                replacement,
            },
            xml_nodes,
            mutation: plan.mutation,
        })
    }

    fn validate_configuration(&self) -> Result<(), XmlEncError> {
        self.policy.validate()?;
        if let EncryptedDataType::Other(uri) = &self.encrypted_type {
            self.validate_metadata("EncryptedData Type", Some(uri))?;
        }
        if self
            .policy
            .data_algorithms
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(&self.algorithm))
        {
            return Err(crate::policy::PolicyViolation::Algorithm {
                operation: "encryption",
                algorithm: self.algorithm.to_string(),
            }
            .into());
        }
        if self.recipients.len() > self.policy.resources.max_encryption_recipients {
            return Err(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::ENCRYPTION_RECIPIENTS,
                maximum: self.policy.resources.max_encryption_recipients,
                actual: self.recipients.len(),
            }
            .into());
        }
        let key_candidates = self.recipients.len() + usize::from(self.direct_key.is_some());
        self.policy
            .resources
            .validate_key_candidates(key_candidates)?;
        self.validate_metadata("EncryptedData Id", self.id.as_deref())?;
        if self.id.as_deref().is_some_and(|id| !is_xml_ncname(id)) {
            return Err(XmlEncError::InvalidEncryptionConfig(
                "EncryptedData Id must be an XML NCName".into(),
            ));
        }
        self.validate_key_name("direct KeyName", self.direct_key_name.as_deref())?;
        for recipient in &self.recipients {
            match recipient {
                EncryptionRecipient::RsaOaep {
                    public_key,
                    parameters,
                    recipient,
                    key_name,
                } => {
                    validate_key_transport_recipient(public_key.as_ref(), &self.policy)?;
                    if parameters.algorithm == super::KeyTransportAlgorithm::RsaOaepMgf1p
                        && parameters.mgf_digest != super::OaepDigestAlgorithm::Sha1
                    {
                        return Err(XmlEncError::InvalidEncryptionConfig(
                            "legacy RSA-OAEP fixes MGF1 to SHA-1".into(),
                        ));
                    }
                    if self
                        .policy
                        .key_transport_algorithms
                        .as_ref()
                        .is_some_and(|allowed| !allowed.contains(&parameters.algorithm))
                        || self.policy.oaep_digests.as_ref().is_some_and(|allowed| {
                            !allowed.contains(&parameters.digest)
                                || !allowed.contains(&parameters.mgf_digest)
                        })
                    {
                        return Err(crate::policy::PolicyViolation::Algorithm {
                            operation: "encryption",
                            algorithm: parameters.algorithm.uri().to_string(),
                        }
                        .into());
                    }
                    self.validate_metadata("EncryptedKey Recipient", recipient.as_deref())?;
                    self.validate_key_name("EncryptedKey KeyName", key_name.as_deref())?;
                    self.validate_metadata_len(parameters.label.len())?;
                }
                EncryptionRecipient::AesKeyWrap {
                    kek,
                    algorithm,
                    recipient,
                    key_name,
                } => {
                    if self
                        .policy
                        .key_wrap_algorithms
                        .as_ref()
                        .is_some_and(|allowed| !allowed.contains(algorithm))
                    {
                        return Err(crate::policy::PolicyViolation::Algorithm {
                            operation: "encryption",
                            algorithm: algorithm.uri().to_string(),
                        }
                        .into());
                    }
                    if kek.len() != algorithm.key_len() {
                        return Err(XmlEncError::InvalidEncryptionConfig(format!(
                            "{} requires a {}-byte key-encryption key, got {} bytes",
                            algorithm.uri(),
                            algorithm.key_len(),
                            kek.len()
                        )));
                    }
                    self.validate_metadata("EncryptedKey Recipient", recipient.as_deref())?;
                    self.validate_key_name("EncryptedKey KeyName", key_name.as_deref())?;
                }
            }
        }
        match (self.direct_key.is_some(), self.recipients.is_empty()) {
            (false, true) => Err(XmlEncError::InvalidEncryptionConfig(
                "configure a direct content key or at least one wrapped recipient".into(),
            )),
            (true, false) => Err(XmlEncError::InvalidEncryptionConfig(
                "a direct content key cannot be combined with wrapped recipients".into(),
            )),
            _ if self.direct_key_name.is_some() && self.direct_key.is_none() => {
                Err(XmlEncError::InvalidEncryptionConfig(
                    "direct KeyName requires a direct content key".into(),
                ))
            }
            _ => Ok(()),
        }
    }

    fn validate_metadata(
        &self,
        field: &'static str,
        value: Option<&str>,
    ) -> Result<(), XmlEncError> {
        validate_metadata(
            field,
            value,
            self.policy.resources.max_encryption_metadata_bytes,
        )
    }

    fn validate_key_name(
        &self,
        field: &'static str,
        value: Option<&str>,
    ) -> Result<(), XmlEncError> {
        validate_key_name(
            field,
            value,
            self.policy.resources.max_encryption_metadata_bytes,
        )
    }

    fn validate_metadata_len(&self, actual: usize) -> Result<(), XmlEncError> {
        validate_metadata_len(actual, self.policy.resources.max_encryption_metadata_bytes)
    }

    fn validate_plaintext_len(&self, actual: usize) -> Result<(), XmlEncError> {
        validate_plaintext_len(actual, self.policy.resources.max_encryption_plaintext_bytes)
    }

    fn validate_document_len(&self, actual: usize) -> Result<(), XmlEncError> {
        validate_document_len(actual, self.policy.resources.max_xml_document_bytes)
    }
}

fn validate_metadata(
    field: &'static str,
    value: Option<&str>,
    maximum: usize,
) -> Result<(), XmlEncError> {
    if value.is_some_and(|value| !value.chars().all(is_xml_1_0_character)) {
        return Err(XmlEncError::InvalidEncryptionConfig(format!(
            "{field} contains a character forbidden by XML 1.0"
        )));
    }
    validate_metadata_len(value.map_or(0, str::len), maximum)
}

fn validate_key_name(
    field: &'static str,
    value: Option<&str>,
    maximum: usize,
) -> Result<(), XmlEncError> {
    if value.is_some_and(str::is_empty) {
        return Err(XmlEncError::InvalidEncryptionConfig(format!(
            "{field} must not be empty"
        )));
    }
    validate_metadata(field, value, maximum)
}

fn validate_metadata_len(actual: usize, maximum: usize) -> Result<(), XmlEncError> {
    if actual <= maximum {
        Ok(())
    } else {
        Err(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::ENCRYPTION_METADATA_BYTES,
            maximum,
            actual,
        }
        .into())
    }
}

#[derive(Debug)]
struct WrappedKey {
    algorithm_uri: &'static str,
    oaep: Option<RsaOaepParameters>,
    recipient: Option<String>,
    key_name: Option<String>,
    ciphertext: Vec<u8>,
}

#[derive(Debug)]
struct ContentBoundaries {
    content: std::ops::Range<usize>,
    self_closing: bool,
    qualified_name: String,
    start_tag_end: usize,
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

fn validate_document_len(actual: usize, maximum: usize) -> Result<(), XmlEncError> {
    if actual > maximum {
        return Err(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::XML_DOCUMENT,
            maximum,
            actual,
        }
        .into());
    }
    Ok(())
}

fn validate_replacement_document_len(
    document_len: usize,
    removed_len: usize,
    inserted_len: usize,
    maximum: usize,
) -> Result<(), XmlEncError> {
    let actual = document_len
        .saturating_sub(removed_len)
        .saturating_add(inserted_len);
    validate_document_len(actual, maximum)
}

fn validate_replacement_node_counts(
    document_nodes: usize,
    selected_nodes: usize,
    inserted_nodes: usize,
    replacement: ReplacementMode,
    maximum: usize,
) -> Result<(), XmlEncError> {
    let removed_nodes = match replacement {
        ReplacementMode::ReplaceElement => selected_nodes,
        ReplacementMode::ReplaceContent => selected_nodes.saturating_sub(1),
    };
    let actual = document_nodes
        .saturating_sub(removed_nodes)
        .saturating_add(inserted_nodes);
    if actual > maximum {
        return Err(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::XML_NODES,
            maximum,
            actual,
        }
        .into());
    }
    Ok(())
}

fn count_generated_encrypted_data_nodes(
    encrypted_data_xml: &str,
    policy: &crate::policy::EncryptionPolicy,
    parse_budget: &XmlParseWorkBudget,
    backend: crate::XmlBackend,
) -> Result<usize, XmlEncError> {
    let maximum_nodes = policy.resources.effective_xml_nodes();
    // The standalone parser adds one document node that is not inserted into
    // the caller's tree. Bound the generated subtree by the active policy while
    // admitting that transient root so exact-fit content replacement remains valid.
    let settings = DocumentParseSettings {
        nodes_limit: maximum_nodes.saturating_add(1),
        ..DocumentParseSettings::from_policy(&policy.xml, &policy.resources).with_backend(backend)
    };
    let generated =
        parse_borrowed_with_settings_and_budget(encrypted_data_xml, settings, Some(parse_budget))
            .map_err(|error| match error {
            XmlDocumentError::Parse(crate::xml::dom::ParseError::NodesLimitReached) => {
                XmlEncError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_NODES,
                    maximum: maximum_nodes as usize,
                    actual: maximum_nodes as usize + 1,
                })
            }
            error => map_document_error(error, settings),
        })?;
    Ok(generated.root_element().descendants().count())
}

fn validate_standalone_encrypted_data_nodes(
    encrypted_data_subtree_nodes: usize,
    maximum: usize,
) -> Result<(), XmlEncError> {
    let actual = encrypted_data_subtree_nodes.saturating_add(1);
    if actual > maximum {
        return Err(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::XML_NODES,
            maximum,
            actual,
        }
        .into());
    }
    Ok(())
}

fn validate_content_key(algorithm: DataEncryptionAlgorithm, key: &[u8]) -> Result<(), XmlEncError> {
    if key.len() == algorithm.key_len() {
        Ok(())
    } else {
        Err(XmlEncError::InvalidKeySize {
            algorithm,
            expected: algorithm.key_len(),
            actual: key.len(),
        })
    }
}

fn random_bytes(
    provider: &dyn crate::provider::CryptoProvider,
    len: usize,
) -> Result<Vec<u8>, XmlEncError> {
    provider.require_capability(crate::provider::ProviderCapability::Random)?;
    let mut bytes = vec![0_u8; len];
    provider.fill_random(&mut bytes)?;
    Ok(bytes)
}

fn encrypt_content(
    provider: &dyn crate::provider::CryptoProvider,
    algorithm: DataEncryptionAlgorithm,
    key: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, XmlEncError> {
    provider.require_capability(crate::provider::ProviderCapability::Encrypt(algorithm))?;
    let ciphertext = provider.encrypt_data(algorithm, key, plaintext)?;
    super::types::validate_ciphertext_framing(algorithm, ciphertext.len())?;
    let expected = algorithm
        .ciphertext_len_for_plaintext(plaintext.len())
        .ok_or(crate::policy::PolicyViolation::ResourceLimit {
            resource: crate::policy::resource_name::ENCRYPTION_PLAINTEXT_BYTES,
            maximum: crate::hard_limits::ENCRYPTION_PLAINTEXT_BYTE_CEILING,
            actual: plaintext.len(),
        })?;
    if ciphertext.len() != expected {
        return Err(crate::provider::ProviderError::InvalidOutputSize {
            operation: crate::provider::ProviderOperation::Encrypt,
            expected,
            actual: ciphertext.len(),
        }
        .into());
    }
    Ok(ciphertext)
}

fn wrap_content_key(
    provider: &dyn crate::provider::CryptoProvider,
    recipient: &EncryptionRecipient,
    content_key: &[u8],
) -> Result<WrappedKey, XmlEncError> {
    match recipient {
        EncryptionRecipient::RsaOaep {
            public_key,
            parameters,
            recipient,
            key_name,
        } => Ok(WrappedKey {
            algorithm_uri: parameters.algorithm.uri(),
            oaep: Some(parameters.clone()),
            recipient: recipient.clone(),
            key_name: key_name.clone(),
            ciphertext: wrap_rsa_oaep(provider, public_key.as_ref(), parameters, content_key)?,
        }),
        EncryptionRecipient::AesKeyWrap {
            kek,
            algorithm,
            recipient,
            key_name,
        } => {
            provider
                .require_capability(crate::provider::ProviderCapability::KeyWrap(*algorithm))?;
            let wrapped = provider.wrap_key(*algorithm, kek, content_key)?;
            let expected = content_key.len() + 8;
            if wrapped.len() != expected {
                return Err(XmlEncError::InvalidWrappedKeyLength {
                    expected,
                    actual: wrapped.len(),
                });
            }
            Ok(WrappedKey {
                algorithm_uri: algorithm.uri(),
                oaep: None,
                recipient: recipient.clone(),
                key_name: key_name.clone(),
                ciphertext: wrapped,
            })
        }
    }
}

fn wrap_rsa_oaep(
    provider: &dyn crate::provider::CryptoProvider,
    public_key: &dyn crate::provider::KeyTransportKey,
    parameters: &RsaOaepParameters,
    content_key: &[u8],
) -> Result<Vec<u8>, XmlEncError> {
    provider.require_capability(crate::provider::ProviderCapability::KeyTransport(
        parameters,
    ))?;
    let ciphertext = provider
        .transport_key(public_key, parameters, content_key)
        .map_err(|error| match error {
            crate::provider::ProviderError::Random(message) => XmlEncError::Rng(message),
            crate::provider::ProviderError::InvalidInput(reason) => {
                XmlEncError::InvalidEncryptionConfig(reason.to_string())
            }
            error => XmlEncError::RsaEncrypt(error.to_string()),
        })?;
    let expected = public_key.rsa_modulus().len();
    if ciphertext.len() != expected {
        return Err(XmlEncError::InvalidWrappedKeyLength {
            expected,
            actual: ciphertext.len(),
        });
    }
    Ok(ciphertext)
}

fn render_encrypted_data(
    algorithm: DataEncryptionAlgorithm,
    encrypted_type: Option<&EncryptedDataType>,
    id: Option<&str>,
    direct_key_name: Option<&str>,
    encrypted_keys: &[WrappedKey],
    ciphertext: &[u8],
) -> Result<String, XmlEncError> {
    let mut writer = Writer::new(Vec::new());
    let mut root = BytesStart::new("xenc:EncryptedData");
    root.push_attribute(("xmlns:xenc", XMLENC_NS));
    root.push_attribute(("xmlns:xenc11", XMLENC11_NS));
    root.push_attribute(("xmlns:ds", XMLDSIG_NS));
    if let Some(id) = id {
        root.push_attribute(("Id", id));
    }
    if let Some(encrypted_type) = encrypted_type {
        let uri = match encrypted_type {
            EncryptedDataType::Element => format!("{XMLENC_NS}Element"),
            EncryptedDataType::Content => format!("{XMLENC_NS}Content"),
            EncryptedDataType::Other(uri) => uri.clone(),
        };
        root.push_attribute(("Type", uri.as_str()));
    }
    write_event(&mut writer, Event::Start(root))?;
    write_empty_with_algorithm(&mut writer, "xenc:EncryptionMethod", algorithm.uri())?;

    if direct_key_name.is_some() || !encrypted_keys.is_empty() {
        write_event(&mut writer, Event::Start(BytesStart::new("ds:KeyInfo")))?;
        if let Some(key_name) = direct_key_name {
            write_text_element(&mut writer, "ds:KeyName", key_name)?;
        }
        for encrypted_key in encrypted_keys {
            write_encrypted_key(&mut writer, encrypted_key)?;
        }
        write_event(&mut writer, Event::End(BytesEnd::new("ds:KeyInfo")))?;
    }

    write_cipher_data(&mut writer, ciphertext)?;
    write_event(&mut writer, Event::End(BytesEnd::new("xenc:EncryptedData")))?;
    String::from_utf8(writer.into_inner())
        .map_err(|error| XmlEncError::XmlSerialize(error.to_string()))
}

fn write_encrypted_key(
    writer: &mut Writer<Vec<u8>>,
    encrypted_key: &WrappedKey,
) -> Result<(), XmlEncError> {
    let mut start = BytesStart::new("xenc:EncryptedKey");
    if let Some(recipient) = encrypted_key.recipient.as_deref() {
        start.push_attribute(("Recipient", recipient));
    }
    write_event(writer, Event::Start(start))?;

    if let Some(parameters) = encrypted_key.oaep.as_ref() {
        let mut method = BytesStart::new("xenc:EncryptionMethod");
        method.push_attribute(("Algorithm", encrypted_key.algorithm_uri));
        write_event(writer, Event::Start(method))?;
        if !parameters.label.is_empty() {
            write_text_element(
                writer,
                "xenc:OAEPparams",
                &STANDARD.encode(&parameters.label),
            )?;
        }
        write_empty_with_algorithm(writer, "ds:DigestMethod", parameters.digest.uri())?;
        if parameters.algorithm == super::KeyTransportAlgorithm::RsaOaep11 {
            write_empty_with_algorithm(writer, "xenc11:MGF", parameters.mgf_digest.mgf_uri())?;
        }
        write_event(writer, Event::End(BytesEnd::new("xenc:EncryptionMethod")))?;
    } else {
        write_empty_with_algorithm(writer, "xenc:EncryptionMethod", encrypted_key.algorithm_uri)?;
    }

    if let Some(key_name) = encrypted_key.key_name.as_deref() {
        write_event(writer, Event::Start(BytesStart::new("ds:KeyInfo")))?;
        write_text_element(writer, "ds:KeyName", key_name)?;
        write_event(writer, Event::End(BytesEnd::new("ds:KeyInfo")))?;
    }
    write_cipher_data(writer, &encrypted_key.ciphertext)?;
    write_event(writer, Event::End(BytesEnd::new("xenc:EncryptedKey")))
}

fn write_cipher_data(writer: &mut Writer<Vec<u8>>, value: &[u8]) -> Result<(), XmlEncError> {
    write_event(writer, Event::Start(BytesStart::new("xenc:CipherData")))?;
    write_text_element(writer, "xenc:CipherValue", &STANDARD.encode(value))?;
    write_event(writer, Event::End(BytesEnd::new("xenc:CipherData")))
}

fn write_empty_with_algorithm(
    writer: &mut Writer<Vec<u8>>,
    name: &str,
    algorithm: &str,
) -> Result<(), XmlEncError> {
    let mut element = BytesStart::new(name);
    element.push_attribute(("Algorithm", algorithm));
    write_event(writer, Event::Empty(element))
}

fn write_text_element(
    writer: &mut Writer<Vec<u8>>,
    name: &str,
    text: &str,
) -> Result<(), XmlEncError> {
    write_event(writer, Event::Start(BytesStart::new(name)))?;
    write_event(writer, Event::Text(BytesText::new(text)))?;
    write_event(writer, Event::End(BytesEnd::new(name)))
}

fn write_event(writer: &mut Writer<Vec<u8>>, event: Event<'_>) -> Result<(), XmlEncError> {
    writer
        .write_event(event)
        .map_err(|error| XmlEncError::XmlSerialize(error.to_string()))
}

fn validate_xml_plaintext(
    xml: &str,
    encrypted_type: &EncryptedDataType,
    policy: &crate::policy::EncryptionPolicy,
    parse_budget: &XmlParseWorkBudget,
    backend: crate::XmlBackend,
) -> Result<(), XmlEncError> {
    let settings =
        DocumentParseSettings::from_policy(&policy.xml, &policy.resources).with_backend(backend);
    match encrypted_type {
        EncryptedDataType::Element => {
            let document =
                parse_borrowed_with_settings_and_budget(xml, settings, Some(parse_budget))
                    .map_err(|error| map_document_error(error, settings))?;
            if !has_single_element_with_boundary_trivia(document.root()) {
                return Err(XmlEncError::InvalidStructure(
                    "Element plaintext must contain exactly one element".into(),
                ));
            }
            Ok(())
        }
        EncryptedDataType::Content => {
            const WRAPPER_START: &str = "<xmlsec-content>";
            const WRAPPER_END: &str = "</xmlsec-content>";

            policy.resources.validate_xml_document_len(xml.len())?;
            let wrapped = format!("{WRAPPER_START}{xml}{WRAPPER_END}");
            let wrapper_bytes = WRAPPER_START.len() + WRAPPER_END.len();
            // The wrapper exists only to parse an XML fragment. Its node must
            // not consume the caller-owned byte, node, or depth allowance.
            let wrapped_settings = DocumentParseSettings {
                nodes_limit: settings.nodes_limit.saturating_add(1),
                depth_limit: settings.depth_limit.saturating_add(1),
                max_bytes: settings.max_bytes.saturating_add(wrapper_bytes),
                ..settings
            };
            parse_borrowed_with_settings_and_budget(&wrapped, wrapped_settings, Some(parse_budget))
                .map_err(|error| match error {
                    XmlDocumentError::DocumentTooLarge { actual, .. } => {
                        XmlEncError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                            resource: crate::policy::resource_name::XML_DOCUMENT,
                            maximum: settings.max_bytes,
                            actual: actual.saturating_sub(wrapper_bytes),
                        })
                    }
                    XmlDocumentError::Parse(crate::xml::dom::ParseError::NodesLimitReached) => {
                        XmlEncError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                            resource: crate::policy::resource_name::XML_NODES,
                            maximum: settings.nodes_limit as usize,
                            actual: settings.nodes_limit as usize + 1,
                        })
                    }
                    XmlDocumentError::DocumentTooDeep { actual, .. } => {
                        XmlEncError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                            resource: crate::policy::resource_name::XML_DEPTH,
                            maximum: settings.depth_limit,
                            actual: actual.saturating_sub(1),
                        })
                    }
                    error => map_document_error(error, wrapped_settings),
                })?;
            Ok(())
        }
        EncryptedDataType::Other(_) => Err(XmlEncError::InvalidEncryptionConfig(
            "encrypt_xml requires Element or Content Type".into(),
        )),
    }
}

fn select_encryption_target<'a, 'input>(
    document: &'a Document<'input>,
    id: Option<&str>,
) -> Result<Node<'a, 'input>, XmlEncError> {
    let Some(id) = id else {
        return Ok(document.root_element());
    };
    let mut matches = document.descendants().filter(|node| {
        node.is_element()
            && ["Id", "ID", "id"]
                .iter()
                .any(|name| node.attribute(*name) == Some(id))
    });
    let selected = matches
        .next()
        .ok_or(XmlEncError::EncryptionTargetNotFound)?;
    if matches.next().is_some() {
        return Err(XmlEncError::AmbiguousEncryptionTarget);
    }
    Ok(selected)
}

fn element_content_boundaries(source: &str) -> Result<ContentBoundaries, XmlEncError> {
    let tag_end = find_start_tag_end(source)?;
    let before_end = source[..tag_end].trim_end_matches(XML_WHITESPACE);
    let self_closing = before_end.ends_with('/');
    let name_end = source[1..]
        .find(|character: char| character.is_ascii_whitespace() || matches!(character, '/' | '>'))
        .map(|index| index + 1)
        .ok_or_else(|| XmlEncError::InvalidStructure("source element has no name".into()))?;
    let qualified_name = source[1..name_end].to_owned();
    if self_closing {
        return Ok(ContentBoundaries {
            content: tag_end..tag_end,
            self_closing: true,
            qualified_name,
            start_tag_end: tag_end,
        });
    }
    // `Node::range()` ends at this element's closing tag, so its `</` marker is
    // necessarily the final one even when child text or CDATA contains `</`.
    let closing_start = source
        .rfind("</")
        .ok_or_else(|| XmlEncError::InvalidStructure("source element has no closing tag".into()))?;
    Ok(ContentBoundaries {
        content: tag_end + 1..closing_start,
        self_closing: false,
        qualified_name,
        start_tag_end: tag_end,
    })
}

fn find_start_tag_end(source: &str) -> Result<usize, XmlEncError> {
    let mut quote = None;
    for (index, character) in source.char_indices() {
        match (quote, character) {
            (Some(expected), actual) if expected == actual => quote = None,
            (None, '\'' | '"') => quote = Some(character),
            (None, '>') => return Ok(index),
            _ => {}
        }
    }
    Err(XmlEncError::InvalidStructure(
        "source element start tag is unterminated".into(),
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use std::sync::Arc;

    use getrandom::SysRng;
    use getrandom::rand_core::UnwrapErr;
    use rsa::pkcs8::DecodePublicKey as _;
    use rsa::{RsaPrivateKey, RsaPublicKey};

    use super::*;
    use crate::hard_limits::{
        ENCRYPTION_METADATA_BYTE_CEILING as MAX_ENCRYPTION_METADATA_LEN,
        ENCRYPTION_PLAINTEXT_BYTE_CEILING as MAX_ENCRYPTION_PLAINTEXT_LEN,
        ENCRYPTION_RECIPIENT_CEILING as MAX_ENCRYPTION_RECIPIENTS,
        XML_DOCUMENT_BYTE_CEILING as MAX_ENCRYPTION_DOCUMENT_LEN,
    };
    use crate::xmlenc::{
        KekDecryptor, OaepDigestAlgorithm, PrivateKeyDecryptor, SymmetricKeyDecryptor, decrypt,
        decrypt_document, parse_encrypted_data,
    };

    #[derive(Debug)]
    struct OverridingOutputProvider {
        ciphertext: Option<Vec<u8>>,
        wrapped_key: Option<Vec<u8>>,
        transported_key: Option<Vec<u8>>,
        transport_calls: AtomicUsize,
    }

    struct OpaqueTransportKey {
        modulus: Vec<u8>,
        exponent: Vec<u8>,
    }

    impl crate::provider::KeyTransportKey for OpaqueTransportKey {
        fn rsa_modulus(&self) -> std::borrow::Cow<'_, [u8]> {
            std::borrow::Cow::Borrowed(&self.modulus)
        }

        fn rsa_exponent(&self) -> std::borrow::Cow<'_, [u8]> {
            std::borrow::Cow::Borrowed(&self.exponent)
        }

        fn transport_with_provider(
            &self,
            _provider: &dyn crate::provider::CryptoProvider,
            _parameters: &RsaOaepParameters,
            _plaintext: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            panic!("custom provider must own transport for its opaque key")
        }
    }

    impl crate::provider::CryptoProvider for OverridingOutputProvider {
        fn name(&self) -> &'static str {
            "overriding-output-test"
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
            if let Some(ciphertext) = &self.ciphertext {
                return Ok(ciphertext.clone());
            }
            crate::provider::CryptoProvider::encrypt_data(
                &crate::provider::RustCryptoProvider,
                algorithm,
                key,
                plaintext,
            )
        }

        fn decrypt_data(
            &self,
            algorithm: DataEncryptionAlgorithm,
            key: &[u8],
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            crate::provider::CryptoProvider::decrypt_data(
                &crate::provider::RustCryptoProvider,
                algorithm,
                key,
                ciphertext,
            )
        }

        fn wrap_key(
            &self,
            algorithm: KeyWrapAlgorithm,
            kek: &[u8],
            key: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            if let Some(wrapped_key) = &self.wrapped_key {
                return Ok(wrapped_key.clone());
            }
            crate::provider::CryptoProvider::wrap_key(
                &crate::provider::RustCryptoProvider,
                algorithm,
                kek,
                key,
            )
        }

        fn unwrap_key(
            &self,
            algorithm: KeyWrapAlgorithm,
            kek: &[u8],
            wrapped: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            crate::provider::CryptoProvider::unwrap_key(
                &crate::provider::RustCryptoProvider,
                algorithm,
                kek,
                wrapped,
            )
        }

        fn transport_key(
            &self,
            key: &dyn crate::provider::KeyTransportKey,
            parameters: &RsaOaepParameters,
            plaintext: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            self.transport_calls.fetch_add(1, Ordering::Relaxed);
            if let Some(transported_key) = &self.transported_key {
                return Ok(transported_key.clone());
            }
            crate::provider::CryptoProvider::transport_key(
                &crate::provider::RustCryptoProvider,
                key,
                parameters,
                plaintext,
            )
        }

        fn recover_key(
            &self,
            key: &dyn crate::provider::KeyRecoveryKey,
            parameters: &RsaOaepParameters,
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            crate::provider::CryptoProvider::recover_key(
                &crate::provider::RustCryptoProvider,
                key,
                parameters,
                ciphertext,
            )
        }
    }

    #[test]
    fn direct_key_round_trips_every_content_algorithm() {
        // All emitted wire layouts must be accepted by the existing independent
        // decrypt path, including empty plaintext and full-block CBC padding.
        for algorithm in [
            DataEncryptionAlgorithm::Aes128Cbc,
            DataEncryptionAlgorithm::Aes256Cbc,
            DataEncryptionAlgorithm::Aes128Gcm,
            DataEncryptionAlgorithm::Aes256Gcm,
        ] {
            for plaintext in [b"".as_slice(), b"sixteen-byte-msg", b"not aligned"] {
                let key = vec![0x31; algorithm.key_len()];
                let encrypted = EncryptedDataBuilder::new(algorithm)
                    .direct_key(key.clone())
                    .direct_key_name("content-key")
                    .encrypt_binary(plaintext)
                    .expect("supported direct encryption must succeed");
                assert_eq!(
                    decrypt(
                        &encrypted.encrypted_data_xml,
                        &SymmetricKeyDecryptor::new(key)
                    )
                    .expect("generated ciphertext must decrypt"),
                    super::super::DecryptedContent::Bytes(plaintext.to_vec())
                );
            }
        }
    }

    #[test]
    fn aes_key_wrap_round_trips_and_preserves_recipient_metadata() {
        let kek = [0x44; 32];
        let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .add_recipient(
                EncryptionRecipient::aes_key_wrap(kek, KeyWrapAlgorithm::AesKw256)
                    .recipient("service-a")
                    .key_name("shared-kek"),
            )
            .encrypt_xml("<secret>value</secret>")
            .expect("AES-KW encryption must succeed");
        let parsed = parse_encrypted_data(&encrypted.encrypted_data_xml)
            .expect("generated EncryptedData must parse");
        assert_eq!(
            parsed.encrypted_keys[0].recipient.as_deref(),
            Some("service-a")
        );
        assert_eq!(
            parsed.encrypted_keys[0].key_name.as_deref(),
            Some("shared-kek")
        );
        assert_eq!(
            decrypt(&encrypted.encrypted_data_xml, &KekDecryptor::new(kek))
                .expect("wrapped key must decrypt"),
            super::super::DecryptedContent::Xml("<secret>value</secret>".into())
        );
    }

    #[test]
    fn aes_key_wrap_rejects_mismatched_kek_before_provider_dispatch() {
        // Algorithm URIs define the KEK size. Provider implementations are
        // capabilities, not authorities allowed to reinterpret wire semantics.
        let builder = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .recipient_aes_kw([0x44; 32], KeyWrapAlgorithm::AesKw128);

        assert!(matches!(
            builder.validate_configuration(),
            Err(XmlEncError::InvalidEncryptionConfig(_))
        ));
    }

    #[test]
    fn rsa_oaep_round_trips_configurable_parameters() {
        let private = RsaPrivateKey::new(&mut UnwrapErr(SysRng), 2048)
            .expect("test RSA key generation must succeed");
        let public = RsaPublicKey::from(&private);
        let parameters =
            RsaOaepParameters::xmlenc11(OaepDigestAlgorithm::Sha256, OaepDigestAlgorithm::Sha512)
                .label(b"recipient-label".to_vec());
        let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes256Gcm)
            .add_recipient(
                EncryptionRecipient::rsa_oaep(public)
                    .oaep_parameters(parameters)
                    .recipient("rsa-recipient"),
            )
            .encrypt_xml("<secret/>")
            .expect("RSA-OAEP encryption must succeed");
        assert_eq!(
            decrypt(
                &encrypted.encrypted_data_xml,
                &PrivateKeyDecryptor::new(private)
            )
            .expect("RSA recipient must recover content key"),
            super::super::DecryptedContent::Xml("<secret/>".into())
        );
    }

    #[test]
    fn legacy_oaep_rejects_non_sha1_mgf_during_configuration_validation() {
        // The legacy URI has no MGF child on the wire, so accepting another
        // digest here would let a permissive provider emit ambiguous ciphertext.
        let public = RsaPublicKey::from_public_key_pem(include_str!(
            "../../tests/fixtures/keys/rsa/rsa-2048-pubkey.pem"
        ))
        .expect("tracked RSA public key must parse");
        let parameters = RsaOaepParameters {
            algorithm: super::super::KeyTransportAlgorithm::RsaOaepMgf1p,
            digest: OaepDigestAlgorithm::Sha256,
            mgf_digest: OaepDigestAlgorithm::Sha256,
            label: Vec::new(),
        };
        let builder = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .add_recipient(EncryptionRecipient::rsa_oaep(public).oaep_parameters(parameters));

        assert!(matches!(
            builder.validate_configuration(),
            Err(XmlEncError::InvalidEncryptionConfig(_))
        ));
    }

    #[test]
    fn encrypt_document_replaces_element_and_self_closing_content() {
        let key = [0x55; 16];
        let document =
            "<root><target ID=\"element\"><child/></target><empty ID=\"content\"/></root>";
        let encrypted_element = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .direct_key(key)
            .encrypt_document(
                document,
                DocumentEncryptionOptions {
                    element_id: Some("element"),
                },
            )
            .expect("element replacement must succeed");
        let decrypted_element =
            decrypt_document(&encrypted_element, None, &SymmetricKeyDecryptor::new(key))
                .expect("element replacement must round-trip");
        assert_eq!(decrypted_element, document);

        let encrypted_content = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .encryption_type(EncryptedDataType::Content)
            .direct_key(key)
            .encrypt_document(
                document,
                DocumentEncryptionOptions {
                    element_id: Some("content"),
                },
            )
            .expect("self-closing content replacement must expand the element");
        assert!(encrypted_content.contains("<empty ID=\"content\"><xenc:EncryptedData"));
        let decrypted_content =
            decrypt_document(&encrypted_content, None, &SymmetricKeyDecryptor::new(key))
                .expect("empty content must decrypt");
        assert_eq!(
            decrypted_content,
            "<root><target ID=\"element\"><child/></target><empty ID=\"content\"></empty></root>"
        );
    }

    #[test]
    fn invalid_configuration_and_bounds_fail_before_encryption() {
        let no_key = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .encrypt_binary(b"data")
            .expect_err("missing key source must fail");
        assert!(matches!(no_key, XmlEncError::InvalidEncryptionConfig(_)));

        assert!(
            validate_plaintext_len(MAX_ENCRYPTION_PLAINTEXT_LEN, MAX_ENCRYPTION_PLAINTEXT_LEN,)
                .is_ok()
        );
        assert!(matches!(
            validate_plaintext_len(
                MAX_ENCRYPTION_PLAINTEXT_LEN + 1,
                MAX_ENCRYPTION_PLAINTEXT_LEN,
            ),
            Err(XmlEncError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::ENCRYPTION_PLAINTEXT_BYTES,
                    ..
                }
            ))
        ));

        assert!(matches!(
            EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                .direct_key([0_u8; 15])
                .encrypt_binary(b"data"),
            Err(XmlEncError::InvalidKeySize { .. })
        ));

        let too_many_recipients = (0..=MAX_ENCRYPTION_RECIPIENTS).fold(
            EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm),
            |builder, _| builder.recipient_aes_kw([0_u8; 16], KeyWrapAlgorithm::AesKw128),
        );
        assert!(matches!(
            too_many_recipients.encrypt_binary(b"data"),
            Err(XmlEncError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::ENCRYPTION_RECIPIENTS,
                    ..
                }
            ))
        ));

        let oversized_metadata = "x".repeat(MAX_ENCRYPTION_METADATA_LEN + 1);
        assert!(matches!(
            EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                .direct_key([0_u8; 16])
                .id(oversized_metadata)
                .encrypt_binary(b"data"),
            Err(XmlEncError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::ENCRYPTION_METADATA_BYTES,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn oversized_xml_is_rejected_before_parsing() {
        // The input bound protects the parser and the Content wrapper
        // allocation, so size must take precedence over malformed XML.
        let oversized_malformed = format!(
            "<child>{}</unclosed>",
            "x".repeat(MAX_ENCRYPTION_PLAINTEXT_LEN)
        );

        assert!(matches!(
            EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                .encryption_type(EncryptedDataType::Content)
                .direct_key([0_u8; 16])
                .encrypt_xml(&oversized_malformed),
            Err(XmlEncError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::ENCRYPTION_PLAINTEXT_BYTES,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn oversized_document_is_rejected_before_parsing() {
        // The document API has a separate parser-input bound because the
        // selected plaintext may be much smaller than its enclosing document.
        let oversized_malformed = format!(
            "<root>{}</unclosed>",
            "x".repeat(MAX_ENCRYPTION_DOCUMENT_LEN)
        );

        assert!(matches!(
            EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                .direct_key([0_u8; 16])
                .encrypt_document(&oversized_malformed, DocumentEncryptionOptions::default()),
            Err(XmlEncError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_DOCUMENT,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn encrypted_replacement_must_fit_document_policy() {
        // Cipher framing, base64, and EncryptedData markup expand the selected
        // range; the returned document must remain valid input to decryption.
        for encrypted_type in [EncryptedDataType::Element, EncryptedDataType::Content] {
            let document = "<root><target ID=\"selected\">x</target></root>";
            let policy = crate::policy::EncryptionPolicy {
                resources: crate::policy::ResourcePolicy {
                    max_xml_document_bytes: document.len(),
                    ..crate::policy::ResourcePolicy::default()
                },
                ..crate::policy::EncryptionPolicy::default()
            };

            assert!(matches!(
                EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                    .encryption_type(encrypted_type)
                    .direct_key([0_u8; 16])
                    .policy(policy)
                    .encrypt_document(
                        document,
                        DocumentEncryptionOptions {
                            element_id: Some("selected"),
                        },
                    ),
                Err(XmlEncError::Policy(
                    crate::policy::PolicyViolation::ResourceLimit {
                        resource: crate::policy::resource_name::XML_DOCUMENT,
                        ..
                    }
                ))
            ));
        }
    }

    #[test]
    fn binary_encryption_preserves_an_opaque_type_hint() {
        // A non-XML Type URI describes opaque application bytes. It must survive
        // binary encryption so decryption can continue returning byte content.
        let result = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .encryption_type(EncryptedDataType::Other("urn:example:binary".into()))
            .direct_key([0x42_u8; 16])
            .encrypt_binary(b"opaque payload")
            .expect("opaque binary Type must be accepted");

        assert!(
            result
                .encrypted_data_xml
                .contains("Type=\"urn:example:binary\"")
        );
    }

    #[test]
    fn binary_encryption_bounds_an_opaque_type_hint() {
        // Generated metadata must obey the same policy as reciprocal parsing so
        // the builder cannot emit an EncryptedData document it would reject.
        let maximum = 64;
        let policy = crate::policy::EncryptionPolicy {
            resources: crate::policy::ResourcePolicy {
                max_encryption_metadata_bytes: maximum,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::EncryptionPolicy::default()
        };
        let encrypt = |uri: String| {
            EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                .encryption_type(EncryptedDataType::Other(uri))
                .direct_key([0x42_u8; 16])
                .policy(policy.clone())
                .encrypt_binary(b"opaque payload")
        };

        encrypt(format!("urn:{}", "x".repeat(maximum - 4)))
            .expect("metadata at the configured boundary must remain accepted");
        assert!(matches!(
            encrypt(format!("urn:{}", "x".repeat(maximum - 3))),
            Err(XmlEncError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::ENCRYPTION_METADATA_BYTES,
                    maximum: 64,
                    actual: 65,
                }
            ))
        ));
    }

    #[test]
    fn encryption_policy_bounds_xml_nodes_at_both_parse_entry_points() {
        // XML plaintext and whole-document encryption are separate parser paths;
        // both must consume the same immutable operation-policy node ceiling.
        let policy = crate::policy::EncryptionPolicy {
            resources: crate::policy::ResourcePolicy {
                max_xml_nodes: 4,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::EncryptionPolicy::default()
        };
        let builder = || {
            EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                .direct_key([0_u8; 16])
                .policy(policy.clone())
        };
        let xml = "<root><a/><b/><c/><d/></root>";

        assert!(matches!(
            builder().encrypt_xml(xml),
            Err(XmlEncError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_NODES,
                    maximum: 4,
                    actual: 5,
                }
            ))
        ));
        assert!(matches!(
            builder().encrypt_document(xml, DocumentEncryptionOptions::default()),
            Err(XmlEncError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_NODES,
                    maximum: 4,
                    actual: 5,
                }
            ))
        ));
    }

    #[test]
    fn encryption_entry_points_enforce_policy_depth() {
        // Whole-document encryption must apply the same depth policy to string
        // and retained inputs before target selection or encryption work.
        let xml = "<root><child><leaf/></child></root>";
        let policy = crate::policy::EncryptionPolicy {
            resources: crate::policy::ResourcePolicy {
                max_xml_depth: 2,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::EncryptionPolicy::default()
        };
        let builder = || {
            EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                .direct_key([0_u8; 16])
                .policy(policy.clone())
        };
        let mut document = XmlDocument::parse(xml).expect("wide retained fixture must parse");

        assert!(matches!(
            builder().encrypt_document(xml, DocumentEncryptionOptions::default()),
            Err(XmlEncError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_DEPTH,
                    maximum: 2,
                    actual: 3,
                }
            ))
        ));
        assert!(matches!(
            builder().encrypt_owned_document(&mut document, DocumentEncryptionOptions::default()),
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
    fn encryption_plaintext_and_owned_mutations_use_the_active_depth() {
        // A document parsed under broad defaults must not retain those defaults
        // when a stricter encryption operation parses or commits replacement XML.
        let policy = crate::policy::EncryptionPolicy {
            resources: crate::policy::ResourcePolicy {
                max_xml_depth: 1,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::EncryptionPolicy::default()
        };
        let builder = || {
            EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                .direct_key([0_u8; 16])
                .policy(policy.clone())
        };

        assert!(matches!(
            builder().encrypt_xml("<root><child/></root>"),
            Err(XmlEncError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_DEPTH,
                    maximum: 1,
                    actual: 2,
                }
            ))
        ));

        let generated = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .direct_key([0_u8; 16])
            .encryption_type(EncryptedDataType::Content)
            .encrypt_xml("")
            .expect("generated content replacement must parse");
        let generated_document = Document::parse(&generated.encrypted_data_xml)
            .expect("generated replacement must be XML");
        let generated_depth = generated_document
            .descendants()
            .filter(|node| node.is_element())
            .map(|node| {
                node.ancestors()
                    .filter(|ancestor| ancestor.is_element())
                    .count()
            })
            .max()
            .expect("generated replacement has elements");
        let mutation_policy = crate::policy::EncryptionPolicy {
            resources: crate::policy::ResourcePolicy {
                max_xml_depth: generated_depth,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::EncryptionPolicy::default()
        };
        let mut document = XmlDocument::parse("<root/>").expect("shallow fixture must parse");
        let original = document.as_xml().to_owned();
        let generation = document.generation();
        assert!(matches!(
            EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                .direct_key([0_u8; 16])
                .encryption_type(EncryptedDataType::Content)
                .policy(mutation_policy)
                .encrypt_owned_document(&mut document, DocumentEncryptionOptions::default()),
            Err(XmlEncError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_DEPTH,
                    maximum,
                    actual,
                }
            )) if maximum == generated_depth && actual == generated_depth + 1
        ));
        assert_eq!(document.as_xml(), original);
        assert_eq!(document.generation(), generation);
    }

    #[test]
    fn owned_encryption_checks_active_node_limit_before_target_selection() {
        // A missing selector must not bypass the active policy or make target
        // discovery traverse a retained document parsed under a wider ceiling.
        let policy = crate::policy::EncryptionPolicy {
            resources: crate::policy::ResourcePolicy {
                max_xml_nodes: 1,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::EncryptionPolicy::default()
        };
        let mut document = XmlDocument::parse("<root><first/><second/></root>")
            .expect("retained fixture must parse");
        let before = document.as_xml().to_owned();

        let error = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .direct_key([0_u8; 16])
            .policy(policy)
            .encrypt_owned_document(
                &mut document,
                DocumentEncryptionOptions {
                    element_id: Some("missing"),
                },
            )
            .expect_err("active node ceiling must precede target selection");

        assert!(matches!(
            error,
            XmlEncError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_NODES,
                maximum: 1,
                actual,
            }) if actual > 1
        ));
        assert_eq!(document.as_xml(), before);
        assert_eq!(document.generation(), 0);
    }

    #[test]
    fn document_encryption_initial_parse_uses_the_policy_work_budget() {
        // Parsing the caller's XML and parsing the encrypted replacement must
        // consume one operation-wide allowance rather than independent caps.
        let xml = "<root/>";
        let policy = crate::policy::EncryptionPolicy {
            resources: crate::policy::ResourcePolicy {
                max_xml_parse_work_bytes: 0,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::EncryptionPolicy::default()
        };

        let error = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .direct_key([0_u8; 16])
            .policy(policy)
            .encrypt_document(xml, DocumentEncryptionOptions::default())
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

    #[test]
    fn content_plaintext_node_limit_excludes_the_internal_wrapper() {
        let policy = |max_xml_nodes| crate::policy::EncryptionPolicy {
            resources: crate::policy::ResourcePolicy {
                max_xml_nodes,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::EncryptionPolicy::default()
        };

        let policy_three = policy(3);
        let budget_three = XmlParseWorkBudget::from_resources(&policy_three.resources);
        validate_xml_plaintext(
            "<first/><second/>",
            &EncryptedDataType::Content,
            &policy_three,
            &budget_three,
            crate::XmlBackend::default(),
        )
        .expect("the caller root and two elements must fit a three-node policy");
        let policy_two = policy(2);
        let budget_two = XmlParseWorkBudget::from_resources(&policy_two.resources);
        assert!(matches!(
            validate_xml_plaintext(
                "<first/><second/>",
                &EncryptedDataType::Content,
                &policy_two,
                &budget_two,
                crate::XmlBackend::default(),
            ),
            Err(XmlEncError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_NODES,
                    maximum: 2,
                    actual: 3,
                }
            ))
        ));
    }

    #[test]
    fn content_plaintext_byte_limit_excludes_only_the_internal_wrapper() {
        // The parser-only wrapper must not replace the caller's byte ceiling.
        // Encryption plaintext may be larger than the XML input policy, but an
        // XML Content fragment still has to satisfy both limits before parsing.
        let xml = "<first/><second/>";
        let maximum = xml.len() - 1;
        let policy = crate::policy::EncryptionPolicy {
            resources: crate::policy::ResourcePolicy {
                max_xml_document_bytes: maximum,
                max_encryption_plaintext_bytes: xml.len(),
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::EncryptionPolicy::default()
        };
        let budget = XmlParseWorkBudget::from_resources(&policy.resources);

        assert!(matches!(
            validate_xml_plaintext(
                xml,
                &EncryptedDataType::Content,
                &policy,
                &budget,
                crate::XmlBackend::default(),
            ),
            Err(XmlEncError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_DOCUMENT,
                    maximum: observed_maximum,
                    actual,
                }
            )) if observed_maximum == maximum && actual == xml.len()
        ));
        assert_eq!(
            budget.consumed(),
            0,
            "oversized XML must fail before parsing"
        );
    }

    #[test]
    fn generated_encrypted_data_parse_uses_the_active_node_limit() {
        // Generated XML is still operation work: reject it in the parser under
        // the active policy rather than allocating up to the absolute ceiling.
        let xml = "<EncryptedData><CipherData><CipherValue>AA==</CipherValue></CipherData></EncryptedData>";
        let policy = crate::policy::EncryptionPolicy {
            resources: crate::policy::ResourcePolicy {
                max_xml_nodes: 1,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::EncryptionPolicy::default()
        };
        let budget = XmlParseWorkBudget::from_resources(&policy.resources);

        assert!(matches!(
            count_generated_encrypted_data_nodes(
                xml,
                &policy,
                &budget,
                crate::XmlBackend::default(),
            ),
            Err(XmlEncError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::XML_NODES,
                    maximum: 1,
                    actual: 2,
                }
            ))
        ));
    }

    #[test]
    fn document_encryption_bounds_projected_replacement_nodes() {
        fn policy(max_xml_nodes: usize) -> crate::policy::EncryptionPolicy {
            crate::policy::EncryptionPolicy {
                resources: crate::policy::ResourcePolicy {
                    max_xml_nodes,
                    ..crate::policy::ResourcePolicy::default()
                },
                ..crate::policy::EncryptionPolicy::default()
            }
        }

        let generated_nodes = {
            let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                .direct_key([0_u8; 16])
                .encrypt_binary(b"payload")
                .expect("default policy must permit generated EncryptedData");
            Document::parse(&encrypted.encrypted_data_xml)
                .expect("generated EncryptedData must parse")
                .root_element()
                .descendants()
                .count()
        };

        // The source document fits the low limit, but the generated
        // EncryptedData replacement does not. The ceiling admits the standalone
        // fragment so this specifically exercises whole-document projection.
        let element_actual = match EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .direct_key([0_u8; 16])
            .policy(policy(generated_nodes))
            .encrypt_document("<root/>", DocumentEncryptionOptions::default())
        {
            Err(XmlEncError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: "XML nodes",
                maximum,
                actual,
            })) if maximum == generated_nodes && actual > maximum => actual,
            result => panic!("expected projected element node bound, got {result:?}"),
        };
        EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .direct_key([0_u8; 16])
            .policy(policy(element_actual))
            .encrypt_document("<root/>", DocumentEncryptionOptions::default())
            .expect("the exact projected element node limit must be accepted");

        // Content replacement retains the selected element. In particular, a
        // self-closing element expands around EncryptedData without adding an
        // extra source node to the projection.
        let content_actual = match EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .encryption_type(EncryptedDataType::Content)
            .direct_key([0_u8; 16])
            .policy(policy(generated_nodes))
            .encrypt_document("<root/>", DocumentEncryptionOptions::default())
        {
            Err(XmlEncError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: "XML nodes",
                maximum,
                actual,
            })) if maximum == generated_nodes && actual > maximum => actual,
            result => panic!("expected projected content node bound, got {result:?}"),
        };
        EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .encryption_type(EncryptedDataType::Content)
            .direct_key([0_u8; 16])
            .policy(policy(content_actual))
            .encrypt_document("<root/>", DocumentEncryptionOptions::default())
            .expect("the exact projected content node limit must be accepted");
    }

    #[test]
    fn standalone_encryption_bounds_generated_xml_nodes() {
        fn policy(max_xml_nodes: usize) -> crate::policy::EncryptionPolicy {
            crate::policy::EncryptionPolicy {
                resources: crate::policy::ResourcePolicy {
                    max_xml_nodes,
                    ..crate::policy::ResourcePolicy::default()
                },
                ..crate::policy::EncryptionPolicy::default()
            }
        }

        // Binary encryption has no input XML tree, but its generated EncryptedData
        // must still be consumable under the same operation-policy node ceiling.
        assert!(matches!(
            EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                .direct_key([0_u8; 16])
                .policy(policy(1))
                .encrypt_binary(b"payload"),
            Err(XmlEncError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: "XML nodes",
                maximum: 1,
                actual,
            })) if actual > 1
        ));

        let generated = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .direct_key([0_u8; 16])
            .encrypt_binary(b"payload")
            .expect("default policy must permit generated EncryptedData");
        let document = Document::parse(&generated.encrypted_data_xml)
            .expect("generated EncryptedData must parse");
        let actual = document.root().descendants().count();
        assert!(matches!(
            EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                .direct_key([0_u8; 16])
                .policy(policy(actual - 1))
                .encrypt_binary(b"payload"),
            Err(XmlEncError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: "XML nodes",
                maximum,
                actual: reported,
            })) if maximum == actual - 1 && reported == actual
        ));
        let exact = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .direct_key([0_u8; 16])
            .policy(policy(actual))
            .encrypt_binary(b"payload")
            .expect("the exact generated node limit must be accepted");
        let exact_document =
            Document::parse(&exact.encrypted_data_xml).expect("exact-boundary output must parse");
        let decryption_policy = crate::policy::DecryptionPolicy {
            resources: crate::policy::ResourcePolicy {
                max_xml_nodes: actual,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::DecryptionPolicy::default()
        };
        super::super::parse::parse_encrypted_data_node_with_policy(
            exact_document.root_element(),
            &decryption_policy,
        )
        .expect("output accepted at the exact limit must be consumable at the same limit");
    }

    #[test]
    fn document_dtd_is_controlled_only_by_operation_policy() {
        // Parser behavior comes from the immutable operation snapshot; target
        // selection options cannot independently weaken or tighten it.
        let document = "<!DOCTYPE root [<!ELEMENT root ANY>]><root/>";
        assert!(matches!(
            EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                .direct_key([0_u8; 16])
                .encrypt_document(document, DocumentEncryptionOptions { element_id: None },),
            Err(XmlEncError::XmlParse(_))
        ));
        let mut policy = crate::policy::EncryptionPolicy::default();
        policy.xml.allow_internal_dtd = true;
        EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .direct_key([0_u8; 16])
            .policy(policy.clone())
            .encrypt_document(document, DocumentEncryptionOptions { element_id: None })
            .expect("the explicit operation policy should permit parsing");
    }

    #[test]
    fn invalid_resource_policy_is_rejected_at_every_entry_point() {
        // Entry points must reject an invalid snapshot before parsing or using
        // any caller-selected limit derived from it.
        let mut policy = crate::policy::EncryptionPolicy::default();
        policy.resources.max_encryption_plaintext_bytes =
            crate::hard_limits::ENCRYPTION_PLAINTEXT_BYTE_CEILING + 1;
        let builder = || {
            EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                .direct_key([0_u8; 16])
                .policy(policy.clone())
        };

        assert!(matches!(
            builder().encrypt_xml("<broken>"),
            Err(XmlEncError::Policy(_))
        ));
        assert!(matches!(
            builder().encrypt_binary(b"x"),
            Err(XmlEncError::Policy(_))
        ));
        assert!(matches!(
            builder().encrypt_document("<broken>", DocumentEncryptionOptions::default()),
            Err(XmlEncError::Policy(_))
        ));
    }

    #[test]
    fn standalone_encrypted_output_obeys_document_byte_ceiling() {
        // The returned fragment must remain admissible to the reciprocal parser;
        // plaintext bounds alone do not account for framing, base64, or markup.
        let policy = |maximum| crate::policy::EncryptionPolicy {
            resources: crate::policy::ResourcePolicy {
                max_xml_document_bytes: maximum,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::EncryptionPolicy::default()
        };

        let binary_len = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .direct_key([0_u8; 16])
            .encrypt_binary(b"bounded binary")
            .expect("baseline binary encryption must succeed")
            .encrypted_data_xml
            .len();
        assert!(matches!(
            EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                .direct_key([0_u8; 16])
                .policy(policy(binary_len - 1))
                .encrypt_binary(b"bounded binary"),
            Err(XmlEncError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_DOCUMENT,
                maximum,
                actual,
            }))
                if maximum == binary_len - 1 && actual == binary_len
        ));
        EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .direct_key([0_u8; 16])
            .policy(policy(binary_len))
            .encrypt_binary(b"bounded binary")
            .expect("the exact standalone binary output bound must be accepted");

        let xml_len = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .direct_key([0_u8; 16])
            .encrypt_xml("<secret>bounded XML</secret>")
            .expect("baseline XML encryption must succeed")
            .encrypted_data_xml
            .len();
        assert!(matches!(
            EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                .direct_key([0_u8; 16])
                .policy(policy(xml_len - 1))
                .encrypt_xml("<secret>bounded XML</secret>"),
            Err(XmlEncError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: crate::policy::resource_name::XML_DOCUMENT,
                maximum,
                actual,
            }))
                if maximum == xml_len - 1 && actual == xml_len
        ));
        EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .direct_key([0_u8; 16])
            .policy(policy(xml_len))
            .encrypt_xml("<secret>bounded XML</secret>")
            .expect("the exact standalone XML output bound must be accepted");
    }

    #[test]
    fn zero_resource_ceilings_allow_operations_that_consume_none() {
        // Zero is deny-all, not an invalid policy. Direct-key encryption has no
        // recipients, and an empty binary payload consumes no plaintext bytes.
        let policy = crate::policy::EncryptionPolicy {
            resources: crate::policy::ResourcePolicy {
                max_encryption_plaintext_bytes: 0,
                max_encryption_recipients: 0,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::EncryptionPolicy::default()
        };

        EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .direct_key([0_u8; 16])
            .policy(policy.clone())
            .encrypt_binary(&[])
            .expect("zero ceilings must allow resources the operation does not consume");

        assert!(matches!(
            EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                .direct_key([0_u8; 16])
                .policy(policy.clone())
                .encrypt_binary(b"x"),
            Err(XmlEncError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::ENCRYPTION_PLAINTEXT_BYTES,
                    maximum: 0,
                    actual: 1
                }
            ))
        ));
        assert!(matches!(
            EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                .recipient_aes_kw([0_u8; 16], KeyWrapAlgorithm::AesKw128)
                .policy(policy)
                .encrypt_binary(&[]),
            Err(XmlEncError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::ENCRYPTION_RECIPIENTS,
                    maximum: 0,
                    actual: 1,
                }
            ))
        ));
    }

    #[test]
    fn encryption_enforces_key_candidate_budget_before_inspection() {
        // Candidate accounting must reject configured keys before validating or
        // dispatching them, while accepting the exact operation-wide boundary.
        let deny_keys = crate::policy::EncryptionPolicy {
            resources: crate::policy::ResourcePolicy {
                max_key_candidates: 0,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::EncryptionPolicy::default()
        };

        for error in [
            EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                .direct_key([0_u8; 15])
                .policy(deny_keys.clone())
                .encrypt_binary(b"data")
                .expect_err("a direct key must consume one candidate"),
            EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                .recipient_aes_kw([0_u8; 15], KeyWrapAlgorithm::AesKw128)
                .policy(deny_keys)
                .encrypt_binary(b"data")
                .expect_err("a recipient key must consume one candidate"),
        ] {
            assert!(matches!(
                error,
                XmlEncError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::KEY_CANDIDATES,
                    maximum: 0,
                    actual: 1,
                })
            ));
        }

        let recipient =
            || EncryptionRecipient::aes_key_wrap([0_u8; 16], KeyWrapAlgorithm::AesKw128);
        let policy_with_candidate_limit = |maximum| crate::policy::EncryptionPolicy {
            resources: crate::policy::ResourcePolicy {
                max_key_candidates: maximum,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::EncryptionPolicy::default()
        };
        let builder = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .add_recipient(recipient())
            .add_recipient(recipient());

        assert!(matches!(
            builder
                .clone()
                .policy(policy_with_candidate_limit(1))
                .encrypt_binary(b"data"),
            Err(XmlEncError::Policy(
                crate::policy::PolicyViolation::ResourceLimit {
                    resource: crate::policy::resource_name::KEY_CANDIDATES,
                    maximum: 1,
                    actual: 2,
                }
            ))
        ));
        builder
            .policy(policy_with_candidate_limit(2))
            .encrypt_binary(b"data")
            .expect("the exact key-candidate boundary must be accepted");
    }

    #[test]
    fn element_plaintext_enforces_replacement_node_contract() {
        // Element ciphertext must be safe for the reciprocal document replacement:
        // boundary whitespace/comments are harmless, but processing instructions are not.
        let builder =
            EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm).direct_key([0_u8; 16]);
        builder
            .encrypt_xml("\n<!--before--><secret/><!--after-->\n")
            .expect("one element with boundary trivia must be accepted");

        assert!(matches!(
            builder.encrypt_xml("<?target value?><secret/>"),
            Err(XmlEncError::InvalidStructure(_))
        ));
    }

    #[test]
    fn empty_key_names_are_rejected_before_serialization() {
        // The reciprocal parser rejects empty KeyName elements, so encryption
        // must not emit output that its own decrypt pipeline cannot consume.
        assert!(matches!(
            EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                .direct_key([0_u8; 16])
                .direct_key_name("")
                .encrypt_binary(b"data"),
            Err(XmlEncError::InvalidEncryptionConfig(_))
        ));
        assert!(matches!(
            EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                .add_recipient(
                    EncryptionRecipient::aes_key_wrap([0_u8; 16], KeyWrapAlgorithm::AesKw128)
                        .key_name("")
                )
                .encrypt_binary(b"data"),
            Err(XmlEncError::InvalidEncryptionConfig(_))
        ));
    }

    #[test]
    fn xml_forbidden_metadata_characters_are_rejected() {
        // XML escaping cannot legalize forbidden XML 1.0 code points, so every
        // caller-controlled attribute/text path must fail before serialization.
        assert!(matches!(
            EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                .direct_key([0_u8; 16])
                .id("invalid\0id")
                .encrypt_binary(b"data"),
            Err(XmlEncError::InvalidEncryptionConfig(_))
        ));
        assert!(matches!(
            EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                .direct_key([0_u8; 16])
                .direct_key_name("invalid\0name")
                .encrypt_binary(b"data"),
            Err(XmlEncError::InvalidEncryptionConfig(_))
        ));
        assert!(matches!(
            EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                .add_recipient(
                    EncryptionRecipient::aes_key_wrap([0_u8; 16], KeyWrapAlgorithm::AesKw128)
                        .recipient("invalid\0recipient")
                )
                .encrypt_binary(b"data"),
            Err(XmlEncError::InvalidEncryptionConfig(_))
        ));
        assert!(matches!(
            EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                .add_recipient(
                    EncryptionRecipient::aes_key_wrap([0_u8; 16], KeyWrapAlgorithm::AesKw128)
                        .key_name("invalid\0name")
                )
                .encrypt_binary(b"data"),
            Err(XmlEncError::InvalidEncryptionConfig(_))
        ));
    }

    #[test]
    fn encrypted_data_id_must_be_an_xml_ncname() {
        // xsd:ID derives from NCName; escaping arbitrary attribute text cannot
        // make whitespace, a leading digit, or a colon schema-valid.
        for invalid in ["bad id", "1leading", "qualified:name", ""] {
            assert!(matches!(
                EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                    .direct_key([0_u8; 16])
                    .id(invalid)
                    .encrypt_binary(b"data"),
                Err(XmlEncError::InvalidEncryptionConfig(_))
            ));
        }

        EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .direct_key([0_u8; 16])
            .id("Δοκιμή")
            .encrypt_binary(b"data")
            .expect("Unicode XML NCNames must remain valid identifiers");
    }

    #[test]
    fn rejects_malformed_custom_provider_ciphertext_before_serialization() {
        // Providers supply primitives, but the facade owns the standard wire
        // contract and must not serialize output its own decryptor rejects.
        for (algorithm, ciphertext) in [
            (DataEncryptionAlgorithm::Aes128Gcm, vec![0_u8; 27]),
            (DataEncryptionAlgorithm::Aes128Cbc, vec![0_u8; 31]),
            (DataEncryptionAlgorithm::Aes256Cbc, vec![0_u8; 33]),
        ] {
            let error = EncryptedDataBuilder::new(algorithm)
                .provider(Arc::new(OverridingOutputProvider {
                    ciphertext: Some(ciphertext),
                    wrapped_key: None,
                    transported_key: None,
                    transport_calls: AtomicUsize::new(0),
                }))
                .direct_key(vec![0_u8; algorithm.key_len()])
                .encrypt_binary(b"data")
                .expect_err("malformed provider output must fail before XML serialization");
            assert!(matches!(
                error,
                XmlEncError::DataTooShort { .. } | XmlEncError::InvalidCbcCiphertextLength(_)
            ));
        }
    }

    #[test]
    fn rejects_overlong_custom_provider_ciphertext_before_serialization() {
        // Provider success cannot change the algorithm-defined relationship
        // between plaintext and ciphertext length.
        for (algorithm, expected, actual) in [
            (DataEncryptionAlgorithm::Aes128Gcm, 32, 33),
            (DataEncryptionAlgorithm::Aes128Cbc, 32, 48),
        ] {
            let error = EncryptedDataBuilder::new(algorithm)
                .provider(Arc::new(OverridingOutputProvider {
                    ciphertext: Some(vec![0_u8; actual]),
                    wrapped_key: None,
                    transported_key: None,
                    transport_calls: AtomicUsize::new(0),
                }))
                .direct_key(vec![0_u8; algorithm.key_len()])
                .encrypt_binary(b"data")
                .expect_err("overlong provider output must fail before XML serialization");
            assert!(matches!(
                error,
                XmlEncError::Provider(crate::provider::ProviderError::InvalidOutputSize {
                    operation: crate::provider::ProviderOperation::Encrypt,
                    expected: observed_expected,
                    actual: observed_actual,
                }) if observed_expected == expected && observed_actual == actual
            ));
        }
    }

    #[test]
    fn rejects_malformed_custom_provider_wrapped_keys_before_serialization() {
        // RFC 3394 adds exactly one 64-bit integrity block. Accepting any other
        // provider output would emit EncryptedKey data no recipient can unwrap.
        for wrapped_key in [vec![], vec![0_u8; 23], vec![0_u8; 25]] {
            let result = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                .provider(Arc::new(OverridingOutputProvider {
                    ciphertext: None,
                    wrapped_key: Some(wrapped_key),
                    transported_key: None,
                    transport_calls: AtomicUsize::new(0),
                }))
                .recipient_aes_kw([0_u8; 16], KeyWrapAlgorithm::AesKw128)
                .encrypt_binary(b"data");
            assert!(matches!(
                result,
                Err(XmlEncError::InvalidWrappedKeyLength { expected: 24, actual })
                    if actual != 24
            ));
        }

        EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .provider(Arc::new(OverridingOutputProvider {
                ciphertext: None,
                wrapped_key: Some(vec![0_u8; 24]),
                transported_key: None,
                transport_calls: AtomicUsize::new(0),
            }))
            .recipient_aes_kw([0_u8; 16], KeyWrapAlgorithm::AesKw128)
            .encrypt_binary(b"data")
            .expect("exact RFC 3394 wrapped-key length must remain accepted");
    }

    #[test]
    fn rejects_malformed_custom_provider_rsa_transport_before_serialization() {
        // RSA ciphertext is exactly one modulus wide. Enforcing that invariant
        // here prevents custom providers from emitting undecryptable XML.
        let private_key = RsaPrivateKey::new(&mut UnwrapErr(SysRng), 2048)
            .expect("RSA key generation should succeed");
        let public_key = RsaPublicKey::from(&private_key);
        for transported_key in [vec![], vec![0_u8; 255], vec![0_u8; 257]] {
            let result = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                .provider(Arc::new(OverridingOutputProvider {
                    ciphertext: None,
                    wrapped_key: None,
                    transported_key: Some(transported_key),
                    transport_calls: AtomicUsize::new(0),
                }))
                .recipient_rsa_oaep(public_key.clone())
                .encrypt_binary(b"data");
            assert!(matches!(
                result,
                Err(XmlEncError::InvalidWrappedKeyLength {
                    expected: 256,
                    actual,
                }) if actual != 256
            ));
        }

        EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .provider(Arc::new(OverridingOutputProvider {
                ciphertext: None,
                wrapped_key: None,
                transported_key: Some(vec![0_u8; 256]),
                transport_calls: AtomicUsize::new(0),
            }))
            .recipient_rsa_oaep(public_key)
            .encrypt_binary(b"data")
            .expect("modulus-sized RSA transport output must remain accepted");
    }

    #[test]
    fn custom_provider_encrypts_with_an_opaque_transport_key() {
        // The key exposes only public policy metadata. Successful encryption
        // proves orchestration never needs a concrete RustCrypto RSA object.
        let provider = Arc::new(OverridingOutputProvider {
            ciphertext: None,
            wrapped_key: None,
            transported_key: Some(vec![0x5a; 256]),
            transport_calls: AtomicUsize::new(0),
        });
        let key = Arc::new(OpaqueTransportKey {
            modulus: vec![0x80; 256],
            exponent: vec![0x01, 0x00, 0x01],
        });

        let encrypted = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .provider(provider.clone())
            .recipient_key_transport(key)
            .encrypt_binary(b"opaque provider key")
            .expect("custom provider must accept its opaque transport key");

        assert_eq!(provider.transport_calls.load(Ordering::Relaxed), 1);
        assert!(encrypted.encrypted_data_xml.contains("rsa-oaep"));
    }

    #[test]
    fn opaque_transport_preflight_rejects_weak_rsa_metadata() {
        // Provider-owned keys cannot bypass the same outbound RSA policy used
        // by the RustCrypto convenience constructor.
        let key = OpaqueTransportKey {
            modulus: vec![0x80; 128],
            exponent: vec![0x01, 0x00, 0x01],
        };
        assert!(matches!(
            validate_key_transport_recipient(&key, &crate::policy::EncryptionPolicy::default()),
            Err(XmlEncError::Policy(
                crate::policy::PolicyViolation::KeySize { .. }
            ))
        ));
    }

    #[test]
    fn encryption_policy_rejects_weak_rsa_recipient_before_provider_dispatch() {
        // Provider capability cannot weaken the outbound recipient-key policy.
        let private_key = RsaPrivateKey::new(&mut UnwrapErr(SysRng), 1024)
            .expect("test RSA key generation should succeed");
        let provider = Arc::new(OverridingOutputProvider {
            ciphertext: None,
            wrapped_key: None,
            transported_key: Some(vec![0_u8; 128]),
            transport_calls: AtomicUsize::new(0),
        });

        let result = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .provider(provider.clone())
            .recipient_rsa_oaep(RsaPublicKey::from(&private_key))
            .encrypt_binary(b"data");

        assert!(matches!(
            result,
            Err(XmlEncError::Policy(
                crate::policy::PolicyViolation::KeySize {
                    operation: "encryption",
                    minimum_bits: 2048,
                    maximum_bits: 8192,
                    actual_bits: 1024,
                    ..
                }
            ))
        ));
        assert_eq!(provider.transport_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn debug_output_redacts_symmetric_key_material() {
        let direct_key = b"direct-key-secret".to_vec();
        let kek = b"key-wrap-secret!".to_vec();
        let builder = EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
            .direct_key(direct_key.clone());
        let recipient = EncryptionRecipient::aes_key_wrap(kek.clone(), KeyWrapAlgorithm::AesKw128);

        let builder_debug = format!("{builder:?}");
        let recipient_debug = format!("{recipient:?}");
        assert!(builder_debug.contains("[REDACTED]"));
        assert!(recipient_debug.contains("[REDACTED]"));
        assert!(!builder_debug.contains(&format!("{direct_key:?}")));
        assert!(!recipient_debug.contains(&format!("{kek:?}")));
    }
}
