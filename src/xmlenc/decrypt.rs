//! XMLEnc decryption entry point and key resolvers.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use roxmltree::{Document, ParsingOptions};
use rsa::{RsaPrivateKey, traits::PublicKeyParts as _};

use super::parse::{
    parse_encrypted_data_node_with_policy, parse_encrypted_data_with_policy,
    validate_encrypted_data_metadata,
};
use super::types::{MAX_CIPHER_VALUE_BASE64_LEN, XMLENC_NS, validate_ciphertext_framing};
use super::{
    DataEncryptionAlgorithm, DecryptedContent, EncryptedData, EncryptedDataType, EncryptedKey,
    KeyTransportAlgorithm, KeyWrapAlgorithm, OaepDigestAlgorithm, RsaOaepParameters, XmlEncError,
    has_single_element_with_boundary_trivia,
};
use crate::xml::XmlIdIndex;

#[cfg(test)]
use super::parse_encrypted_data;

/// Aggregate key-candidate work allowance for one decryption operation.
///
/// Resolver implementations must consume one unit before each key lookup or
/// unwrap attempt. A single budget is shared across direct and recipient keys.
#[derive(Debug)]
pub struct DecryptionCandidateBudget {
    maximum: usize,
    remaining: usize,
}

impl DecryptionCandidateBudget {
    /// Create the fixed implementation-wide budget for one operation.
    pub fn for_operation() -> Self {
        let maximum = crate::hard_limits::DECRYPTION_KEY_CANDIDATE_CEILING;
        Self {
            maximum,
            remaining: maximum,
        }
    }

    /// Number of candidate attempts still available to this operation.
    pub const fn remaining(&self) -> usize {
        self.remaining
    }

    /// Charge attempted candidate work before performing it.
    pub fn consume(&mut self, count: usize, resource: &'static str) -> Result<(), XmlEncError> {
        if count > self.remaining {
            return Err(XmlEncError::DecryptionCandidateLimitExceeded {
                resource,
                maximum: self.maximum,
                actual: self
                    .maximum
                    .saturating_sub(self.remaining)
                    .saturating_add(count),
            });
        }
        self.remaining -= count;
        Ok(())
    }

    fn account_returned_candidates(
        &mut self,
        remaining_before: usize,
        returned: usize,
    ) -> Result<(), XmlEncError> {
        let resolver_charged = remaining_before.saturating_sub(self.remaining);
        self.consume(
            returned.saturating_sub(resolver_charged),
            "decryption key candidates",
        )
    }
}

/// Supplies a content-encryption key for parsed XMLEnc data.
pub trait DecryptionKeyResolver {
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
    /// did not explicitly charge.
    fn resolve_key_candidates(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
        budget: &mut DecryptionCandidateBudget,
    ) -> Result<Vec<Vec<u8>>, XmlEncError> {
        budget.consume(1, "decryption key candidates")?;
        self.resolve_key(provider, algorithm, encrypted_key)
            .map(|key| vec![key])
    }
}

/// XML parser controls for caller-owned document decryption.
#[derive(Debug, Clone, Copy, Default)]
pub struct DocumentDecryptionOptions<'a> {
    /// Select a specific `EncryptedData` by its `Id` attribute.
    pub encrypted_data_id: Option<&'a str>,
    /// Permit an internal DTD subset while parsing the caller's document.
    ///
    /// This is disabled by default. No external entity resolver is installed,
    /// so external resources are never loaded by this API.
    pub allow_dtd: bool,
}

/// Immutable XMLEnc decryption operation context.
pub struct DecryptContext<'a> {
    resolver: &'a dyn DecryptionKeyResolver,
    policy: crate::policy::DecryptionPolicy,
    provider: &'a dyn crate::provider::CryptoProvider,
    id_attributes: &'a [crate::IdAttributeRegistration],
}

impl<'a> DecryptContext<'a> {
    /// Create a context with compatibility defaults and the RustCrypto provider.
    pub fn new(resolver: &'a dyn DecryptionKeyResolver) -> Self {
        Self {
            resolver,
            policy: crate::policy::DecryptionPolicy::default(),
            provider: crate::provider::default_provider(),
            id_attributes: &[],
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

    /// Add caller-declared ID attributes for operation start-node lookup.
    pub fn id_attributes(mut self, registrations: &'a [crate::IdAttributeRegistration]) -> Self {
        self.id_attributes = registrations;
        self
    }

    /// Parse and decrypt a standalone `EncryptedData` XML fragment.
    pub fn decrypt(&self, xml: &str) -> Result<DecryptedContent, XmlEncError> {
        let encrypted = parse_encrypted_data_with_policy(xml, &self.policy)?;
        self.decrypt_data(&encrypted)
    }

    /// Decrypt an already parsed `EncryptedData` value.
    pub fn decrypt_data(&self, encrypted: &EncryptedData) -> Result<DecryptedContent, XmlEncError> {
        self.process_decryption_candidates(encrypted, Ok)
    }

    fn process_decryption_candidates<T>(
        &self,
        encrypted: &EncryptedData,
        mut accept: impl FnMut(DecryptedContent) -> Result<T, XmlEncError>,
    ) -> Result<T, XmlEncError> {
        self.policy.resources.validate()?;
        validate_encrypted_data_metadata(encrypted, &self.policy)?;
        encrypted.encryption_method.validate_structure()?;
        validate_recipient_count(
            encrypted.encrypted_keys.len(),
            self.policy.resources.max_encryption_recipients,
        )?;
        let algorithm = DataEncryptionAlgorithm::from_uri(&encrypted.encryption_method.algorithm)?;
        if self
            .policy
            .data_algorithms
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(&algorithm))
        {
            return Err(crate::policy::PolicyViolation::Algorithm {
                operation: "decryption",
                algorithm: encrypted.encryption_method.algorithm.clone(),
            }
            .into());
        }
        validate_typed_cipher_values(
            encrypted,
            algorithm,
            self.policy.resources.max_encryption_plaintext_bytes,
            self.policy.resources.max_xml_document_bytes,
        )?;
        let ciphertext = STANDARD
            .decode(&encrypted.cipher_data.value)
            .map_err(|error| XmlEncError::Base64(error.to_string()))?;
        validate_content_framing_before_resolution(
            algorithm,
            ciphertext.len(),
            &encrypted.encrypted_keys,
            &self.policy,
        )?;
        validate_possible_plaintext_len(
            algorithm,
            ciphertext.len(),
            self.policy.resources.max_encryption_plaintext_bytes,
        )?;
        let keys = resolve_content_key_candidates(
            self.provider,
            algorithm,
            encrypted,
            self.resolver,
            &self.policy,
        )?;
        let keys = compatible_decryption_key_candidates(algorithm, keys)?;
        validate_decryption_key_candidates(algorithm, keys.len())?;
        let mut last_error = None;
        for key in keys {
            let attempt = (|| {
                validate_key_len(algorithm, &key)?;
                let plaintext = self
                    .provider
                    .decrypt_data(algorithm, &key, &ciphertext)
                    .map_err(|error| {
                        map_data_decryption_error(algorithm, ciphertext.len(), error)
                    })?;
                validate_provider_plaintext_len(algorithm, ciphertext.len(), plaintext.len())?;
                validate_plaintext_len(
                    plaintext.len(),
                    self.policy.resources.max_encryption_plaintext_bytes,
                )?;
                match encrypted.encrypted_type.as_ref() {
                    Some(EncryptedDataType::Element | EncryptedDataType::Content) => {
                        Ok(DecryptedContent::Xml(String::from_utf8(plaintext)?))
                    }
                    Some(EncryptedDataType::Other(_)) | None => {
                        Ok(DecryptedContent::Bytes(plaintext))
                    }
                }
            })();
            match attempt {
                Ok(content) => match accept(content) {
                    Ok(result) => return Ok(result),
                    Err(error) => last_error = Some(error),
                },
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or(XmlEncError::KeyNotFound))
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

    /// Decrypt and replace the sole `EncryptedData` below an operation start
    /// node selected by ID.
    pub fn decrypt_document_from_start_node(
        &self,
        xml: &str,
        start_node_id: Option<&str>,
    ) -> Result<String, XmlEncError> {
        decrypt_document_with_context(
            xml,
            DocumentEncryptedDataSelector::StartNodeId(start_node_id),
            self,
        )
    }
}

/// Resolver for direct, pre-shared AES content keys.
#[derive(Clone)]
pub struct SymmetricKeyDecryptor {
    key: Vec<u8>,
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
    /// Create a direct symmetric-key resolver.
    pub fn new(key: impl Into<Vec<u8>>) -> Self {
        Self { key: key.into() }
    }
}

impl DecryptionKeyResolver for SymmetricKeyDecryptor {
    fn resolve_key(
        &self,
        _provider: &dyn crate::provider::CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        _encrypted_key: Option<&EncryptedKey>,
    ) -> Result<Vec<u8>, XmlEncError> {
        validate_key_len(algorithm, &self.key)?;
        Ok(self.key.clone())
    }
}

/// Resolver backed by an RSA private key for OAEP-wrapped session keys.
#[derive(Clone)]
pub struct PrivateKeyDecryptor {
    key: RsaPrivateKey,
}

/// Resolver backed by a pre-shared AES key-encryption key (KEK).
#[derive(Clone)]
pub struct KekDecryptor {
    kek: Vec<u8>,
}

impl fmt::Debug for KekDecryptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KekDecryptor")
            .field("kek", &"[REDACTED]")
            .finish()
    }
}

impl KekDecryptor {
    /// Create a resolver for RFC 3394 AES key-wrap `EncryptedKey` elements.
    pub fn new(kek: impl Into<Vec<u8>>) -> Self {
        Self { kek: kek.into() }
    }
}

impl DecryptionKeyResolver for KekDecryptor {
    fn resolve_key(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
    ) -> Result<Vec<u8>, XmlEncError> {
        let encrypted_key = encrypted_key.ok_or(XmlEncError::KeyNotFound)?;
        encrypted_key.encryption_method.validate_structure()?;
        let wrapped = STANDARD
            .decode(&encrypted_key.cipher_data.value)
            .map_err(|error| XmlEncError::Base64(error.to_string()))?;
        let wrap_algorithm =
            KeyWrapAlgorithm::from_uri(&encrypted_key.encryption_method.algorithm)?;
        let expected_kek_len = wrap_algorithm.key_len();
        if self.kek.len() != expected_kek_len {
            return Err(XmlEncError::InvalidKekSize {
                algorithm: wrap_algorithm,
                expected: expected_kek_len,
                actual: self.kek.len(),
            });
        }
        let expected_wrapped_len = algorithm.key_len() + 8;
        if wrapped.len() != expected_wrapped_len {
            return Err(XmlEncError::InvalidWrappedKeyLength {
                expected: expected_wrapped_len,
                actual: wrapped.len(),
            });
        }
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
        validate_key_len(algorithm, &key)?;
        Ok(key)
    }
}

impl PrivateKeyDecryptor {
    /// Create a resolver from an already-parsed RSA private key.
    pub fn new(key: RsaPrivateKey) -> Self {
        Self { key }
    }
}

impl DecryptionKeyResolver for PrivateKeyDecryptor {
    fn resolve_key(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
    ) -> Result<Vec<u8>, XmlEncError> {
        let encrypted_key = encrypted_key.ok_or(XmlEncError::KeyNotFound)?;
        encrypted_key.encryption_method.validate_structure()?;
        let wrapped = STANDARD
            .decode(&encrypted_key.cipher_data.value)
            .map_err(|error| XmlEncError::Base64(error.to_string()))?;
        let label = encrypted_key
            .encryption_method
            .oaep_params
            .clone()
            .unwrap_or_default();
        let transport =
            KeyTransportAlgorithm::from_uri(&encrypted_key.encryption_method.algorithm)?;
        let key = match transport {
            KeyTransportAlgorithm::RsaOaepMgf1p => self.decrypt_oaep_mgf1p(
                provider,
                encrypted_key.encryption_method.oaep_digest.as_deref(),
                label,
                &wrapped,
            ),
            KeyTransportAlgorithm::RsaOaep11 => self.decrypt_oaep11(
                provider,
                encrypted_key.encryption_method.oaep_digest.as_deref(),
                encrypted_key.encryption_method.mgf_algorithm.as_deref(),
                label,
                &wrapped,
            ),
        }?;
        validate_key_len(algorithm, &key)?;
        Ok(key)
    }
}

impl PrivateKeyDecryptor {
    fn decrypt_oaep_mgf1p(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        digest: Option<&str>,
        label: Vec<u8>,
        wrapped: &[u8],
    ) -> Result<Vec<u8>, XmlEncError> {
        let parameters = RsaOaepParameters {
            algorithm: KeyTransportAlgorithm::RsaOaepMgf1p,
            digest: parse_oaep_digest(digest)?,
            mgf_digest: OaepDigestAlgorithm::Sha1,
            label,
        };
        recover_rsa_oaep(provider, &self.key, &parameters, wrapped)
    }

    fn decrypt_oaep11(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        digest: Option<&str>,
        mgf: Option<&str>,
        label: Vec<u8>,
        wrapped: &[u8],
    ) -> Result<Vec<u8>, XmlEncError> {
        let parameters = RsaOaepParameters {
            algorithm: KeyTransportAlgorithm::RsaOaep11,
            digest: parse_oaep_digest(digest)?,
            mgf_digest: parse_oaep_mgf_digest(mgf)?,
            label,
        };
        recover_rsa_oaep(provider, &self.key, &parameters, wrapped)
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
    key: &RsaPrivateKey,
    parameters: &RsaOaepParameters,
    wrapped: &[u8],
) -> Result<Vec<u8>, XmlEncError> {
    let expected = key.size();
    if wrapped.len() != expected {
        return Err(XmlEncError::InvalidWrappedKeyLength {
            expected,
            actual: wrapped.len(),
        });
    }
    provider
        .recover_key(key, parameters, wrapped)
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
        DocumentDecryptionOptions {
            encrypted_data_id,
            allow_dtd: false,
        },
        resolver,
    )
}

/// Decrypt and replace one `EncryptedData` using explicit XML parser controls.
pub fn decrypt_document_with_options(
    xml: &str,
    options: DocumentDecryptionOptions<'_>,
    resolver: &dyn DecryptionKeyResolver,
) -> Result<String, XmlEncError> {
    let mut policy = crate::policy::DecryptionPolicy::default();
    policy.xml.allow_internal_dtd = options.allow_dtd;
    DecryptContext::new(resolver)
        .policy(policy)
        .decrypt_document(xml, options.encrypted_data_id)
}

#[derive(Clone, Copy)]
enum DocumentEncryptedDataSelector<'a> {
    EncryptedDataId(Option<&'a str>),
    StartNodeId(Option<&'a str>),
}

fn decrypt_document_with_context(
    xml: &str,
    selector: DocumentEncryptedDataSelector<'_>,
    context: &DecryptContext<'_>,
) -> Result<String, XmlEncError> {
    context.policy.resources.validate()?;
    validate_encryption_document_len(xml.len(), &context.policy)?;
    let parsing_options = || decryption_parsing_options(&context.policy);
    let document = Document::parse_with_options(xml, parsing_options())?;
    let start = match selector {
        DocumentEncryptedDataSelector::StartNodeId(Some(id)) => {
            XmlIdIndex::with_registrations(&document, context.id_attributes)
                .node(id)
                .ok_or_else(|| XmlEncError::SelectedNodeUnavailable { id: id.to_owned() })?
        }
        DocumentEncryptedDataSelector::StartNodeId(None)
        | DocumentEncryptedDataSelector::EncryptedDataId(_) => document.root(),
    };
    let encrypted_data_id = match selector {
        DocumentEncryptedDataSelector::EncryptedDataId(id) => id,
        DocumentEncryptedDataSelector::StartNodeId(_) => None,
    };
    let mut matches = start.descendants().filter(|node| {
        node.has_tag_name((XMLENC_NS, "EncryptedData"))
            && encrypted_data_id.is_none_or(|id| node.attribute("Id") == Some(id))
    });
    let selected = matches.next().ok_or(XmlEncError::EncryptedDataNotFound)?;
    if matches.next().is_some() {
        return Err(XmlEncError::AmbiguousEncryptedData);
    }

    let range = selected.range();
    let encrypted = parse_encrypted_data_node_with_policy(selected, &context.policy)?;
    context.process_decryption_candidates(&encrypted, |candidate| {
        replace_decrypted_content(
            xml,
            range.clone(),
            candidate,
            encrypted.encrypted_type.as_ref(),
            &context.policy,
        )
    })
}

fn replace_decrypted_content(
    xml: &str,
    range: std::ops::Range<usize>,
    content: DecryptedContent,
    encrypted_type: Option<&EncryptedDataType>,
    policy: &crate::policy::DecryptionPolicy,
) -> Result<String, XmlEncError> {
    let DecryptedContent::Xml(plaintext) = content else {
        return Err(XmlEncError::ReplacementRequiresXml);
    };
    let output_len = xml.len() - range.len() + plaintext.len();
    validate_encryption_document_len(output_len, policy)?;
    validate_plaintext_fragment(
        xml,
        range.start,
        range.end,
        &plaintext,
        encrypted_type,
        policy,
    )?;

    let mut output = String::with_capacity(output_len);
    output.push_str(&xml[..range.start]);
    output.push_str(&plaintext);
    output.push_str(&xml[range.end..]);
    let _ = Document::parse_with_options(&output, decryption_parsing_options(policy))?;
    Ok(output)
}

fn validate_plaintext_fragment(
    xml: &str,
    replacement_start: usize,
    replacement_end: usize,
    plaintext: &str,
    encrypted_type: Option<&EncryptedDataType>,
    policy: &crate::policy::DecryptionPolicy,
) -> Result<(), XmlEncError> {
    const WRAPPER_NS: &str = "urn:structured-world:xml-sec:decrypted-fragment";
    const WRAPPER_START: &str = "<xmlsec-internal:fragment xmlns:xmlsec-internal=\"urn:structured-world:xml-sec:decrypted-fragment\">";
    const WRAPPER_END: &str = "</xmlsec-internal:fragment>";

    let expected_end =
        replacement_start + WRAPPER_START.len() + plaintext.len() + WRAPPER_END.len();
    let mut wrapped = String::with_capacity(
        xml.len() - (replacement_end - replacement_start)
            + WRAPPER_START.len()
            + plaintext.len()
            + WRAPPER_END.len(),
    );
    wrapped.push_str(&xml[..replacement_start]);
    wrapped.push_str(WRAPPER_START);
    wrapped.push_str(plaintext);
    wrapped.push_str(WRAPPER_END);
    wrapped.push_str(&xml[replacement_end..]);

    let document = Document::parse_with_options(
        &wrapped,
        decryption_parsing_options_with_internal_nodes(policy, 1),
    )?;
    let wrapper = document
        .descendants()
        .find(|node| {
            node.has_tag_name((WRAPPER_NS, "fragment")) && node.range().start == replacement_start
        })
        .ok_or_else(|| {
            XmlEncError::InvalidStructure(
                "decrypted plaintext escaped its replacement boundary".into(),
            )
        })?;
    if wrapper.range().end != expected_end {
        return Err(XmlEncError::InvalidStructure(
            "decrypted plaintext escaped its replacement boundary".into(),
        ));
    }

    if matches!(encrypted_type, Some(EncryptedDataType::Element))
        && !has_single_element_with_boundary_trivia(wrapper)
    {
        return Err(XmlEncError::InvalidStructure(
            "Element plaintext must contain exactly one element".into(),
        ));
    }
    Ok(())
}

fn decryption_parsing_options<'input>(
    policy: &crate::policy::DecryptionPolicy,
) -> ParsingOptions<'input> {
    decryption_parsing_options_with_internal_nodes(policy, 0)
}

fn decryption_parsing_options_with_internal_nodes<'input>(
    policy: &crate::policy::DecryptionPolicy,
    internal_nodes: u32,
) -> ParsingOptions<'input> {
    ParsingOptions {
        allow_dtd: policy.xml.allow_internal_dtd,
        // The temporary wrapper proves fragment boundaries but is not part of
        // either caller-owned input or the final decrypted document.
        nodes_limit: policy
            .resources
            .effective_xml_nodes()
            .saturating_add(internal_nodes),
        entity_resolver: None,
    }
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
            resource: "encryption recipients",
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
) -> Result<Vec<Vec<u8>>, XmlEncError> {
    let mut budget = DecryptionCandidateBudget::for_operation();
    let mut last_error = None;
    let mut candidates =
        match resolve_candidates_with_budget(resolver, provider, algorithm, None, &mut budget) {
            Ok(keys) => keys,
            Err(error) => {
                record_candidate_source_error(error, &mut last_error)?;
                Vec::new()
            }
        };
    for encrypted_key in &encrypted.encrypted_keys {
        if !encrypted_key_applies_to_data(encrypted_key, encrypted) {
            continue;
        }
        if let Err(error) = validate_encrypted_key_policy(encrypted_key, policy) {
            last_error = Some(error);
            continue;
        }
        match resolve_candidates_with_budget(
            resolver,
            provider,
            algorithm,
            Some(encrypted_key),
            &mut budget,
        ) {
            Ok(keys) => candidates.extend(keys),
            Err(error) => record_candidate_source_error(error, &mut last_error)?,
        }
    }
    if candidates.is_empty() {
        Err(last_error.unwrap_or(XmlEncError::KeyNotFound))
    } else {
        Ok(candidates)
    }
}

fn record_candidate_source_error(
    error: XmlEncError,
    last_error: &mut Option<XmlEncError>,
) -> Result<(), XmlEncError> {
    // Candidate-specific failures permit the next ordered key source. The
    // shared work ceiling is operation-wide and must never be recoverable by
    // advancing to another recipient.
    if matches!(&error, XmlEncError::DecryptionCandidateLimitExceeded { .. }) {
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
    budget: &mut DecryptionCandidateBudget,
) -> Result<Vec<Vec<u8>>, XmlEncError> {
    let remaining_before = budget.remaining();
    let keys = resolver.resolve_key_candidates(provider, algorithm, encrypted_key, budget)?;
    budget.account_returned_candidates(remaining_before, keys.len())?;
    Ok(keys)
}

fn encrypted_key_applies_to_data(
    encrypted_key: &EncryptedKey,
    encrypted_data: &EncryptedData,
) -> bool {
    // XMLEnc association metadata is optional, but authoritative when present:
    // DataReference identifies encrypted objects and CarriedKeyName identifies
    // the transported key referenced by the enclosing ds:KeyName.
    if let Some(references) = encrypted_key.reference_list.as_ref()
        && !references.data_references.is_empty()
    {
        let Some(id) = encrypted_data.id.as_deref() else {
            return false;
        };
        let target = format!("#{id}");
        if !references.data_references.iter().any(|uri| uri == &target) {
            return false;
        }
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

fn compatible_decryption_key_candidates(
    algorithm: DataEncryptionAlgorithm,
    keys: Vec<Vec<u8>>,
) -> Result<Vec<Vec<u8>>, XmlEncError> {
    let mut compatible = Vec::with_capacity(keys.len());
    let mut last_error = None;
    for key in keys {
        match validate_key_len(algorithm, &key) {
            Ok(()) if !compatible.iter().any(|existing| existing == &key) => {
                compatible.push(key);
            }
            Ok(()) => {}
            Err(error) => last_error = Some(error),
        }
    }
    if compatible.is_empty() {
        return Err(last_error.unwrap_or(XmlEncError::KeyNotFound));
    }
    Ok(compatible)
}

fn validate_decryption_key_candidates(
    algorithm: DataEncryptionAlgorithm,
    actual: usize,
) -> Result<(), XmlEncError> {
    let maximum = crate::hard_limits::DECRYPTION_KEY_CANDIDATE_CEILING;
    if actual > maximum {
        return Err(crate::policy::PolicyViolation::ResourceLimit {
            resource: "decryption key candidates",
            maximum,
            actual,
        }
        .into());
    }
    if actual > 1
        && matches!(
            algorithm,
            DataEncryptionAlgorithm::Aes128Cbc | DataEncryptionAlgorithm::Aes256Cbc
        )
    {
        return Err(XmlEncError::AmbiguousKeyCandidates { algorithm, actual });
    }
    Ok(())
}

fn validate_encrypted_key_policy(
    encrypted_key: &EncryptedKey,
    policy: &crate::policy::DecryptionPolicy,
) -> Result<(), XmlEncError> {
    encrypted_key.encryption_method.validate_structure()?;
    let uri = &encrypted_key.encryption_method.algorithm;
    if let Ok(transport) = KeyTransportAlgorithm::from_uri(uri) {
        if policy
            .key_transport_algorithms
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(&transport))
        {
            return Err(crate::policy::PolicyViolation::Algorithm {
                operation: "decryption",
                algorithm: uri.clone(),
            }
            .into());
        }
        let digest = parse_oaep_digest(encrypted_key.encryption_method.oaep_digest.as_deref())?;
        let mgf_digest = if transport == KeyTransportAlgorithm::RsaOaepMgf1p {
            OaepDigestAlgorithm::Sha1
        } else {
            parse_oaep_mgf_digest(encrypted_key.encryption_method.mgf_algorithm.as_deref())?
        };
        for selected in [digest, mgf_digest] {
            if policy
                .oaep_digests
                .as_ref()
                .is_some_and(|allowed| !allowed.contains(&selected))
            {
                return Err(crate::policy::PolicyViolation::Algorithm {
                    operation: "decryption",
                    algorithm: selected.uri().to_owned(),
                }
                .into());
            }
        }
    } else {
        let wrap = KeyWrapAlgorithm::from_uri(uri)?;
        if policy
            .key_wrap_algorithms
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(&wrap))
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
    let maximum_ciphertext = match algorithm {
        DataEncryptionAlgorithm::Aes128Cbc | DataEncryptionAlgorithm::Aes256Cbc => {
            (maximum_plaintext / 16)
                .saturating_add(1)
                .saturating_mul(16)
                .saturating_add(16)
        }
        DataEncryptionAlgorithm::Aes128Gcm | DataEncryptionAlgorithm::Aes256Gcm => {
            maximum_plaintext.saturating_add(28)
        }
    };
    let projected = validate_cipher_value_len(&encrypted.cipher_data.value, maximum_ciphertext)?;
    if projected > maximum_ciphertext {
        return Err(XmlEncError::PlaintextTooLarge {
            maximum: maximum_plaintext,
            actual: projected.saturating_sub(algorithm.minimum_ciphertext_len()),
        });
    }

    let mut aggregate_encoded = encrypted.cipher_data.value.len();
    if aggregate_encoded > maximum_cipher_values {
        return Err(crate::policy::PolicyViolation::ResourceLimit {
            resource: "aggregate encryption CipherValue bytes",
            maximum: maximum_cipher_values,
            actual: aggregate_encoded,
        }
        .into());
    }

    let maximum_wrapped_key = projected_decoded_len_for_encoded_len(MAX_CIPHER_VALUE_BASE64_LEN);
    for encrypted_key in &encrypted.encrypted_keys {
        validate_cipher_value_len(&encrypted_key.cipher_data.value, maximum_wrapped_key)?;
        aggregate_encoded = aggregate_encoded.saturating_add(encrypted_key.cipher_data.value.len());
        if aggregate_encoded > maximum_cipher_values {
            return Err(crate::policy::PolicyViolation::ResourceLimit {
                resource: "aggregate encryption CipherValue bytes",
                maximum: maximum_cipher_values,
                actual: aggregate_encoded,
            }
            .into());
        }
    }
    Ok(())
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

fn validate_key_len(algorithm: DataEncryptionAlgorithm, key: &[u8]) -> Result<(), XmlEncError> {
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

fn validate_possible_plaintext_len(
    algorithm: DataEncryptionAlgorithm,
    ciphertext_len: usize,
    maximum: usize,
) -> Result<(), XmlEncError> {
    // CBC's minimum includes a 16-byte IV and one padded block; using that
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

    match algorithm {
        DataEncryptionAlgorithm::Aes128Gcm | DataEncryptionAlgorithm::Aes256Gcm => {
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
        DataEncryptionAlgorithm::Aes128Cbc | DataEncryptionAlgorithm::Aes256Cbc => {
            let padded_len = ciphertext_len - 16;
            let minimum = padded_len - 16;
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
        Err(XmlEncError::PlaintextTooLarge { maximum, actual })
    }
}

fn map_data_decryption_error(
    algorithm: DataEncryptionAlgorithm,
    ciphertext_len: usize,
    error: crate::provider::ProviderError,
) -> XmlEncError {
    use crate::provider::ProviderError;

    match (algorithm, error) {
        (
            DataEncryptionAlgorithm::Aes128Gcm | DataEncryptionAlgorithm::Aes256Gcm,
            ProviderError::AuthenticationFailed,
        ) => XmlEncError::AeadAuthenticationFailed,
        (
            DataEncryptionAlgorithm::Aes128Gcm | DataEncryptionAlgorithm::Aes256Gcm,
            ProviderError::InvalidInput(crate::provider::ProviderInputError::AesGcmFraming),
        ) => XmlEncError::DataTooShort {
            algorithm: "AES-GCM",
            minimum: 28,
            actual: ciphertext_len,
        },
        (
            DataEncryptionAlgorithm::Aes128Cbc | DataEncryptionAlgorithm::Aes256Cbc,
            ProviderError::InvalidInput(crate::provider::ProviderInputError::AesCbcFraming),
        ) if ciphertext_len < 32 => XmlEncError::DataTooShort {
            algorithm: "AES-CBC",
            minimum: 32,
            actual: ciphertext_len,
        },
        (
            DataEncryptionAlgorithm::Aes128Cbc | DataEncryptionAlgorithm::Aes256Cbc,
            ProviderError::InvalidInput(crate::provider::ProviderInputError::AesCbcFraming),
        ) => XmlEncError::InvalidCbcCiphertextLength(ciphertext_len.saturating_sub(16)),
        (
            DataEncryptionAlgorithm::Aes128Cbc | DataEncryptionAlgorithm::Aes256Cbc,
            ProviderError::InvalidInput(crate::provider::ProviderInputError::AesCbcCiphertext),
        ) => XmlEncError::InvalidPadding,
        (_, error) => XmlEncError::Provider(error),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use aes_gcm::{
        Aes128Gcm,
        aead::{AeadInOut, KeyInit},
    };
    use aes_kw::KwAes128;
    use base64::engine::general_purpose::STANDARD;
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
    use rsa::{Oaep, RsaPublicKey, pkcs8::DecodePrivateKey};
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

    struct MislabelledExhaustionResolver {
        direct: Vec<u8>,
    }

    impl DecryptionKeyResolver for DirectAndRecipientResolver {
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

    impl DecryptionKeyResolver for MislabelledExhaustionResolver {
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
            budget: &mut DecryptionCandidateBudget,
        ) -> Result<Vec<Vec<u8>>, XmlEncError> {
            if encrypted_key.is_none() {
                budget.consume(1, "decryption key candidates")?;
                return Ok(vec![self.direct.clone()]);
            }
            budget.consume(
                budget.remaining().saturating_add(1),
                "RSA private-key candidates",
            )?;
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

        fn resolve_key_candidates(
            &self,
            _provider: &dyn crate::provider::CryptoProvider,
            _algorithm: DataEncryptionAlgorithm,
            encrypted_key: Option<&EncryptedKey>,
            budget: &mut DecryptionCandidateBudget,
        ) -> Result<Vec<Vec<u8>>, XmlEncError> {
            budget.consume(1, "decryption key candidates")?;
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
            budget: &mut DecryptionCandidateBudget,
        ) -> Result<Vec<Vec<u8>>, XmlEncError> {
            if encrypted_key.is_none() {
                budget.consume(self.keys.len(), "decryption key candidates")?;
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

        fn resolve_key_candidates(
            &self,
            _provider: &dyn crate::provider::CryptoProvider,
            _algorithm: DataEncryptionAlgorithm,
            encrypted_key: Option<&EncryptedKey>,
            budget: &mut DecryptionCandidateBudget,
        ) -> Result<Vec<Vec<u8>>, XmlEncError> {
            let encrypted_key = encrypted_key.ok_or(XmlEncError::KeyNotFound)?;
            let attempts = budget.remaining();
            if attempts == 0 {
                budget.consume(1, "decryption key candidates")?;
            }
            budget.consume(attempts, "decryption key candidates")?;
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

        fn resolve_key_candidates(
            &self,
            _provider: &dyn crate::provider::CryptoProvider,
            _algorithm: DataEncryptionAlgorithm,
            encrypted_key: Option<&EncryptedKey>,
            budget: &mut DecryptionCandidateBudget,
        ) -> Result<Vec<Vec<u8>>, XmlEncError> {
            let encrypted_key = encrypted_key.ok_or(XmlEncError::KeyNotFound)?;
            budget.consume(1, "decryption key candidates")?;
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
            recipient: None,
            key_name: None,
            encryption_method: EncryptionMethod {
                algorithm: KeyTransportAlgorithm::RsaOaep11.uri().into(),
                key_size_bits: None,
                oaep_digest: None,
                mgf_algorithm: None,
                oaep_params: None,
            },
            cipher_data: CipherData {
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
            cipher_data: CipherData {
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

    impl crate::provider::CryptoProvider for PermissiveUnwrapProvider {
        fn name(&self) -> &'static str {
            "permissive-unwrap-test"
        }

        fn supports(&self, query: crate::provider::CapabilityQuery<'_>) -> bool {
            crate::provider::CryptoProvider::supports(&crate::provider::RustCryptoProvider, query)
        }

        fn fill_random(&self, output: &mut [u8]) -> Result<(), crate::provider::ProviderError> {
            crate::provider::CryptoProvider::fill_random(
                &crate::provider::RustCryptoProvider,
                output,
            )
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
            key: &RsaPublicKey,
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
            _key: &rsa::RsaPrivateKey,
            _parameters: &RsaOaepParameters,
            _ciphertext: &[u8],
        ) -> Result<Vec<u8>, crate::provider::ProviderError> {
            self.recover_calls.fetch_add(1, Ordering::Relaxed);
            Ok(vec![0_u8; 16])
        }
    }

    impl DecryptionKeyResolver for CountingResolver {
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
            cipher_data: CipherData {
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
            cipher_data: CipherData {
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
            cipher_data: CipherData {
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
            cipher_data: CipherData {
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
            cipher_data: CipherData {
                value: STANDARD.encode(vec![0_u8; 28]),
            },
        };
        let actual = crate::hard_limits::DECRYPTION_KEY_CANDIDATE_CEILING + 1;
        let resolver = CandidateResolver {
            keys: vec![vec![0_u8; 16]; actual],
        };

        let error = DecryptContext::new(&resolver)
            .decrypt_data(&encrypted)
            .expect_err("oversized candidate sets must fail before decryption");

        assert!(matches!(
            error,
            XmlEncError::DecryptionCandidateLimitExceeded {
                resource: "decryption key candidates",
                maximum: crate::hard_limits::DECRYPTION_KEY_CANDIDATE_CEILING,
                actual: observed,
            } if observed == actual
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
            crate::hard_limits::DECRYPTION_KEY_CANDIDATE_CEILING
        );
    }

    #[test]
    fn candidate_budget_exhaustion_is_fatal_after_a_key_was_found() {
        // The resolver chooses resource labels only for diagnostics; changing
        // that label must not turn operation-wide exhaustion into recovery.
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
            XmlEncError::DecryptionCandidateLimitExceeded {
                resource: "RSA private-key candidates",
                maximum: crate::hard_limits::DECRYPTION_KEY_CANDIDATE_CEILING,
                actual,
            } if actual == crate::hard_limits::DECRYPTION_KEY_CANDIDATE_CEILING + 1
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
        encrypted.cipher_data.value = STANDARD.encode(
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
            cipher_data: CipherData {
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
            cipher_data: super::super::CipherData {
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
                    resource: "encryption recipients",
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
            recipient: None,
            key_name: None,
            encryption_method: super::super::EncryptionMethod {
                algorithm: "http://www.w3.org/2001/04/xmlenc#kw-aes128".into(),
                key_size_bits: None,
                oaep_digest: None,
                mgf_algorithm: None,
                oaep_params: None,
            },
            cipher_data: super::super::CipherData {
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
            recipient: None,
            key_name: None,
            encryption_method: super::super::EncryptionMethod {
                algorithm: KeyWrapAlgorithm::AesKw128.uri().into(),
                key_size_bits: None,
                oaep_digest: None,
                mgf_algorithm: None,
                oaep_params: None,
            },
            cipher_data: super::super::CipherData {
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
                cipher_data: super::super::CipherData {
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
                cipher_data: super::super::CipherData {
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
                cipher_data: super::super::CipherData {
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
                ),
                Err(XmlEncError::InvalidWrappedKeyLength {
                    expected: 256,
                    actual: output_len,
                }) if output_len == actual
            ));
        }
        assert_eq!(provider.recover_calls.load(Ordering::Relaxed), 0);
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
            cipher_data: super::super::CipherData {
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
            recipient: None,
            key_name: None,
            encryption_method: super::super::EncryptionMethod {
                algorithm: "http://www.w3.org/2001/04/xmlenc#kw-aes128".into(),
                key_size_bits: None,
                oaep_digest: None,
                mgf_algorithm: None,
                oaep_params: None,
            },
            cipher_data: super::super::CipherData {
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
            recipient: Some("recipient-a".into()),
            key_name: None,
            encryption_method: super::super::EncryptionMethod {
                algorithm: "http://www.w3.org/2009/xmlenc11#rsa-oaep".into(),
                key_size_bits: None,
                oaep_digest: Some("http://www.w3.org/2001/04/xmlenc#sha256".into()),
                mgf_algorithm: Some("http://www.w3.org/2009/xmlenc11#mgf1sha384".into()),
                oaep_params: Some(label),
            },
            cipher_data: super::super::CipherData {
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
        // The legacy URI fixes MGF1 to SHA-1 while allowing an explicit message digest.
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
            recipient: None,
            key_name: None,
            encryption_method: super::super::EncryptionMethod {
                algorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p".into(),
                key_size_bits: None,
                oaep_digest: Some("http://www.w3.org/2001/04/xmlenc#sha256".into()),
                mgf_algorithm: None,
                oaep_params: None,
            },
            cipher_data: super::super::CipherData {
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
        // OAEP algorithm URIs because the legacy form still fixes MGF1 to SHA-1.
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
                recipient: None,
                key_name: None,
                encryption_method: super::super::EncryptionMethod {
                    algorithm: algorithm.into(),
                    key_size_bits: None,
                    oaep_digest: Some(digest.into()),
                    mgf_algorithm: mgf_algorithm.map(str::to_owned),
                    oaep_params: None,
                },
                cipher_data: super::super::CipherData {
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
            cipher_data: super::super::CipherData {
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
            key_name: None,
            encryption_method: super::super::EncryptionMethod {
                algorithm: KeyTransportAlgorithm::RsaOaep11.uri().into(),
                key_size_bits: None,
                oaep_digest: Some(OaepDigestAlgorithm::Sha256.uri().into()),
                mgf_algorithm: Some("http://www.w3.org/2009/xmlenc11#mgf1sha1".into()),
                oaep_params: None,
            },
            cipher_data: super::super::CipherData {
                value: STANDARD.encode([0_u8; 256]),
            },
            reference_list: None,
            carried_key_name: None,
        };
        let encrypted = EncryptedData {
            id: None,
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
            cipher_data: super::super::CipherData {
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
                crate::policy::PolicyViolation::Algorithm { .. }
            ))
        ));

        let ciphertext = crate::provider::default_provider()
            .encrypt_data(DataEncryptionAlgorithm::Aes128Gcm, &[0_u8; 16], b"four")
            .expect("test encryption must succeed");
        let bounded = EncryptedData {
            encrypted_keys: Vec::new(),
            cipher_data: super::super::CipherData {
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
            Err(XmlEncError::PlaintextTooLarge {
                maximum: 3,
                actual: 4
            })
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
            cipher_data: super::super::CipherData {
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
            cipher_data: super::super::CipherData {
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

        assert!(matches!(
            DecryptContext::new(&SymmetricKeyDecryptor::new([0_u8; 16]))
                .policy(policy)
                .decrypt_data(&encrypted),
            Err(XmlEncError::EncryptionMetadataTooLarge {
                field: "EncryptedData Id",
                maximum: 8,
                actual: 9,
            })
        ));
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
            cipher_data: super::super::CipherData {
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
        encrypted.cipher_data.value = "A".repeat(48);
        assert!(matches!(
            DecryptContext::new(&SymmetricKeyDecryptor::new(key))
                .policy(policy)
                .decrypt_data(&encrypted),
            Err(XmlEncError::PlaintextTooLarge { .. })
        ));

        encrypted.cipher_data.value = STANDARD.encode([0_u8; 28]);
        encrypted.encrypted_keys.push(EncryptedKey {
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
            cipher_data: super::super::CipherData {
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

        encrypted.encrypted_keys[0].cipher_data.value = "AAAA".into();
        let aggregate_encoded_len =
            encrypted.cipher_data.value.len() + encrypted.encrypted_keys[0].cipher_data.value.len();
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
                    resource: "aggregate encryption CipherValue bytes",
                    maximum,
                    actual,
                }
            )) if maximum == aggregate_encoded_len - 1 && actual == aggregate_encoded_len
        ));
        assert_eq!(resolver.candidate_calls.get(), 0);
    }

    #[test]
    fn typed_legacy_oaep_mgf_is_rejected_before_key_resolution() {
        // The legacy RSA-OAEP URI fixes MGF1 to SHA-1 and cannot carry an MGF
        // child. Typed input must preserve the parser's structural invariant.
        let key = [0x43_u8; 16];
        let ciphertext = crate::provider::default_provider()
            .encrypt_data(DataEncryptionAlgorithm::Aes128Gcm, &key, b"data")
            .expect("test encryption must succeed");
        let encrypted = EncryptedData {
            id: None,
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
                key_name: None,
                encryption_method: super::super::EncryptionMethod {
                    algorithm: KeyTransportAlgorithm::RsaOaepMgf1p.uri().into(),
                    key_size_bits: None,
                    oaep_digest: Some(OaepDigestAlgorithm::Sha256.uri().into()),
                    mgf_algorithm: Some(OaepDigestAlgorithm::Sha384.mgf_uri().into()),
                    oaep_params: None,
                },
                cipher_data: super::super::CipherData {
                    value: STANDARD.encode([0_u8; 256]),
                },
                reference_list: None,
                carried_key_name: None,
            }],
            cipher_data: super::super::CipherData {
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
                if message == "MGF is only valid for XML Encryption 1.1 RSA-OAEP"
        ));
        assert_eq!(resolver.candidate_calls.get(), 0);

        let private_key = RsaPrivateKey::from_pkcs8_pem(include_str!(
            "../../tests/fixtures/keys/rsa/rsa-2048-key.pem"
        ))
        .expect("tracked RSA private key must parse");
        assert!(matches!(
            PrivateKeyDecryptor::new(private_key).resolve_key(
                crate::provider::default_provider(),
                DataEncryptionAlgorithm::Aes128Gcm,
                encrypted.encrypted_keys.first(),
            ),
            Err(XmlEncError::InvalidStructure(message))
                if message == "MGF is only valid for XML Encryption 1.1 RSA-OAEP"
        ));
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
                key_name: None,
                encryption_method: super::super::EncryptionMethod {
                    algorithm: KeyTransportAlgorithm::RsaOaep11.uri().into(),
                    key_size_bits: Some(0),
                    oaep_digest: Some(OaepDigestAlgorithm::Sha256.uri().into()),
                    mgf_algorithm: Some(OaepDigestAlgorithm::Sha256.mgf_uri().into()),
                    oaep_params: None,
                },
                cipher_data: super::super::CipherData {
                    value: STANDARD.encode([0_u8; 256]),
                },
                reference_list: None,
                carried_key_name: None,
            }],
            cipher_data: super::super::CipherData {
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
            cipher_data: super::super::CipherData {
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
                key_name: None,
                encryption_method: super::super::EncryptionMethod {
                    algorithm: "urn:example:unknown-key-algorithm".into(),
                    key_size_bits: None,
                    oaep_digest: None,
                    mgf_algorithm: None,
                    oaep_params: None,
                },
                cipher_data: super::super::CipherData {
                    value: STANDARD.encode([0_u8; 24]),
                },
                reference_list: None,
                carried_key_name: None,
            }],
            cipher_data: super::super::CipherData {
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
            Err(XmlEncError::XmlParse(roxmltree::Error::DtdDetected))
        ));
        assert!(
            decrypt_document_with_options(
                &with_dtd,
                DocumentDecryptionOptions {
                    encrypted_data_id: None,
                    allow_dtd: true,
                },
                &SymmetricKeyDecryptor::new(key),
            )
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
                resource: "XML document",
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
            Err(XmlEncError::XmlParse(roxmltree::Error::NodesLimitReached))
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
