//! XMLEnc decryption entry point and key resolvers.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use roxmltree::{Document, ParsingOptions};
use rsa::RsaPrivateKey;

use super::parse::{
    parse_encrypted_data_node_with_policy, parse_encrypted_data_with_policy,
    validate_encrypted_data_metadata,
};
use super::types::{MAX_CIPHER_VALUE_BASE64_LEN, XMLENC_NS};
use super::{
    DataEncryptionAlgorithm, DecryptedContent, EncryptedData, EncryptedDataType, EncryptedKey,
    KeyTransportAlgorithm, KeyWrapAlgorithm, OaepDigestAlgorithm, RsaOaepParameters, XmlEncError,
    has_single_element_with_boundary_trivia,
};

#[cfg(test)]
use super::parse_encrypted_data;

/// Supplies a content-encryption key for parsed XMLEnc data.
pub trait DecryptionKeyResolver {
    /// Resolve the symmetric key for `algorithm`, optionally unwrapping `encrypted_key`.
    fn resolve_key(
        &self,
        provider: &dyn crate::provider::CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
    ) -> Result<Vec<u8>, XmlEncError>;
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
}

impl<'a> DecryptContext<'a> {
    /// Create a context with compatibility defaults and the RustCrypto provider.
    pub fn new(resolver: &'a dyn DecryptionKeyResolver) -> Self {
        Self {
            resolver,
            policy: crate::policy::DecryptionPolicy::default(),
            provider: crate::provider::default_provider(),
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

    /// Parse and decrypt a standalone `EncryptedData` XML fragment.
    pub fn decrypt(&self, xml: &str) -> Result<DecryptedContent, XmlEncError> {
        let encrypted = parse_encrypted_data_with_policy(xml, &self.policy)?;
        self.decrypt_data(&encrypted)
    }

    /// Decrypt an already parsed `EncryptedData` value.
    pub fn decrypt_data(&self, encrypted: &EncryptedData) -> Result<DecryptedContent, XmlEncError> {
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
        )?;
        let ciphertext = STANDARD
            .decode(&encrypted.cipher_data.value)
            .map_err(|error| XmlEncError::Base64(error.to_string()))?;
        validate_possible_plaintext_len(
            algorithm,
            ciphertext.len(),
            self.policy.resources.max_encryption_plaintext_bytes,
        )?;
        let key = resolve_content_key(
            self.provider,
            algorithm,
            &encrypted.encrypted_keys,
            self.resolver,
            &self.policy,
        )?;
        validate_key_len(algorithm, &key)?;
        let plaintext = self
            .provider
            .decrypt_data(algorithm, &key, &ciphertext)
            .map_err(|error| map_data_decryption_error(algorithm, ciphertext.len(), error))?;
        validate_plaintext_len(
            plaintext.len(),
            self.policy.resources.max_encryption_plaintext_bytes,
        )?;
        match encrypted.encrypted_type.as_ref() {
            Some(EncryptedDataType::Element | EncryptedDataType::Content) => {
                Ok(DecryptedContent::Xml(String::from_utf8(plaintext)?))
            }
            Some(EncryptedDataType::Other(_)) | None => Ok(DecryptedContent::Bytes(plaintext)),
        }
    }

    /// Decrypt and replace one selected `EncryptedData` in a caller-owned document.
    pub fn decrypt_document(
        &self,
        xml: &str,
        encrypted_data_id: Option<&str>,
    ) -> Result<String, XmlEncError> {
        decrypt_document_with_context(xml, encrypted_data_id, self)
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
    match uri.unwrap_or("http://www.w3.org/2000/09/xmldsig#sha1") {
        "http://www.w3.org/2000/09/xmldsig#sha1" => Ok(OaepDigestAlgorithm::Sha1),
        "http://www.w3.org/2001/04/xmlenc#sha256" => Ok(OaepDigestAlgorithm::Sha256),
        "http://www.w3.org/2001/04/xmlenc#sha384"
        | "http://www.w3.org/2001/04/xmldsig-more#sha384" => Ok(OaepDigestAlgorithm::Sha384),
        "http://www.w3.org/2001/04/xmlenc#sha512" => Ok(OaepDigestAlgorithm::Sha512),
        unsupported => Err(XmlEncError::UnsupportedAlgorithm(unsupported.to_owned())),
    }
}

fn parse_oaep_mgf_digest(uri: Option<&str>) -> Result<OaepDigestAlgorithm, XmlEncError> {
    match uri.unwrap_or("http://www.w3.org/2009/xmlenc11#mgf1sha1") {
        "http://www.w3.org/2009/xmlenc11#mgf1sha1" => Ok(OaepDigestAlgorithm::Sha1),
        "http://www.w3.org/2009/xmlenc11#mgf1sha256" => Ok(OaepDigestAlgorithm::Sha256),
        "http://www.w3.org/2009/xmlenc11#mgf1sha384" => Ok(OaepDigestAlgorithm::Sha384),
        "http://www.w3.org/2009/xmlenc11#mgf1sha512" => Ok(OaepDigestAlgorithm::Sha512),
        unsupported => Err(XmlEncError::UnsupportedAlgorithm(unsupported.to_owned())),
    }
}

fn recover_rsa_oaep(
    provider: &dyn crate::provider::CryptoProvider,
    key: &RsaPrivateKey,
    parameters: &RsaOaepParameters,
    wrapped: &[u8],
) -> Result<Vec<u8>, XmlEncError> {
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

fn decrypt_document_with_context(
    xml: &str,
    encrypted_data_id: Option<&str>,
    context: &DecryptContext<'_>,
) -> Result<String, XmlEncError> {
    context.policy.resources.validate()?;
    validate_encryption_document_len(xml.len(), &context.policy)?;
    let parsing_options = || decryption_parsing_options(&context.policy);
    let document = Document::parse_with_options(xml, parsing_options())?;
    let mut matches = document.descendants().filter(|node| {
        node.has_tag_name((XMLENC_NS, "EncryptedData"))
            && encrypted_data_id.is_none_or(|id| node.attribute("Id") == Some(id))
    });
    let selected = matches.next().ok_or(XmlEncError::EncryptedDataNotFound)?;
    if matches.next().is_some() {
        return Err(XmlEncError::AmbiguousEncryptedData);
    }

    let range = selected.range();
    let encrypted = parse_encrypted_data_node_with_policy(selected, &context.policy)?;
    let DecryptedContent::Xml(plaintext) = context.decrypt_data(&encrypted)? else {
        return Err(XmlEncError::ReplacementRequiresXml);
    };

    let output_len = xml.len() - range.len() + plaintext.len();
    validate_encryption_document_len(output_len, &context.policy)?;
    validate_plaintext_fragment(
        xml,
        range.start,
        range.end,
        &plaintext,
        encrypted.encrypted_type.as_ref(),
        &context.policy,
    )?;

    let mut output = String::with_capacity(output_len);
    output.push_str(&xml[..range.start]);
    output.push_str(&plaintext);
    output.push_str(&xml[range.end..]);
    let _ = Document::parse_with_options(&output, parsing_options())?;
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

    let document = Document::parse_with_options(&wrapped, decryption_parsing_options(policy))?;
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

fn decryption_parsing_options<'a>(policy: &crate::policy::DecryptionPolicy) -> ParsingOptions<'a> {
    ParsingOptions {
        allow_dtd: policy.xml.allow_internal_dtd,
        nodes_limit: u32::try_from(policy.resources.max_xml_nodes)
            .unwrap_or(crate::hard_limits::XML_DOCUMENT_NODE_CEILING),
        entity_resolver: None,
    }
}

fn validate_encryption_document_len(
    actual: usize,
    policy: &crate::policy::DecryptionPolicy,
) -> Result<(), XmlEncError> {
    if actual > policy.resources.max_encryption_document_bytes {
        return Err(crate::policy::PolicyViolation::ResourceLimit {
            resource: "encryption document",
            maximum: policy.resources.max_encryption_document_bytes,
            actual,
        }
        .into());
    }
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

fn resolve_content_key(
    provider: &dyn crate::provider::CryptoProvider,
    algorithm: DataEncryptionAlgorithm,
    encrypted_keys: &[EncryptedKey],
    resolver: &dyn DecryptionKeyResolver,
    policy: &crate::policy::DecryptionPolicy,
) -> Result<Vec<u8>, XmlEncError> {
    match resolver.resolve_key(provider, algorithm, None) {
        Ok(key) => return Ok(key),
        Err(XmlEncError::KeyNotFound) => {}
        Err(error) => return Err(error),
    }

    let mut last_error = None;
    for encrypted_key in encrypted_keys {
        if let Err(error) = validate_encrypted_key_policy(encrypted_key, policy) {
            last_error = Some(error);
            continue;
        }
        match resolver.resolve_key(provider, algorithm, Some(encrypted_key)) {
            Ok(key) => return Ok(key),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or(XmlEncError::KeyNotFound))
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

fn validate_typed_cipher_values(
    encrypted: &EncryptedData,
    algorithm: DataEncryptionAlgorithm,
    maximum_plaintext: usize,
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
            actual: projected.saturating_sub(ciphertext_framing_len(algorithm)),
        });
    }

    let maximum_wrapped_key = projected_decoded_len_for_encoded_len(MAX_CIPHER_VALUE_BASE64_LEN);
    for encrypted_key in &encrypted.encrypted_keys {
        validate_cipher_value_len(&encrypted_key.cipher_data.value, maximum_wrapped_key)?;
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

const fn ciphertext_framing_len(algorithm: DataEncryptionAlgorithm) -> usize {
    match algorithm {
        DataEncryptionAlgorithm::Aes128Cbc | DataEncryptionAlgorithm::Aes256Cbc => 32,
        DataEncryptionAlgorithm::Aes128Gcm | DataEncryptionAlgorithm::Aes256Gcm => 28,
    }
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
    let framing = match algorithm {
        // CBC contains a 16-byte IV and 1 to 16 padding bytes. Assuming the
        // largest padding yields the smallest plaintext possible on success,
        // which is the safe pre-decryption lower bound checked here. The exact
        // plaintext length is checked after decryption.
        DataEncryptionAlgorithm::Aes128Cbc | DataEncryptionAlgorithm::Aes256Cbc => 32,
        DataEncryptionAlgorithm::Aes128Gcm | DataEncryptionAlgorithm::Aes256Gcm => 28,
    };
    validate_plaintext_len(ciphertext_len.saturating_sub(framing), maximum)
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
            ProviderError::InvalidInput(crate::provider::ProviderInputError::XmlEncCbcPadding),
        ) => XmlEncError::InvalidPadding,
        (_, error) => XmlEncError::Provider(error),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use aes_gcm::{
        Aes128Gcm,
        aead::{AeadInOut, KeyInit},
    };
    use aes_kw::KwAes128;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
    use rsa::{Oaep, RsaPublicKey, pkcs8::DecodePrivateKey};
    use sha1::Sha1;
    use sha2::{Sha256, Sha384};

    use super::*;

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
                crate::provider::ProviderInputError::XmlEncCbcPadding,
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
                max_encryption_document_bytes: document.len() - 1,
                ..crate::policy::ResourcePolicy::default()
            },
            ..crate::policy::DecryptionPolicy::default()
        };
        assert!(matches!(
            DecryptContext::new(&SymmetricKeyDecryptor::new(key))
                .policy(byte_policy)
                .decrypt_document(&document, None),
            Err(XmlEncError::Policy(crate::policy::PolicyViolation::ResourceLimit {
                resource: "encryption document",
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
