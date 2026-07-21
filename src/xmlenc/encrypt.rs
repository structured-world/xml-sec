//! XMLEnc content encryption, key wrapping, and XML generation.

use std::fmt;

use aes::{
    Aes128, Aes256,
    cipher::{BlockModeEncrypt, KeyIvInit, block_padding::NoPadding},
};
use aes_gcm::{
    Aes128Gcm, Aes256Gcm, Nonce,
    aead::{AeadInOut, KeyInit},
};
use aes_kw::{KwAes128, KwAes256};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use cbc::Encryptor;
use getrandom::{SysRng, rand_core::TryRng};
use quick_xml::{
    Writer,
    events::{BytesEnd, BytesStart, BytesText, Event},
};
use roxmltree::{Document, Node, ParsingOptions};
use rsa::{Oaep, RsaPublicKey, traits::PaddingScheme};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

use super::types::{
    MAX_ENCRYPTION_DOCUMENT_LEN, MAX_ENCRYPTION_METADATA_LEN, MAX_ENCRYPTION_PLAINTEXT_LEN,
    MAX_ENCRYPTION_RECIPIENTS, XMLDSIG_NS, XMLENC_NS, XMLENC11_NS,
};
use super::{
    DataEncryptionAlgorithm, DocumentEncryptionOptions, EncryptedDataType, EncryptionRecipient,
    EncryptionResult, KeyWrapAlgorithm, OaepDigestAlgorithm, ReplacementMode, RsaOaepParameters,
    XmlEncError, has_single_element_with_boundary_trivia,
};

const XML_WHITESPACE: &[char] = &[' ', '\t', '\n', '\r'];

/// Builder for complete `EncryptedData` fragments and document replacement.
#[derive(Clone)]
pub struct EncryptedDataBuilder {
    algorithm: DataEncryptionAlgorithm,
    encrypted_type: EncryptedDataType,
    id: Option<String>,
    direct_key: Option<Vec<u8>>,
    direct_key_name: Option<String>,
    recipients: Vec<EncryptionRecipient>,
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
        }
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

    /// Add an AES Key Wrap recipient.
    pub fn recipient_aes_kw(self, kek: impl Into<Vec<u8>>, algorithm: KeyWrapAlgorithm) -> Self {
        self.add_recipient(EncryptionRecipient::aes_key_wrap(kek, algorithm))
    }

    /// Encrypt one complete XML element or an XML content fragment.
    pub fn encrypt_xml(&self, xml: &str) -> Result<EncryptionResult, XmlEncError> {
        validate_plaintext_len(xml.len())?;
        validate_xml_plaintext(xml, &self.encrypted_type)?;
        self.encrypt_payload(xml.as_bytes(), Some(self.encrypted_type.clone()))
    }

    /// Encrypt opaque bytes without an XML `Type` attribute.
    pub fn encrypt_binary(&self, data: &[u8]) -> Result<EncryptionResult, XmlEncError> {
        self.encrypt_payload(data, None)
    }

    /// Encrypt and replace the document root or one element selected by XML ID.
    pub fn encrypt_document(
        &self,
        xml: &str,
        options: DocumentEncryptionOptions<'_>,
    ) -> Result<String, XmlEncError> {
        validate_document_len(xml.len())?;
        let parsing_options = ParsingOptions {
            allow_dtd: options.allow_dtd,
            entity_resolver: None,
            ..ParsingOptions::default()
        };
        let document = Document::parse_with_options(xml, parsing_options)?;
        let selected = select_encryption_target(&document, options.element_id)?;
        let range = selected.range();
        let source = &xml[range.clone()];

        match self.encrypted_type {
            EncryptedDataType::Element => {
                let result =
                    self.encrypt_payload(source.as_bytes(), Some(EncryptedDataType::Element))?;
                Ok(replace_range(xml, range, &result.encrypted_data_xml))
            }
            EncryptedDataType::Content => {
                let boundaries = element_content_boundaries(source)?;
                let plaintext = &source[boundaries.content.clone()];
                let result =
                    self.encrypt_payload(plaintext.as_bytes(), Some(EncryptedDataType::Content))?;
                replace_element_content(xml, range, source, boundaries, &result.encrypted_data_xml)
            }
            EncryptedDataType::Other(_) => Err(XmlEncError::InvalidEncryptionConfig(
                "document encryption requires Element or Content Type".into(),
            )),
        }
    }

    fn encrypt_payload(
        &self,
        plaintext: &[u8],
        encrypted_type: Option<EncryptedDataType>,
    ) -> Result<EncryptionResult, XmlEncError> {
        validate_plaintext_len(plaintext.len())?;
        self.validate_configuration()?;

        let content_key = if let Some(key) = &self.direct_key {
            validate_content_key(self.algorithm, key)?;
            key.clone()
        } else {
            random_bytes(self.algorithm.key_len())?
        };
        let ciphertext = encrypt_content(self.algorithm, &content_key, plaintext)?;
        let encrypted_keys = self
            .recipients
            .iter()
            .map(|recipient| wrap_content_key(recipient, &content_key))
            .collect::<Result<Vec<_>, _>>()?;
        let encrypted_data_xml = render_encrypted_data(
            self.algorithm,
            encrypted_type.as_ref(),
            self.id.as_deref(),
            self.direct_key_name.as_deref(),
            &encrypted_keys,
            &ciphertext,
        )?;
        let replacement = match encrypted_type {
            Some(EncryptedDataType::Content) => ReplacementMode::ReplaceContent,
            Some(EncryptedDataType::Element | EncryptedDataType::Other(_)) | None => {
                ReplacementMode::ReplaceElement
            }
        };
        Ok(EncryptionResult {
            encrypted_data_xml,
            replacement,
        })
    }

    fn validate_configuration(&self) -> Result<(), XmlEncError> {
        if matches!(self.encrypted_type, EncryptedDataType::Other(_)) {
            return Err(XmlEncError::InvalidEncryptionConfig(
                "Other Type hints are not valid for XML encryption".into(),
            ));
        }
        if self.recipients.len() > MAX_ENCRYPTION_RECIPIENTS {
            return Err(XmlEncError::TooManyRecipients {
                maximum: MAX_ENCRYPTION_RECIPIENTS,
                actual: self.recipients.len(),
            });
        }
        validate_metadata("EncryptedData Id", self.id.as_deref())?;
        validate_key_name("direct KeyName", self.direct_key_name.as_deref())?;
        for recipient in &self.recipients {
            match recipient {
                EncryptionRecipient::RsaOaep {
                    parameters,
                    recipient,
                    key_name,
                    ..
                } => {
                    validate_metadata("EncryptedKey Recipient", recipient.as_deref())?;
                    validate_key_name("EncryptedKey KeyName", key_name.as_deref())?;
                    validate_metadata_len("OAEPparams", parameters.label.len())?;
                }
                EncryptionRecipient::AesKeyWrap {
                    recipient,
                    key_name,
                    ..
                } => {
                    validate_metadata("EncryptedKey Recipient", recipient.as_deref())?;
                    validate_key_name("EncryptedKey KeyName", key_name.as_deref())?;
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
}

fn validate_metadata(field: &'static str, value: Option<&str>) -> Result<(), XmlEncError> {
    validate_metadata_len(field, value.map_or(0, str::len))
}

fn validate_key_name(field: &'static str, value: Option<&str>) -> Result<(), XmlEncError> {
    if value.is_some_and(str::is_empty) {
        return Err(XmlEncError::InvalidEncryptionConfig(format!(
            "{field} must not be empty"
        )));
    }
    validate_metadata(field, value)
}

fn validate_metadata_len(field: &'static str, actual: usize) -> Result<(), XmlEncError> {
    if actual <= MAX_ENCRYPTION_METADATA_LEN {
        Ok(())
    } else {
        Err(XmlEncError::EncryptionMetadataTooLarge {
            field,
            maximum: MAX_ENCRYPTION_METADATA_LEN,
            actual,
        })
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

fn validate_plaintext_len(actual: usize) -> Result<(), XmlEncError> {
    if actual <= MAX_ENCRYPTION_PLAINTEXT_LEN {
        Ok(())
    } else {
        Err(XmlEncError::PlaintextTooLarge {
            maximum: MAX_ENCRYPTION_PLAINTEXT_LEN,
            actual,
        })
    }
}

fn validate_document_len(actual: usize) -> Result<(), XmlEncError> {
    if actual > MAX_ENCRYPTION_DOCUMENT_LEN {
        return Err(XmlEncError::DocumentTooLarge {
            maximum: MAX_ENCRYPTION_DOCUMENT_LEN,
            actual,
        });
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

fn random_bytes(len: usize) -> Result<Vec<u8>, XmlEncError> {
    let mut bytes = vec![0_u8; len];
    SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|error| XmlEncError::Rng(error.to_string()))?;
    Ok(bytes)
}

fn encrypt_content(
    algorithm: DataEncryptionAlgorithm,
    key: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, XmlEncError> {
    validate_content_key(algorithm, key)?;
    match algorithm {
        DataEncryptionAlgorithm::Aes128Cbc => encrypt_cbc::<Aes128>(key, plaintext),
        DataEncryptionAlgorithm::Aes256Cbc => encrypt_cbc::<Aes256>(key, plaintext),
        DataEncryptionAlgorithm::Aes128Gcm => encrypt_gcm::<Aes128Gcm>(key, plaintext),
        DataEncryptionAlgorithm::Aes256Gcm => encrypt_gcm::<Aes256Gcm>(key, plaintext),
    }
}

fn encrypt_cbc<C>(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, XmlEncError>
where
    C: aes::cipher::BlockCipherEncrypt + aes::cipher::KeyInit,
{
    const BLOCK: usize = 16;
    let iv = random_bytes(BLOCK)?;
    let pad_len = BLOCK - (plaintext.len() % BLOCK);
    let mut padded = Vec::with_capacity(plaintext.len() + pad_len);
    padded.extend_from_slice(plaintext);
    if pad_len > 1 {
        padded.extend_from_slice(&random_bytes(pad_len - 1)?);
    }
    padded.push(pad_len as u8);
    let padded_len = padded.len();
    Encryptor::<C>::new_from_slices(key, &iv)
        .map_err(|_| XmlEncError::InvalidKeySize {
            algorithm: if key.len() == 16 {
                DataEncryptionAlgorithm::Aes128Cbc
            } else {
                DataEncryptionAlgorithm::Aes256Cbc
            },
            expected: key.len(),
            actual: key.len(),
        })?
        .encrypt_padded::<NoPadding>(&mut padded, padded_len)
        .map_err(|error| XmlEncError::XmlSerialize(error.to_string()))?;
    let mut output = Vec::with_capacity(BLOCK + padded.len());
    output.extend_from_slice(&iv);
    output.extend_from_slice(&padded);
    Ok(output)
}

fn encrypt_gcm<C>(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, XmlEncError>
where
    C: AeadInOut + KeyInit,
{
    const NONCE_LEN: usize = 12;
    let nonce = random_bytes(NONCE_LEN)?;
    let cipher = C::new_from_slice(key).map_err(|_| XmlEncError::InvalidKeySize {
        algorithm: if key.len() == 16 {
            DataEncryptionAlgorithm::Aes128Gcm
        } else {
            DataEncryptionAlgorithm::Aes256Gcm
        },
        expected: key.len(),
        actual: key.len(),
    })?;
    let mut encrypted = plaintext.to_vec();
    let nonce_value = Nonce::try_from(nonce.as_slice())
        .map_err(|error| XmlEncError::XmlSerialize(error.to_string()))?;
    cipher
        .encrypt_in_place(&nonce_value, b"", &mut encrypted)
        .map_err(|_| XmlEncError::AeadAuthenticationFailed)?;
    let mut output = Vec::with_capacity(NONCE_LEN + encrypted.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&encrypted);
    Ok(output)
}

fn wrap_content_key(
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
            ciphertext: wrap_rsa_oaep(public_key, parameters, content_key)?,
        }),
        EncryptionRecipient::AesKeyWrap {
            kek,
            algorithm,
            recipient,
            key_name,
        } => {
            if kek.len() != algorithm.key_len() {
                return Err(XmlEncError::InvalidKekSize {
                    algorithm: *algorithm,
                    expected: algorithm.key_len(),
                    actual: kek.len(),
                });
            }
            let mut output = vec![0_u8; content_key.len() + 8];
            let wrapped = match algorithm {
                KeyWrapAlgorithm::AesKw128 => KwAes128::new_from_slice(kek)
                    .map_err(|_| invalid_kek_size(*algorithm, kek.len()))?
                    .wrap_key(content_key, &mut output),
                KeyWrapAlgorithm::AesKw256 => KwAes256::new_from_slice(kek)
                    .map_err(|_| invalid_kek_size(*algorithm, kek.len()))?
                    .wrap_key(content_key, &mut output),
            }
            .map_err(|_| XmlEncError::KeyWrapIntegrity)?;
            Ok(WrappedKey {
                algorithm_uri: algorithm.uri(),
                oaep: None,
                recipient: recipient.clone(),
                key_name: key_name.clone(),
                ciphertext: wrapped.to_vec(),
            })
        }
    }
}

fn wrap_rsa_oaep(
    public_key: &RsaPublicKey,
    parameters: &RsaOaepParameters,
    content_key: &[u8],
) -> Result<Vec<u8>, XmlEncError> {
    if parameters.algorithm == super::KeyTransportAlgorithm::RsaOaepMgf1p
        && parameters.mgf_digest != OaepDigestAlgorithm::Sha1
    {
        return Err(XmlEncError::InvalidEncryptionConfig(
            "legacy rsa-oaep-mgf1p requires MGF1-SHA1".into(),
        ));
    }
    let mut rng = SysRng;
    macro_rules! encrypt_with {
        ($digest:ty, $mgf:ty) => {
            // Call `PaddingScheme` directly: it accepts `TryCryptoRng`, so a
            // `SysRng` failure returns `rsa::Error::Rng` for the mapping below
            // instead of entering RSA's infallible `CryptoRng` convenience API.
            Oaep::<$digest, $mgf>::new_with_mgf_hash_and_label(parameters.label.clone()).encrypt(
                &mut rng,
                public_key,
                content_key,
            )
        };
    }
    let result = match (parameters.digest, parameters.mgf_digest) {
        (OaepDigestAlgorithm::Sha1, OaepDigestAlgorithm::Sha1) => {
            encrypt_with!(Sha1, Sha1)
        }
        (OaepDigestAlgorithm::Sha1, OaepDigestAlgorithm::Sha256) => {
            encrypt_with!(Sha1, Sha256)
        }
        (OaepDigestAlgorithm::Sha1, OaepDigestAlgorithm::Sha384) => {
            encrypt_with!(Sha1, Sha384)
        }
        (OaepDigestAlgorithm::Sha1, OaepDigestAlgorithm::Sha512) => {
            encrypt_with!(Sha1, Sha512)
        }
        (OaepDigestAlgorithm::Sha256, OaepDigestAlgorithm::Sha1) => {
            encrypt_with!(Sha256, Sha1)
        }
        (OaepDigestAlgorithm::Sha256, OaepDigestAlgorithm::Sha256) => {
            encrypt_with!(Sha256, Sha256)
        }
        (OaepDigestAlgorithm::Sha256, OaepDigestAlgorithm::Sha384) => {
            encrypt_with!(Sha256, Sha384)
        }
        (OaepDigestAlgorithm::Sha256, OaepDigestAlgorithm::Sha512) => {
            encrypt_with!(Sha256, Sha512)
        }
        (OaepDigestAlgorithm::Sha384, OaepDigestAlgorithm::Sha1) => {
            encrypt_with!(Sha384, Sha1)
        }
        (OaepDigestAlgorithm::Sha384, OaepDigestAlgorithm::Sha256) => {
            encrypt_with!(Sha384, Sha256)
        }
        (OaepDigestAlgorithm::Sha384, OaepDigestAlgorithm::Sha384) => {
            encrypt_with!(Sha384, Sha384)
        }
        (OaepDigestAlgorithm::Sha384, OaepDigestAlgorithm::Sha512) => {
            encrypt_with!(Sha384, Sha512)
        }
        (OaepDigestAlgorithm::Sha512, OaepDigestAlgorithm::Sha1) => {
            encrypt_with!(Sha512, Sha1)
        }
        (OaepDigestAlgorithm::Sha512, OaepDigestAlgorithm::Sha256) => {
            encrypt_with!(Sha512, Sha256)
        }
        (OaepDigestAlgorithm::Sha512, OaepDigestAlgorithm::Sha384) => {
            encrypt_with!(Sha512, Sha384)
        }
        (OaepDigestAlgorithm::Sha512, OaepDigestAlgorithm::Sha512) => {
            encrypt_with!(Sha512, Sha512)
        }
    };
    result.map_err(|error| match error {
        rsa::Error::Rng => XmlEncError::Rng("RSA-OAEP random generation failed".into()),
        error => XmlEncError::RsaEncrypt(error.to_string()),
    })
}

fn invalid_kek_size(algorithm: KeyWrapAlgorithm, actual: usize) -> XmlEncError {
    XmlEncError::InvalidKekSize {
        algorithm,
        expected: algorithm.key_len(),
        actual,
    }
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
) -> Result<(), XmlEncError> {
    match encrypted_type {
        EncryptedDataType::Element => {
            let document = Document::parse(xml)?;
            if !has_single_element_with_boundary_trivia(document.root()) {
                return Err(XmlEncError::InvalidStructure(
                    "Element plaintext must contain exactly one element".into(),
                ));
            }
            Ok(())
        }
        EncryptedDataType::Content => {
            let wrapped = format!("<xmlsec-content>{xml}</xmlsec-content>");
            let _ = Document::parse(&wrapped)?;
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

fn replace_element_content(
    xml: &str,
    range: std::ops::Range<usize>,
    source: &str,
    boundaries: ContentBoundaries,
    encrypted_data: &str,
) -> Result<String, XmlEncError> {
    if !boundaries.self_closing {
        let absolute = range.start + boundaries.content.start..range.start + boundaries.content.end;
        return Ok(replace_range(xml, absolute, encrypted_data));
    }

    let slash = source[..boundaries.start_tag_end]
        .rfind('/')
        .ok_or_else(|| XmlEncError::InvalidStructure("self-closing tag has no slash".into()))?;
    let mut expanded = String::with_capacity(source.len() + encrypted_data.len() + 16);
    expanded.push_str(&source[..slash]);
    expanded.push('>');
    expanded.push_str(encrypted_data);
    expanded.push_str("</");
    expanded.push_str(&boundaries.qualified_name);
    expanded.push('>');
    Ok(replace_range(xml, range, &expanded))
}

fn replace_range(xml: &str, range: std::ops::Range<usize>, replacement: &str) -> String {
    let mut output = String::with_capacity(xml.len() - range.len() + replacement.len());
    output.push_str(&xml[..range.start]);
    output.push_str(replacement);
    output.push_str(&xml[range.end..]);
    output
}

#[cfg(test)]
mod tests {
    use getrandom::rand_core::UnwrapErr;
    use rsa::{RsaPrivateKey, RsaPublicKey};

    use super::*;
    use crate::xmlenc::{
        KekDecryptor, PrivateKeyDecryptor, SymmetricKeyDecryptor, decrypt, decrypt_document,
        parse_encrypted_data,
    };

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
                    allow_dtd: false,
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
                    allow_dtd: false,
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

        assert!(validate_plaintext_len(MAX_ENCRYPTION_PLAINTEXT_LEN).is_ok());
        assert!(matches!(
            validate_plaintext_len(MAX_ENCRYPTION_PLAINTEXT_LEN + 1),
            Err(XmlEncError::PlaintextTooLarge { .. })
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
            Err(XmlEncError::TooManyRecipients { .. })
        ));

        let oversized_metadata = "x".repeat(MAX_ENCRYPTION_METADATA_LEN + 1);
        assert!(matches!(
            EncryptedDataBuilder::new(DataEncryptionAlgorithm::Aes128Gcm)
                .direct_key([0_u8; 16])
                .id(oversized_metadata)
                .encrypt_binary(b"data"),
            Err(XmlEncError::EncryptionMetadataTooLarge { .. })
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
            Err(XmlEncError::PlaintextTooLarge { .. })
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
            Err(XmlEncError::DocumentTooLarge { .. })
        ));
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
