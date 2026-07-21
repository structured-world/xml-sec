//! XMLEnc decryption entry point and key resolvers.

use aes::{
    Aes128, Aes256,
    cipher::{BlockModeDecrypt, KeyIvInit, block_padding::NoPadding},
};
use aes_gcm::{
    Aes128Gcm, Aes256Gcm, Nonce,
    aead::{AeadInOut, KeyInit},
};
use aes_kw::{KwAes128, KwAes256};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use cbc::Decryptor;
use getrandom::{SysRng, rand_core::UnwrapErr};
use roxmltree::{Document, ParsingOptions};
use rsa::{Oaep, RsaPrivateKey};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

use super::parse::parse_encrypted_data_node;
use super::types::XMLENC_NS;
use super::{
    DataEncryptionAlgorithm, DecryptedContent, EncryptedData, EncryptedDataType, EncryptedKey,
    KeyTransportAlgorithm, KeyWrapAlgorithm, XmlEncError, parse_encrypted_data,
};

/// Supplies a content-encryption key for parsed XMLEnc data.
pub trait DecryptionKeyResolver {
    /// Resolve the symmetric key for `algorithm`, optionally unwrapping `encrypted_key`.
    fn resolve_key(
        &self,
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

/// Resolver for direct, pre-shared AES content keys.
#[derive(Debug, Clone)]
pub struct SymmetricKeyDecryptor {
    key: Vec<u8>,
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
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
    ) -> Result<Vec<u8>, XmlEncError> {
        if encrypted_key.is_some() {
            return Err(XmlEncError::KeyNotFound);
        }
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
#[derive(Debug, Clone)]
pub struct KekDecryptor {
    kek: Vec<u8>,
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
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
    ) -> Result<Vec<u8>, XmlEncError> {
        let encrypted_key = encrypted_key.ok_or(XmlEncError::KeyNotFound)?;
        let wrapped = STANDARD
            .decode(&encrypted_key.cipher_data.value)
            .map_err(|error| XmlEncError::Base64(error.to_string()))?;
        let wrap_algorithm =
            KeyWrapAlgorithm::from_uri(&encrypted_key.encryption_method.algorithm)?;
        if self.kek.len() != wrap_algorithm.key_len() {
            return Err(XmlEncError::InvalidKekSize {
                algorithm: wrap_algorithm,
                expected: wrap_algorithm.key_len(),
                actual: self.kek.len(),
            });
        }
        let mut output = vec![0_u8; wrapped.len().saturating_sub(8)];
        let key = match wrap_algorithm {
            KeyWrapAlgorithm::AesKw128 => KwAes128::new_from_slice(&self.kek)
                .map_err(|_| invalid_kek_size(wrap_algorithm, self.kek.len()))?
                .unwrap_key(&wrapped, &mut output),
            KeyWrapAlgorithm::AesKw256 => KwAes256::new_from_slice(&self.kek)
                .map_err(|_| invalid_kek_size(wrap_algorithm, self.kek.len()))?
                .unwrap_key(&wrapped, &mut output),
        }
        .map_err(|_| XmlEncError::KeyWrapIntegrity)?;
        validate_key_len(algorithm, key)?;
        Ok(key.to_vec())
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
        algorithm: DataEncryptionAlgorithm,
        encrypted_key: Option<&EncryptedKey>,
    ) -> Result<Vec<u8>, XmlEncError> {
        let encrypted_key = encrypted_key.ok_or(XmlEncError::KeyNotFound)?;
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
                encrypted_key.encryption_method.oaep_digest.as_deref(),
                label,
                &wrapped,
            ),
            KeyTransportAlgorithm::RsaOaep11 => self.decrypt_oaep11(
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
        digest: Option<&str>,
        label: Vec<u8>,
        wrapped: &[u8],
    ) -> Result<Vec<u8>, XmlEncError> {
        // Every private-key operation is blinded; UnwrapErr adapts the OS RNG
        // to rsa's infallible CryptoRng contract.
        match digest.unwrap_or("http://www.w3.org/2000/09/xmldsig#sha1") {
            "http://www.w3.org/2000/09/xmldsig#sha1" => self
                .key
                .decrypt_blinded(
                    &mut UnwrapErr(SysRng),
                    Oaep::<Sha1>::new_with_label(label),
                    wrapped,
                )
                .map_err(rsa_error),
            "http://www.w3.org/2001/04/xmlenc#sha256" => self
                .key
                .decrypt_blinded(
                    &mut UnwrapErr(SysRng),
                    Oaep::<Sha256, Sha1>::new_with_mgf_hash_and_label(label),
                    wrapped,
                )
                .map_err(rsa_error),
            "http://www.w3.org/2001/04/xmlenc#sha384"
            | "http://www.w3.org/2001/04/xmldsig-more#sha384" => self
                .key
                .decrypt_blinded(
                    &mut UnwrapErr(SysRng),
                    Oaep::<Sha384, Sha1>::new_with_mgf_hash_and_label(label),
                    wrapped,
                )
                .map_err(rsa_error),
            "http://www.w3.org/2001/04/xmlenc#sha512" => self
                .key
                .decrypt_blinded(
                    &mut UnwrapErr(SysRng),
                    Oaep::<Sha512, Sha1>::new_with_mgf_hash_and_label(label),
                    wrapped,
                )
                .map_err(rsa_error),
            unsupported => Err(XmlEncError::UnsupportedAlgorithm(unsupported.to_owned())),
        }
    }

    fn decrypt_oaep11(
        &self,
        digest: Option<&str>,
        mgf: Option<&str>,
        label: Vec<u8>,
        wrapped: &[u8],
    ) -> Result<Vec<u8>, XmlEncError> {
        const SHA1: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
        const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
        const SHA384: &str = "http://www.w3.org/2001/04/xmlenc#sha384";
        const SHA384_COMPAT: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
        const SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";
        const MGF1_SHA1: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha1";
        const MGF1_SHA256: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha256";
        const MGF1_SHA384: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha384";
        const MGF1_SHA512: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha512";

        macro_rules! decrypt_with {
            ($digest:ty, $mgf:ty) => {
                self.key
                    .decrypt_blinded(
                        &mut UnwrapErr(SysRng),
                        Oaep::<$digest, $mgf>::new_with_mgf_hash_and_label(label),
                        wrapped,
                    )
                    .map_err(rsa_error)
            };
        }

        let digest = match digest.unwrap_or(SHA1) {
            SHA384_COMPAT => SHA384,
            digest => digest,
        };
        match (digest, mgf.unwrap_or(MGF1_SHA1)) {
            (SHA1, MGF1_SHA1) => decrypt_with!(Sha1, Sha1),
            (SHA1, MGF1_SHA256) => decrypt_with!(Sha1, Sha256),
            (SHA1, MGF1_SHA384) => decrypt_with!(Sha1, Sha384),
            (SHA1, MGF1_SHA512) => decrypt_with!(Sha1, Sha512),
            (SHA256, MGF1_SHA1) => decrypt_with!(Sha256, Sha1),
            (SHA256, MGF1_SHA256) => decrypt_with!(Sha256, Sha256),
            (SHA256, MGF1_SHA384) => decrypt_with!(Sha256, Sha384),
            (SHA256, MGF1_SHA512) => decrypt_with!(Sha256, Sha512),
            (SHA384, MGF1_SHA1) => decrypt_with!(Sha384, Sha1),
            (SHA384, MGF1_SHA256) => decrypt_with!(Sha384, Sha256),
            (SHA384, MGF1_SHA384) => decrypt_with!(Sha384, Sha384),
            (SHA384, MGF1_SHA512) => decrypt_with!(Sha384, Sha512),
            (SHA512, MGF1_SHA1) => decrypt_with!(Sha512, Sha1),
            (SHA512, MGF1_SHA256) => decrypt_with!(Sha512, Sha256),
            (SHA512, MGF1_SHA384) => decrypt_with!(Sha512, Sha384),
            (SHA512, MGF1_SHA512) => decrypt_with!(Sha512, Sha512),
            (unsupported, MGF1_SHA1 | MGF1_SHA256 | MGF1_SHA384 | MGF1_SHA512) => {
                Err(XmlEncError::UnsupportedAlgorithm(unsupported.to_owned()))
            }
            (_, unsupported) => Err(XmlEncError::UnsupportedAlgorithm(unsupported.to_owned())),
        }
    }
}

fn rsa_error(error: rsa::Error) -> XmlEncError {
    XmlEncError::Rsa(error.to_string())
}

fn invalid_kek_size(algorithm: KeyWrapAlgorithm, actual: usize) -> XmlEncError {
    XmlEncError::InvalidKekSize {
        algorithm,
        expected: algorithm.key_len(),
        actual,
    }
}

/// Parse and decrypt a standalone `EncryptedData` XML fragment.
pub fn decrypt(
    xml: &str,
    resolver: &dyn DecryptionKeyResolver,
) -> Result<DecryptedContent, XmlEncError> {
    let encrypted = parse_encrypted_data(xml)?;
    decrypt_data(&encrypted, resolver)
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
    let parsing_options = || ParsingOptions {
        allow_dtd: options.allow_dtd,
        entity_resolver: None,
        ..ParsingOptions::default()
    };
    let document = Document::parse_with_options(xml, parsing_options())?;
    let mut matches = document.descendants().filter(|node| {
        node.has_tag_name((XMLENC_NS, "EncryptedData"))
            && options
                .encrypted_data_id
                .is_none_or(|id| node.attribute("Id") == Some(id))
    });
    let selected = matches.next().ok_or(XmlEncError::EncryptedDataNotFound)?;
    if matches.next().is_some() {
        return Err(XmlEncError::AmbiguousEncryptedData);
    }

    let range = selected.range();
    let encrypted = parse_encrypted_data_node(selected)?;
    let DecryptedContent::Xml(plaintext) = decrypt_data(&encrypted, resolver)? else {
        return Err(XmlEncError::ReplacementRequiresXml);
    };

    validate_plaintext_fragment(
        xml,
        range.start,
        range.end,
        &plaintext,
        encrypted.encrypted_type.as_ref(),
        options.allow_dtd,
    )?;

    let mut output = String::with_capacity(xml.len() - range.len() + plaintext.len());
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
    allow_dtd: bool,
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
        ParsingOptions {
            allow_dtd,
            entity_resolver: None,
            ..ParsingOptions::default()
        },
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

    if matches!(encrypted_type, Some(EncryptedDataType::Element)) {
        let mut children = wrapper.children();
        if !children.next().is_some_and(|node| node.is_element()) || children.next().is_some() {
            return Err(XmlEncError::InvalidStructure(
                "Element plaintext must contain exactly one element".into(),
            ));
        }
    }
    Ok(())
}

/// Decrypt an already parsed `EncryptedData` value.
pub fn decrypt_data(
    encrypted: &EncryptedData,
    resolver: &dyn DecryptionKeyResolver,
) -> Result<DecryptedContent, XmlEncError> {
    let algorithm = DataEncryptionAlgorithm::from_uri(&encrypted.encryption_method.algorithm)?;
    let key = resolver.resolve_key(algorithm, encrypted.encrypted_key.as_ref())?;
    validate_key_len(algorithm, &key)?;
    let ciphertext = STANDARD
        .decode(&encrypted.cipher_data.value)
        .map_err(|error| XmlEncError::Base64(error.to_string()))?;
    let plaintext = decrypt_content(algorithm, &key, &ciphertext)?;
    match encrypted.encrypted_type.as_ref() {
        Some(EncryptedDataType::Element | EncryptedDataType::Content) => {
            Ok(DecryptedContent::Xml(String::from_utf8(plaintext)?))
        }
        Some(EncryptedDataType::Other(_)) | None => Ok(DecryptedContent::Bytes(plaintext)),
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

fn decrypt_content(
    algorithm: DataEncryptionAlgorithm,
    key: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, XmlEncError> {
    match algorithm {
        DataEncryptionAlgorithm::Aes128Gcm => decrypt_gcm::<Aes128Gcm>(key, ciphertext),
        DataEncryptionAlgorithm::Aes256Gcm => decrypt_gcm::<Aes256Gcm>(key, ciphertext),
        DataEncryptionAlgorithm::Aes128Cbc => decrypt_cbc_128(key, ciphertext),
        DataEncryptionAlgorithm::Aes256Cbc => decrypt_cbc_256(key, ciphertext),
    }
}

fn decrypt_gcm<C>(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, XmlEncError>
where
    C: AeadInOut + KeyInit,
{
    const NONCE_LEN: usize = 12;
    const TAG_LEN: usize = 16;
    if ciphertext.len() < NONCE_LEN + TAG_LEN {
        return Err(XmlEncError::DataTooShort {
            algorithm: "AES-GCM",
            minimum: NONCE_LEN + TAG_LEN,
            actual: ciphertext.len(),
        });
    }
    let (nonce, encrypted) = ciphertext.split_at(NONCE_LEN);
    let cipher = C::new_from_slice(key).map_err(|_| XmlEncError::AeadAuthenticationFailed)?;
    let mut output = encrypted.to_vec();
    let nonce = Nonce::try_from(nonce).map_err(|_| XmlEncError::AeadAuthenticationFailed)?;
    cipher
        .decrypt_in_place(&nonce, b"", &mut output)
        .map_err(|_| XmlEncError::AeadAuthenticationFailed)?;
    Ok(output)
}

fn cbc_input(ciphertext: &[u8]) -> Result<(&[u8], &[u8]), XmlEncError> {
    const BLOCK: usize = 16;
    if ciphertext.len() < BLOCK * 2 {
        return Err(XmlEncError::DataTooShort {
            algorithm: "AES-CBC",
            minimum: BLOCK * 2,
            actual: ciphertext.len(),
        });
    }
    let (iv, encrypted) = ciphertext.split_at(BLOCK);
    if encrypted.len() % BLOCK != 0 {
        return Err(XmlEncError::InvalidCbcCiphertextLength(encrypted.len()));
    }
    Ok((iv, encrypted))
}

fn remove_cbc_padding(plaintext: &[u8]) -> Result<Vec<u8>, XmlEncError> {
    const BLOCK: usize = 16;
    let pad_len = *plaintext.last().ok_or(XmlEncError::DataTooShort {
        algorithm: "AES-CBC",
        minimum: 1,
        actual: 0,
    })?;
    if pad_len == 0 || usize::from(pad_len) > BLOCK {
        return Err(XmlEncError::InvalidPadding {
            pad_len,
            block_size: BLOCK,
        });
    }
    Ok(plaintext[..plaintext.len() - usize::from(pad_len)].to_vec())
}

fn decrypt_cbc_128(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, XmlEncError> {
    let (iv, encrypted) = cbc_input(ciphertext)?;
    let mut output = encrypted.to_vec();
    let plaintext = Decryptor::<Aes128>::new_from_slices(key, iv)
        .map_err(|_| XmlEncError::InvalidKeySize {
            algorithm: DataEncryptionAlgorithm::Aes128Cbc,
            expected: 16,
            actual: key.len(),
        })?
        .decrypt_padded::<NoPadding>(&mut output)
        .map_err(|_| XmlEncError::InvalidCbcCiphertextLength(encrypted.len()))?;
    remove_cbc_padding(plaintext)
}

fn decrypt_cbc_256(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, XmlEncError> {
    let (iv, encrypted) = cbc_input(ciphertext)?;
    let mut output = encrypted.to_vec();
    let plaintext = Decryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|_| XmlEncError::InvalidKeySize {
            algorithm: DataEncryptionAlgorithm::Aes256Cbc,
            expected: 32,
            actual: key.len(),
        })?
        .decrypt_padded::<NoPadding>(&mut output)
        .map_err(|_| XmlEncError::InvalidCbcCiphertextLength(encrypted.len()))?;
    remove_cbc_padding(plaintext)
}

#[cfg(test)]
mod tests {
    use aes_gcm::{
        Aes128Gcm,
        aead::{AeadInOut, KeyInit},
    };
    use aes_kw::KwAes128;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
    use rsa::{RsaPublicKey, pkcs8::DecodePrivateKey};

    use super::*;

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
    fn handles_xmlenc_cbc_padding_boundaries() {
        // XMLEnc permits random padding bytes and uses only the final byte as
        // the length, including the one-byte and full-block boundaries.
        assert_eq!(
            remove_cbc_padding(b"plaintext\x01").expect("one-byte padding must be valid"),
            b"plaintext"
        );
        let mut full_block = [0x5a_u8; 16];
        full_block[15] = 16;
        assert_eq!(
            remove_cbc_padding(&full_block).expect("full-block padding must be valid"),
            Vec::<u8>::new()
        );
        assert!(matches!(
            remove_cbc_padding(&[0]),
            Err(XmlEncError::InvalidPadding { pad_len: 0, .. })
        ));
        assert!(matches!(
            remove_cbc_padding(&[17]),
            Err(XmlEncError::InvalidPadding { pad_len: 17, .. })
        ));
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
            .resolve_key(DataEncryptionAlgorithm::Aes128Gcm, Some(&encrypted_key))
            .expect("wrapped session key must resolve");
        assert_eq!(resolved, session_key);
    }

    #[test]
    fn rejects_truncated_gcm_and_invalid_wrapped_key() {
        // Framing and key-wrap integrity failures must occur before content is exposed.
        assert!(matches!(
            decrypt_content(DataEncryptionAlgorithm::Aes128Gcm, &[0_u8; 16], &[0_u8; 27]),
            Err(XmlEncError::DataTooShort {
                algorithm: "AES-GCM",
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
            KekDecryptor::new([0_u8; 16])
                .resolve_key(DataEncryptionAlgorithm::Aes128Gcm, Some(&encrypted_key)),
            Err(XmlEncError::KeyWrapIntegrity)
        ));
        assert!(matches!(
            KekDecryptor::new([0_u8; 32])
                .resolve_key(DataEncryptionAlgorithm::Aes128Gcm, Some(&encrypted_key)),
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
            .resolve_key(DataEncryptionAlgorithm::Aes128Gcm, Some(&encrypted_key))
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
            .resolve_key(DataEncryptionAlgorithm::Aes128Gcm, Some(&encrypted_key))
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
                .resolve_key(DataEncryptionAlgorithm::Aes128Gcm, Some(&encrypted_key))
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
            decryptor.resolve_key(DataEncryptionAlgorithm::Aes128Gcm, Some(&encrypted_key)),
            Err(XmlEncError::UnsupportedAlgorithm(uri)) if uri == "urn:unsupported:digest"
        ));

        encrypted_key.encryption_method.oaep_digest = None;
        encrypted_key.encryption_method.mgf_algorithm = Some("urn:unsupported:mgf".into());
        assert!(matches!(
            decryptor.resolve_key(DataEncryptionAlgorithm::Aes128Gcm, Some(&encrypted_key)),
            Err(XmlEncError::UnsupportedAlgorithm(uri)) if uri == "urn:unsupported:mgf"
        ));
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
