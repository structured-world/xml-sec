//! Public XMLEnc data structures and errors.

use std::fmt;

/// XML Encryption 1.0 namespace.
pub const XMLENC_NS: &str = "http://www.w3.org/2001/04/xmlenc#";
/// XML Encryption 1.1 namespace.
pub const XMLENC11_NS: &str = "http://www.w3.org/2009/xmlenc11#";
/// XML Signature namespace, used by OAEP parameter elements.
pub const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

/// Maximum normalized base64 text accepted from a `CipherValue`.
pub const MAX_CIPHER_VALUE_BASE64_LEN: usize = 16 * 1024 * 1024;

/// The `Type` attribute on an `EncryptedData` element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptedDataType {
    /// The plaintext contains one complete XML element.
    Element,
    /// The plaintext contains the encrypted element's child content.
    Content,
    /// An application-defined or empty type hint whose plaintext remains opaque.
    Other(String),
}

/// Supported content-encryption algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataEncryptionAlgorithm {
    /// AES-128 in CBC mode with XMLEnc padding.
    Aes128Cbc,
    /// AES-256 in CBC mode with XMLEnc padding.
    Aes256Cbc,
    /// AES-128 in GCM mode.
    Aes128Gcm,
    /// AES-256 in GCM mode.
    Aes256Gcm,
}

impl DataEncryptionAlgorithm {
    /// Parse a supported XMLEnc content-encryption URI.
    pub fn from_uri(uri: &str) -> Result<Self, XmlEncError> {
        match uri {
            "http://www.w3.org/2001/04/xmlenc#aes128-cbc" => Ok(Self::Aes128Cbc),
            "http://www.w3.org/2001/04/xmlenc#aes256-cbc" => Ok(Self::Aes256Cbc),
            "http://www.w3.org/2009/xmlenc11#aes128-gcm" => Ok(Self::Aes128Gcm),
            "http://www.w3.org/2009/xmlenc11#aes256-gcm" => Ok(Self::Aes256Gcm),
            _ => Err(XmlEncError::UnsupportedAlgorithm(uri.to_owned())),
        }
    }

    /// Required symmetric key length in bytes.
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Cbc | Self::Aes128Gcm => 16,
            Self::Aes256Cbc | Self::Aes256Gcm => 32,
        }
    }
}

impl KeyTransportAlgorithm {
    /// Parse a supported XMLEnc key-transport URI.
    pub fn from_uri(uri: &str) -> Result<Self, XmlEncError> {
        match uri {
            "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p" => Ok(Self::RsaOaepMgf1p),
            "http://www.w3.org/2009/xmlenc11#rsa-oaep" => Ok(Self::RsaOaep11),
            _ => Err(XmlEncError::UnsupportedAlgorithm(uri.to_owned())),
        }
    }
}

impl KeyWrapAlgorithm {
    /// Parse a supported XMLEnc symmetric key-wrap URI.
    pub fn from_uri(uri: &str) -> Result<Self, XmlEncError> {
        match uri {
            "http://www.w3.org/2001/04/xmlenc#kw-aes128" => Ok(Self::AesKw128),
            "http://www.w3.org/2001/04/xmlenc#kw-aes256" => Ok(Self::AesKw256),
            _ => Err(XmlEncError::UnsupportedAlgorithm(uri.to_owned())),
        }
    }

    /// Required key-encryption-key length in bytes.
    pub const fn key_len(self) -> usize {
        match self {
            Self::AesKw128 => 16,
            Self::AesKw256 => 32,
        }
    }
}

/// Supported asymmetric session-key transport algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyTransportAlgorithm {
    /// XML Encryption 1.0 OAEP with SHA-1 and MGF1-SHA-1.
    RsaOaepMgf1p,
    /// XML Encryption 1.1 OAEP with explicitly parsed digest and MGF settings.
    RsaOaep11,
}

/// Supported symmetric key-wrap algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyWrapAlgorithm {
    /// RFC 3394 AES key wrap with a 128-bit KEK.
    AesKw128,
    /// RFC 3394 AES key wrap with a 256-bit KEK.
    AesKw256,
}

/// Parsed `EncryptionMethod` data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionMethod {
    /// Algorithm URI from the mandatory `Algorithm` attribute.
    pub algorithm: String,
    /// Optional explicit key size in bits.
    pub key_size_bits: Option<usize>,
    /// Digest URI used by XML Encryption 1.1 OAEP.
    pub oaep_digest: Option<String>,
    /// MGF URI used by XML Encryption 1.1 OAEP.
    pub mgf_algorithm: Option<String>,
    /// Decoded OAEP label bytes.
    pub oaep_params: Option<Vec<u8>>,
}

/// Inline ciphertext data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CipherData {
    /// Whitespace-normalized base64 text from `CipherValue`.
    pub value: String,
}

/// Parsed embedded `EncryptedKey` used to recover a content-encryption key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedKey {
    /// Optional XML identifier.
    pub id: Option<String>,
    /// Optional recipient hint.
    pub recipient: Option<String>,
    /// Optional direct `ds:KeyName` hint from the key's `KeyInfo`.
    pub key_name: Option<String>,
    /// Method which wrapped the session key.
    pub encryption_method: EncryptionMethod,
    /// Wrapped session-key bytes in base64 form.
    pub cipher_data: CipherData,
    /// Optional references identifying data or keys associated with this key.
    pub reference_list: Option<ReferenceList>,
    /// Optional name associated with the transported plaintext key.
    pub carried_key_name: Option<String>,
}

/// References associated with an `EncryptedKey`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceList {
    /// URI references to `EncryptedData` elements encrypted with this key.
    pub data_references: Vec<String>,
    /// URI references to other `EncryptedKey` elements encrypted with this key.
    pub key_references: Vec<String>,
}

/// Parsed `EncryptedData` document fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedData {
    /// Optional XML identifier.
    pub id: Option<String>,
    /// Optional plaintext representation hint.
    pub encrypted_type: Option<EncryptedDataType>,
    /// Optional direct `ds:KeyName` hint from `KeyInfo`.
    pub key_name: Option<String>,
    /// Content-encryption method.
    pub encryption_method: EncryptionMethod,
    /// Embedded recipient session keys in `KeyInfo` document order.
    pub encrypted_keys: Vec<EncryptedKey>,
    /// Content ciphertext in base64 form.
    pub cipher_data: CipherData,
}

/// Plaintext returned from XMLEnc decryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptedContent {
    /// XML plaintext for `Element` and `Content` encrypted data.
    Xml(String),
    /// Binary plaintext when the encrypted data has no standard XML type hint.
    Bytes(Vec<u8>),
}

/// Errors raised while parsing, resolving, or decrypting XMLEnc data.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum XmlEncError {
    /// XML document parsing failed.
    #[error("XML parsing error: {0}")]
    XmlParse(#[from] roxmltree::Error),
    /// Required child element or attribute was absent.
    #[error("missing required {0}")]
    MissingRequired(&'static str),
    /// The XML element order or namespace is invalid for the XMLEnc profile.
    #[error("invalid encrypted structure: {0}")]
    InvalidStructure(String),
    /// An algorithm URI is not supported by this build.
    #[error("unsupported encryption algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// Base64 input is invalid or exceeds the configured input bound.
    #[error("invalid base64 data: {0}")]
    Base64(String),
    /// A decoded cipher value is too short for its algorithm's framing.
    #[error("{algorithm} ciphertext is too short: need at least {minimum} bytes, got {actual}")]
    DataTooShort {
        /// Algorithm name.
        algorithm: &'static str,
        /// Minimum valid byte length.
        minimum: usize,
        /// Actual byte length.
        actual: usize,
    },
    /// CBC ciphertext is not a non-empty multiple of the AES block size.
    #[error("AES-CBC ciphertext length must be a non-zero multiple of 16 bytes, got {0}")]
    InvalidCbcCiphertextLength(usize),
    /// XMLEnc's final random-padding length byte is invalid.
    #[error("invalid XMLEnc padding length {pad_len} for {block_size}-byte block")]
    InvalidPadding {
        /// Padding length from plaintext's final byte.
        pad_len: u8,
        /// Cipher block size.
        block_size: usize,
    },
    /// GCM authentication failed.
    #[error("AES-GCM authentication failed")]
    AeadAuthenticationFailed,
    /// A supplied content key is not the expected size.
    #[error("{algorithm:?} requires a {expected}-byte key, got {actual}")]
    InvalidKeySize {
        /// Content algorithm requiring the key.
        algorithm: DataEncryptionAlgorithm,
        /// Expected key size.
        expected: usize,
        /// Actual key size.
        actual: usize,
    },
    /// A supplied AES key-encryption key is not the size declared by EncryptedKey.
    #[error("{algorithm:?} requires a {expected}-byte KEK, got {actual}")]
    InvalidKekSize {
        /// Key-wrap algorithm requiring the KEK.
        algorithm: KeyWrapAlgorithm,
        /// Expected KEK size.
        expected: usize,
        /// Actual KEK size.
        actual: usize,
    },
    /// No caller-provided resolver could supply a usable key.
    #[error("no suitable decryption key was resolved")]
    KeyNotFound,
    /// No `EncryptedData` matched the requested document selection.
    #[error("no matching EncryptedData element was found")]
    EncryptedDataNotFound,
    /// More than one `EncryptedData` matched the requested document selection.
    #[error("more than one EncryptedData element matched; select one by Id")]
    AmbiguousEncryptedData,
    /// Document replacement requires an XML `Type` declaration.
    #[error("EncryptedData must declare Element or Content Type for document replacement")]
    ReplacementRequiresXml,
    /// RSA-OAEP session-key recovery failed.
    #[error("RSA-OAEP key unwrap failed: {0}")]
    Rsa(String),
    /// RFC 3394 integrity validation failed while unwrapping a key.
    #[error("AES key unwrap failed integrity validation")]
    KeyWrapIntegrity,
    /// XML-declared plaintext could not be decoded as UTF-8.
    #[error("decrypted XML is not valid UTF-8: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}

impl fmt::Display for DataEncryptionAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Aes128Cbc => "AES-128-CBC",
            Self::Aes256Cbc => "AES-256-CBC",
            Self::Aes128Gcm => "AES-128-GCM",
            Self::Aes256Gcm => "AES-256-GCM",
        })
    }
}
