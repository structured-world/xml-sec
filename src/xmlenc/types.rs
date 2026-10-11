//! Public XMLEnc data structures and errors.

use std::{fmt, sync::Arc};

use rsa::RsaPublicKey;

/// XML Encryption 1.0 namespace.
pub const XMLENC_NS: &str = "http://www.w3.org/2001/04/xmlenc#";
/// XML Encryption 1.1 namespace.
pub const XMLENC11_NS: &str = "http://www.w3.org/2009/xmlenc11#";
/// XML Signature namespace, used by OAEP parameter elements.
pub const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

/// Maximum normalized base64 text accepted from a `CipherValue`.
pub const MAX_CIPHER_VALUE_BASE64_LEN: usize =
    crate::hard_limits::ENCRYPTION_CIPHER_VALUE_BASE64_BYTE_CEILING;
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataEncryptionAlgorithm {
    /// Legacy three-key Triple DES CBC, available only with explicit policy permission.
    #[cfg(feature = "legacy-algorithms")]
    TripleDesCbc,
    /// AES-192 CBC compatibility capability.
    #[cfg(feature = "legacy-algorithms")]
    Aes192Cbc,
    /// AES-192 GCM compatibility capability.
    #[cfg(feature = "legacy-algorithms")]
    Aes192Gcm,
    /// AES-128 in CBC mode with XMLEnc padding.
    Aes128Cbc,
    /// AES-256 in CBC mode with XMLEnc padding.
    Aes256Cbc,
    /// AES-128 in GCM mode.
    Aes128Gcm,
    /// AES-256 in GCM mode.
    Aes256Gcm,
    /// Camellia CBC with a 128-bit key (RFC 9231 §2.6.2).
    Camellia128Cbc,
    /// Camellia CBC with a 192-bit key.
    Camellia192Cbc,
    /// Camellia CBC with a 256-bit key.
    Camellia256Cbc,
    /// RFC 9231 ChaCha20 profile; unauthenticated and opt-in.
    ChaCha20,
    /// ChaCha20-Poly1305 with XML-carried nonce and optional AAD.
    ChaCha20Poly1305,
}

impl DataEncryptionAlgorithm {
    /// Whether successful decryption cryptographically authenticates the key.
    pub const fn is_authenticated(self) -> bool {
        // RFC 9231 §§2.6.7-2.6.8 distinguishes the stream cipher from AEAD.
        // https://www.rfc-editor.org/rfc/rfc9231.html#section-2.6.8
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm | Self::ChaCha20Poly1305 => true,
            #[cfg(feature = "legacy-algorithms")]
            Self::Aes192Gcm => true,
            Self::Aes128Cbc
            | Self::Aes256Cbc
            | Self::Camellia128Cbc
            | Self::Camellia192Cbc
            | Self::Camellia256Cbc
            | Self::ChaCha20 => false,
            #[cfg(feature = "legacy-algorithms")]
            Self::TripleDesCbc | Self::Aes192Cbc => false,
        }
    }

    /// Key family required independently of the byte length (AES-192 and
    /// three-key Triple DES both use 24 bytes).
    pub const fn key_kind(self) -> crate::key_manager::SymmetricKeyKind {
        if matches!(self, Self::ChaCha20 | Self::ChaCha20Poly1305) {
            return crate::key_manager::SymmetricKeyKind::ChaCha20;
        }
        if matches!(
            self,
            Self::Camellia128Cbc | Self::Camellia192Cbc | Self::Camellia256Cbc
        ) {
            return crate::key_manager::SymmetricKeyKind::Camellia;
        }
        #[cfg(feature = "legacy-algorithms")]
        if matches!(self, Self::TripleDesCbc) {
            return crate::key_manager::SymmetricKeyKind::Des;
        }
        crate::key_manager::SymmetricKeyKind::Aes
    }
    /// Parse a supported XMLEnc content-encryption URI.
    pub fn from_uri(uri: &str) -> Result<Self, XmlEncError> {
        match uri {
            #[cfg(feature = "legacy-algorithms")]
            "http://www.w3.org/2001/04/xmlenc#tripledes-cbc" => Ok(Self::TripleDesCbc),
            #[cfg(feature = "legacy-algorithms")]
            "http://www.w3.org/2001/04/xmlenc#aes192-cbc" => Ok(Self::Aes192Cbc),
            #[cfg(feature = "legacy-algorithms")]
            "http://www.w3.org/2009/xmlenc11#aes192-gcm" => Ok(Self::Aes192Gcm),
            "http://www.w3.org/2001/04/xmlenc#aes128-cbc" => Ok(Self::Aes128Cbc),
            "http://www.w3.org/2001/04/xmlenc#aes256-cbc" => Ok(Self::Aes256Cbc),
            "http://www.w3.org/2009/xmlenc11#aes128-gcm" => Ok(Self::Aes128Gcm),
            "http://www.w3.org/2009/xmlenc11#aes256-gcm" => Ok(Self::Aes256Gcm),
            "http://www.w3.org/2001/04/xmldsig-more#camellia128-cbc" => Ok(Self::Camellia128Cbc),
            "http://www.w3.org/2001/04/xmldsig-more#camellia192-cbc" => Ok(Self::Camellia192Cbc),
            "http://www.w3.org/2001/04/xmldsig-more#camellia256-cbc" => Ok(Self::Camellia256Cbc),
            "http://www.w3.org/2021/04/xmldsig-more#chacha20" => Ok(Self::ChaCha20),
            "http://www.w3.org/2021/04/xmldsig-more#chacha20poly1305" => Ok(Self::ChaCha20Poly1305),
            _ => Err(XmlEncError::UnsupportedAlgorithm(uri.to_owned())),
        }
    }

    /// Required symmetric key length in bytes.
    pub const fn key_len(self) -> usize {
        match self {
            #[cfg(feature = "legacy-algorithms")]
            Self::TripleDesCbc | Self::Aes192Cbc | Self::Aes192Gcm => 24,
            Self::Aes128Cbc | Self::Aes128Gcm => 16,
            Self::Aes256Cbc | Self::Aes256Gcm => 32,
            Self::Camellia128Cbc => 16,
            Self::Camellia192Cbc => 24,
            Self::Camellia256Cbc => 32,
            Self::ChaCha20 | Self::ChaCha20Poly1305 => 32,
        }
    }

    /// Return the standard XMLEnc algorithm URI.
    pub const fn uri(self) -> &'static str {
        match self {
            #[cfg(feature = "legacy-algorithms")]
            Self::TripleDesCbc => "http://www.w3.org/2001/04/xmlenc#tripledes-cbc",
            #[cfg(feature = "legacy-algorithms")]
            Self::Aes192Cbc => "http://www.w3.org/2001/04/xmlenc#aes192-cbc",
            #[cfg(feature = "legacy-algorithms")]
            Self::Aes192Gcm => "http://www.w3.org/2009/xmlenc11#aes192-gcm",
            Self::Aes128Cbc => "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
            Self::Aes256Cbc => "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
            Self::Aes128Gcm => "http://www.w3.org/2009/xmlenc11#aes128-gcm",
            Self::Aes256Gcm => "http://www.w3.org/2009/xmlenc11#aes256-gcm",
            Self::Camellia128Cbc => "http://www.w3.org/2001/04/xmldsig-more#camellia128-cbc",
            Self::Camellia192Cbc => "http://www.w3.org/2001/04/xmldsig-more#camellia192-cbc",
            Self::Camellia256Cbc => "http://www.w3.org/2001/04/xmldsig-more#camellia256-cbc",
            Self::ChaCha20 => "http://www.w3.org/2021/04/xmldsig-more#chacha20",
            Self::ChaCha20Poly1305 => "http://www.w3.org/2021/04/xmldsig-more#chacha20poly1305",
        }
    }

    /// Minimum standard wire length for ciphertext produced by this algorithm.
    pub(crate) const fn minimum_ciphertext_len(self) -> usize {
        if matches!(self, Self::ChaCha20) {
            return 0;
        }
        if matches!(self, Self::ChaCha20Poly1305) {
            return 16;
        }
        match self.cbc_block_len() {
            Some(block) => block * 2,
            None => 28,
        }
    }

    /// Compile-time capability is not the operation's permission.
    /// Whether this capability must be explicitly selected in the operation allowlist.
    pub const fn requires_explicit_permission(self) -> bool {
        match self {
            Self::Camellia128Cbc | Self::Camellia192Cbc | Self::Camellia256Cbc => true,
            Self::ChaCha20 | Self::ChaCha20Poly1305 => true,
            #[cfg(feature = "legacy-algorithms")]
            Self::TripleDesCbc | Self::Aes192Cbc | Self::Aes192Gcm => true,
            _ => false,
        }
    }

    pub(crate) const fn cbc_block_len(self) -> Option<usize> {
        // XMLEnc 1.1 §§5.2.2-5.2.4: CBC frames prefix one cipher block;
        // GCM instead prefixes a 96-bit nonce and appends a 128-bit tag.
        // https://www.w3.org/TR/xmlenc-core1/#sec-Block-Encryption
        match self {
            Self::Aes128Cbc | Self::Aes256Cbc => Some(16),
            Self::Camellia128Cbc | Self::Camellia192Cbc | Self::Camellia256Cbc => Some(16),
            #[cfg(feature = "legacy-algorithms")]
            Self::Aes192Cbc => Some(16),
            #[cfg(feature = "legacy-algorithms")]
            Self::TripleDesCbc => Some(8),
            _ => None,
        }
    }

    /// Exact wire length produced when encrypting the given plaintext length.
    pub(crate) fn ciphertext_len_for_plaintext(self, plaintext_len: usize) -> Option<usize> {
        if matches!(self, Self::ChaCha20) {
            return Some(plaintext_len);
        }
        if matches!(self, Self::ChaCha20Poly1305) {
            return plaintext_len.checked_add(16);
        }
        match self.cbc_block_len() {
            Some(block) => (plaintext_len / block)
                .checked_add(1)?
                .checked_mul(block)?
                .checked_add(block),
            None => plaintext_len.checked_add(28),
        }
    }
}

pub(crate) fn validate_ciphertext_framing(
    algorithm: DataEncryptionAlgorithm,
    ciphertext_len: usize,
) -> Result<(), XmlEncError> {
    let minimum = algorithm.minimum_ciphertext_len();
    if ciphertext_len < minimum {
        let algorithm_name = match algorithm {
            DataEncryptionAlgorithm::ChaCha20 => "ChaCha20",
            DataEncryptionAlgorithm::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            DataEncryptionAlgorithm::Camellia128Cbc
            | DataEncryptionAlgorithm::Camellia192Cbc
            | DataEncryptionAlgorithm::Camellia256Cbc => "Camellia-CBC",
            _ => match algorithm.cbc_block_len() {
                Some(8) => "Triple DES CBC",
                Some(_) => "AES-CBC",
                None => "AES-GCM",
            },
        };
        return Err(XmlEncError::DataTooShort {
            algorithm: algorithm_name,
            minimum,
            actual: ciphertext_len,
        });
    }
    if let Some(block) = algorithm.cbc_block_len()
        && !(ciphertext_len - block).is_multiple_of(block)
    {
        return Err(XmlEncError::InvalidCbcCiphertextLength {
            algorithm,
            block,
            actual: ciphertext_len - block,
        });
    }
    Ok(())
}

impl KeyTransportAlgorithm {
    /// Historical transport is never enabled merely by compiling its primitive.
    pub const fn requires_explicit_permission(self) -> bool {
        match self {
            #[cfg(feature = "legacy-algorithms")]
            Self::RsaPkcs1v15 => true,
            _ => false,
        }
    }
    /// Parse a supported XMLEnc key-transport URI.
    pub fn from_uri(uri: &str) -> Result<Self, XmlEncError> {
        match uri {
            "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p" => Ok(Self::RsaOaepMgf1p),
            "http://www.w3.org/2009/xmlenc11#rsa-oaep" => Ok(Self::RsaOaep11),
            #[cfg(feature = "legacy-algorithms")]
            "http://www.w3.org/2001/04/xmlenc#rsa-1_5" => Ok(Self::RsaPkcs1v15),
            _ => Err(XmlEncError::UnsupportedAlgorithm(uri.to_owned())),
        }
    }

    /// Return the standard XMLEnc key-transport URI.
    pub const fn uri(self) -> &'static str {
        match self {
            Self::RsaOaepMgf1p => "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
            Self::RsaOaep11 => "http://www.w3.org/2009/xmlenc11#rsa-oaep",
            #[cfg(feature = "legacy-algorithms")]
            Self::RsaPkcs1v15 => "http://www.w3.org/2001/04/xmlenc#rsa-1_5",
        }
    }
}

impl KeyWrapAlgorithm {
    /// Family of the wrapping key, not of the wrapped content key.
    pub const fn key_kind(self) -> crate::key_manager::SymmetricKeyKind {
        if let Self::Cbc(algorithm) = self {
            return algorithm.key_kind();
        }
        if matches!(
            self,
            Self::CamelliaKw128 | Self::CamelliaKw192 | Self::CamelliaKw256
        ) {
            return crate::key_manager::SymmetricKeyKind::Camellia;
        }
        #[cfg(feature = "legacy-algorithms")]
        if matches!(self, Self::TripleDes) {
            return crate::key_manager::SymmetricKeyKind::Des;
        }
        crate::key_manager::SymmetricKeyKind::Aes
    }
    /// Parse a supported XMLEnc symmetric key-wrap URI.
    pub fn from_uri(uri: &str) -> Result<Self, XmlEncError> {
        match uri {
            #[cfg(feature = "legacy-algorithms")]
            "http://www.w3.org/2001/04/xmlenc#kw-aes192" => Ok(Self::AesKw192),
            #[cfg(feature = "legacy-algorithms")]
            "http://www.w3.org/2001/04/xmlenc#kw-tripledes" => Ok(Self::TripleDes),
            "http://www.w3.org/2001/04/xmlenc#kw-aes128" => Ok(Self::AesKw128),
            "http://www.w3.org/2001/04/xmlenc#kw-aes256" => Ok(Self::AesKw256),
            "http://www.w3.org/2001/04/xmldsig-more#kw-camellia128" => Ok(Self::CamelliaKw128),
            "http://www.w3.org/2001/04/xmldsig-more#kw-camellia192" => Ok(Self::CamelliaKw192),
            "http://www.w3.org/2001/04/xmldsig-more#kw-camellia256" => Ok(Self::CamelliaKw256),
            _ => DataEncryptionAlgorithm::from_uri(uri)
                .ok()
                .filter(|algorithm| algorithm.cbc_block_len().is_some())
                .map(Self::Cbc)
                .ok_or_else(|| XmlEncError::UnsupportedAlgorithm(uri.to_owned())),
        }
    }

    /// Required key-encryption-key length in bytes.
    pub const fn key_len(self) -> usize {
        match self {
            #[cfg(feature = "legacy-algorithms")]
            Self::AesKw192 | Self::TripleDes => 24,
            Self::AesKw128 => 16,
            Self::AesKw256 => 32,
            Self::CamelliaKw128 => 16,
            Self::CamelliaKw192 => 24,
            Self::CamelliaKw256 => 32,
            Self::Cbc(algorithm) => algorithm.key_len(),
        }
    }

    /// Return the standard XMLEnc key-wrap URI.
    pub const fn uri(self) -> &'static str {
        match self {
            #[cfg(feature = "legacy-algorithms")]
            Self::AesKw192 => "http://www.w3.org/2001/04/xmlenc#kw-aes192",
            #[cfg(feature = "legacy-algorithms")]
            Self::TripleDes => "http://www.w3.org/2001/04/xmlenc#kw-tripledes",
            Self::AesKw128 => "http://www.w3.org/2001/04/xmlenc#kw-aes128",
            Self::AesKw256 => "http://www.w3.org/2001/04/xmlenc#kw-aes256",
            Self::CamelliaKw128 => "http://www.w3.org/2001/04/xmldsig-more#kw-camellia128",
            Self::CamelliaKw192 => "http://www.w3.org/2001/04/xmldsig-more#kw-camellia192",
            Self::CamelliaKw256 => "http://www.w3.org/2001/04/xmldsig-more#kw-camellia256",
            Self::Cbc(algorithm) => algorithm.uri(),
        }
    }

    /// Whether use requires an explicit compiled-policy allowlist entry.
    pub const fn requires_explicit_permission(self) -> bool {
        match self {
            Self::CamelliaKw128 | Self::CamelliaKw192 | Self::CamelliaKw256 => true,
            Self::Cbc(_) => true,
            #[cfg(feature = "legacy-algorithms")]
            Self::AesKw192 | Self::TripleDes => true,
            _ => false,
        }
    }

    pub(crate) fn wrapped_len(self, plaintext_len: usize) -> Option<usize> {
        // XMLEnc 1.1 §5.7.1 / RFC 3217 §§2-3: CMS wrapping includes
        // an 8-byte checksum and an 8-byte IV, unlike RFC 3394's A register.
        // https://www.w3.org/TR/xmlenc-core1/#sec-CMS-3DES
        let overhead = match self {
            Self::Cbc(algorithm) => {
                return if algorithm.cbc_block_len().is_some() {
                    algorithm.ciphertext_len_for_plaintext(plaintext_len)
                } else {
                    None
                };
            }
            #[cfg(feature = "legacy-algorithms")]
            Self::TripleDes => 16,
            _ => 8,
        };
        plaintext_len.checked_add(overhead)
    }
}

/// Supported asymmetric session-key transport algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyTransportAlgorithm {
    /// Historical RSAES-PKCS1-v1_5 transport; explicit policy permission is required.
    #[cfg(feature = "legacy-algorithms")]
    RsaPkcs1v15,
    /// XML Encryption 1.0 OAEP URI with SHA-1/MGF1-SHA1 absent-field defaults.
    ///
    /// An explicit DigestMethod or XMLEnc 1.1 MGF child overrides the corresponding default,
    /// matching libxmlsec1 1.3.13 behavior.
    RsaOaepMgf1p,
    /// XML Encryption 1.1 OAEP with explicitly parsed digest and MGF settings.
    RsaOaep11,
}

/// Supported symmetric key-wrap algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyWrapAlgorithm {
    /// CBC encryption of key bytes. Unlike RFC 3394 this is not authenticated;
    /// permission must name this exact algorithm. Only CBC ciphers are valid.
    /// XMLEnc 1.1 §3.4 permits EncryptedKey's inherited EncryptionMethod.
    Cbc(DataEncryptionAlgorithm),
    /// AES-192 RFC 3394 key wrap, explicitly permitted by compatibility policy.
    #[cfg(feature = "legacy-algorithms")]
    AesKw192,
    /// CMS Triple DES key wrap, including XMLEnc's optional non-DES key inputs.
    #[cfg(feature = "legacy-algorithms")]
    TripleDes,
    /// RFC 3394 AES key wrap with a 128-bit KEK.
    AesKw128,
    /// RFC 3394 AES key wrap with a 256-bit KEK.
    AesKw256,
    /// RFC 9231 §2.6.3 Camellia wrapping with a 128-bit KEK.
    CamelliaKw128,
    /// Camellia wrapping with a 192-bit KEK.
    CamelliaKw192,
    /// Camellia wrapping with a 256-bit KEK.
    CamelliaKw256,
}

/// Digest algorithms accepted by RSA-OAEP encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OaepDigestAlgorithm {
    /// MD5 compatibility digest; requires explicit legacy permission.
    #[cfg(feature = "legacy-algorithms")]
    Md5,
    /// RIPEMD-160 compatibility digest; requires explicit legacy permission.
    #[cfg(feature = "legacy-algorithms")]
    Ripemd160,
    /// SHA-1, retained for legacy XMLEnc OAEP interoperability.
    Sha1,
    /// SHA-224, including the XML Encryption 1.1 MGF1-SHA224 identifier.
    Sha224,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
    /// SHA3-224.
    Sha3_224,
    /// SHA3-256.
    Sha3_256,
    /// SHA3-384.
    Sha3_384,
    /// SHA3-512.
    Sha3_512,
}

impl OaepDigestAlgorithm {
    /// Parse a digest URI accepted by XML Encryption and libxmlsec1.
    pub fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            #[cfg(feature = "legacy-algorithms")]
            "http://www.w3.org/2001/04/xmldsig-more#md5" => Some(Self::Md5),
            #[cfg(feature = "legacy-algorithms")]
            "http://www.w3.org/2001/04/xmlenc#ripemd160" => Some(Self::Ripemd160),
            "http://www.w3.org/2000/09/xmldsig#sha1" => Some(Self::Sha1),
            "http://www.w3.org/2001/04/xmldsig-more#sha224" => Some(Self::Sha224),
            "http://www.w3.org/2001/04/xmlenc#sha256" => Some(Self::Sha256),
            "http://www.w3.org/2001/04/xmlenc#sha384"
            | "http://www.w3.org/2001/04/xmldsig-more#sha384" => Some(Self::Sha384),
            "http://www.w3.org/2001/04/xmlenc#sha512" => Some(Self::Sha512),
            "http://www.w3.org/2007/05/xmldsig-more#sha3-224" => Some(Self::Sha3_224),
            "http://www.w3.org/2007/05/xmldsig-more#sha3-256" => Some(Self::Sha3_256),
            "http://www.w3.org/2007/05/xmldsig-more#sha3-384" => Some(Self::Sha3_384),
            "http://www.w3.org/2007/05/xmldsig-more#sha3-512" => Some(Self::Sha3_512),
            _ => None,
        }
    }

    /// Parse an XML Encryption 1.1 MGF1 URI.
    pub fn from_mgf_uri(uri: &str) -> Option<Self> {
        match uri {
            "http://www.w3.org/2009/xmlenc11#mgf1sha1" => Some(Self::Sha1),
            "http://www.w3.org/2009/xmlenc11#mgf1sha224" => Some(Self::Sha224),
            "http://www.w3.org/2009/xmlenc11#mgf1sha256" => Some(Self::Sha256),
            "http://www.w3.org/2009/xmlenc11#mgf1sha384" => Some(Self::Sha384),
            "http://www.w3.org/2009/xmlenc11#mgf1sha512" => Some(Self::Sha512),
            _ => None,
        }
    }

    /// Return the standard digest URI.
    pub const fn uri(self) -> &'static str {
        match self {
            #[cfg(feature = "legacy-algorithms")]
            Self::Md5 => "http://www.w3.org/2001/04/xmldsig-more#md5",
            #[cfg(feature = "legacy-algorithms")]
            Self::Ripemd160 => "http://www.w3.org/2001/04/xmlenc#ripemd160",
            Self::Sha1 => "http://www.w3.org/2000/09/xmldsig#sha1",
            Self::Sha224 => "http://www.w3.org/2001/04/xmldsig-more#sha224",
            Self::Sha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
            Self::Sha384 => "http://www.w3.org/2001/04/xmlenc#sha384",
            Self::Sha512 => "http://www.w3.org/2001/04/xmlenc#sha512",
            Self::Sha3_224 => "http://www.w3.org/2007/05/xmldsig-more#sha3-224",
            Self::Sha3_256 => "http://www.w3.org/2007/05/xmldsig-more#sha3-256",
            Self::Sha3_384 => "http://www.w3.org/2007/05/xmldsig-more#sha3-384",
            Self::Sha3_512 => "http://www.w3.org/2007/05/xmldsig-more#sha3-512",
        }
    }

    /// Return an XML Encryption 1.1 MGF URI, if one exists for this digest.
    /// DigestMethod support does not invent additional wire MGF identifiers.
    pub const fn mgf_uri(self) -> Option<&'static str> {
        // XML Encryption 1.1 §5.5.2 defines five MGF1 URIs. RFC 8017's
        // arbitrary Hash parameter does not register further XML identifiers.
        // https://www.w3.org/TR/xmlenc-core1/#sec-RSA-OAEP
        match self {
            Self::Sha1 => Some("http://www.w3.org/2009/xmlenc11#mgf1sha1"),
            Self::Sha224 => Some("http://www.w3.org/2009/xmlenc11#mgf1sha224"),
            Self::Sha256 => Some("http://www.w3.org/2009/xmlenc11#mgf1sha256"),
            Self::Sha384 => Some("http://www.w3.org/2009/xmlenc11#mgf1sha384"),
            Self::Sha512 => Some("http://www.w3.org/2009/xmlenc11#mgf1sha512"),
            _ => None,
        }
    }

    /// Compatibility digest capability never implicitly permits its use.
    pub const fn requires_explicit_permission(self) -> bool {
        match self {
            #[cfg(feature = "legacy-algorithms")]
            Self::Md5 | Self::Ripemd160 => true,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{OaepDigestAlgorithm, XmlEncError};

    #[test]
    fn operation_plan_failures_have_a_distinct_error_class() {
        let error = XmlEncError::from(crate::operation::OperationPlanError::StaleResourceIdentity);
        assert!(matches!(error, XmlEncError::OperationPlan(_)));
    }

    #[test]
    fn oaep_sha384_accepts_both_interoperable_digest_uris() {
        // The canonical XML Encryption spelling and libxmlsec1's XMLDSig-more
        // spelling identify the same OAEP digest algorithm.
        for uri in [
            "http://www.w3.org/2001/04/xmlenc#sha384",
            "http://www.w3.org/2001/04/xmldsig-more#sha384",
        ] {
            assert_eq!(
                OaepDigestAlgorithm::from_uri(uri),
                Some(OaepDigestAlgorithm::Sha384)
            );
        }
    }

    #[test]
    fn oaep_mgf_uris_round_trip() {
        for algorithm in [
            OaepDigestAlgorithm::Sha1,
            OaepDigestAlgorithm::Sha224,
            OaepDigestAlgorithm::Sha256,
            OaepDigestAlgorithm::Sha384,
            OaepDigestAlgorithm::Sha512,
        ] {
            assert_eq!(
                OaepDigestAlgorithm::from_mgf_uri(
                    algorithm.mgf_uri().expect("standard MGF1 digest URI")
                ),
                Some(algorithm)
            );
        }
        assert_eq!(
            OaepDigestAlgorithm::from_mgf_uri("urn:unsupported-mgf"),
            None
        );
    }
}

/// RSA-OAEP parameters emitted in an `EncryptedKey`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaOaepParameters {
    /// XMLEnc 1.0 legacy OAEP or XMLEnc 1.1 configurable OAEP.
    pub algorithm: KeyTransportAlgorithm,
    /// Digest used by OAEP.
    pub digest: OaepDigestAlgorithm,
    /// Digest used by MGF1.
    pub mgf_digest: OaepDigestAlgorithm,
    /// Optional OAEP label bytes.
    pub label: Vec<u8>,
}

impl RsaOaepParameters {
    /// Create legacy OAEP parameters with SHA-1 and MGF1-SHA-1.
    pub fn legacy() -> Self {
        Self {
            algorithm: KeyTransportAlgorithm::RsaOaepMgf1p,
            digest: OaepDigestAlgorithm::Sha1,
            mgf_digest: OaepDigestAlgorithm::Sha1,
            label: Vec::new(),
        }
    }

    /// Create XMLEnc 1.1 OAEP parameters.
    pub fn xmlenc11(digest: OaepDigestAlgorithm, mgf_digest: OaepDigestAlgorithm) -> Self {
        Self {
            algorithm: KeyTransportAlgorithm::RsaOaep11,
            digest,
            mgf_digest,
            label: Vec::new(),
        }
    }

    /// Set the OAEP label bytes.
    pub fn label(mut self, label: impl Into<Vec<u8>>) -> Self {
        self.label = label.into();
        self
    }
}

impl Default for RsaOaepParameters {
    fn default() -> Self {
        Self::xmlenc11(OaepDigestAlgorithm::Sha256, OaepDigestAlgorithm::Sha256)
    }
}

/// One recipient of a generated content-encryption key.
#[derive(Clone)]
pub enum EncryptionRecipient {
    /// Historical RSA transport, admitted only by explicit compiled policy.
    #[cfg(feature = "legacy-algorithms")]
    RsaPkcs1v15 {
        /// Opaque RSA public key used by the selected provider.
        public_key: Arc<dyn crate::provider::KeyTransportKey>,
        /// Optional recipient identifier.
        recipient: Option<String>,
        /// Optional key hint.
        key_name: Option<String>,
    },
    /// Wrap the content key with an RSA public key and OAEP.
    RsaOaep {
        /// Opaque recipient public-key handle.
        public_key: Arc<dyn crate::provider::KeyTransportKey>,
        /// OAEP algorithm parameters.
        parameters: RsaOaepParameters,
        /// Optional `Recipient` attribute.
        recipient: Option<String>,
        /// Optional key hint inside the encrypted key's `KeyInfo`.
        key_name: Option<String>,
    },
    /// Wrap the content key with a pre-shared AES KEK.
    AesKeyWrap {
        /// AES key-encryption key.
        kek: Vec<u8>,
        /// RFC 3394 key-wrap variant.
        algorithm: KeyWrapAlgorithm,
        /// Optional `Recipient` attribute.
        recipient: Option<String>,
        /// Optional key hint inside the encrypted key's `KeyInfo`.
        key_name: Option<String>,
    },
}

impl fmt::Debug for EncryptionRecipient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "legacy-algorithms")]
            Self::RsaPkcs1v15 {
                recipient,
                key_name,
                ..
            } => formatter
                .debug_struct("EncryptionRecipient::RsaPkcs1v15")
                .field("public_key", &"[PUBLIC KEY]")
                .field("recipient", recipient)
                .field("key_name", key_name)
                .finish(),
            Self::RsaOaep {
                parameters,
                recipient,
                key_name,
                ..
            } => formatter
                .debug_struct("EncryptionRecipient::RsaOaep")
                .field("public_key", &"[PUBLIC KEY]")
                .field("parameters", parameters)
                .field("recipient", recipient)
                .field("key_name", key_name)
                .finish(),
            Self::AesKeyWrap {
                algorithm,
                recipient,
                key_name,
                ..
            } => formatter
                .debug_struct("EncryptionRecipient::AesKeyWrap")
                .field("kek", &"[REDACTED]")
                .field("algorithm", algorithm)
                .field("recipient", recipient)
                .field("key_name", key_name)
                .finish(),
        }
    }
}

impl EncryptionRecipient {
    /// Create a historical RSAES-PKCS1-v1_5 recipient. Defaults still deny it.
    #[cfg(feature = "legacy-algorithms")]
    pub fn rsa_pkcs1v15(public_key: RsaPublicKey) -> Self {
        Self::provider_pkcs1v15(Arc::new(crate::provider::RustCryptoRsaPublicKey::new(
            public_key,
        )))
    }

    /// Create a historical RSA recipient without extracting provider-owned keys.
    #[cfg(feature = "legacy-algorithms")]
    pub fn provider_pkcs1v15(public_key: Arc<dyn crate::provider::KeyTransportKey>) -> Self {
        Self::RsaPkcs1v15 {
            public_key,
            recipient: None,
            key_name: None,
        }
    }
    /// Create an RSA-OAEP recipient using SHA-256 and MGF1-SHA-256.
    ///
    /// XMLEnc 1.1 assigns SHA-1 and MGF1-SHA-1 when these parameters are
    /// omitted. Serialized keys therefore include both algorithm values
    /// explicitly instead of relying on the specification's legacy defaults.
    pub fn rsa_oaep(public_key: RsaPublicKey) -> Self {
        Self::provider_key_transport(Arc::new(crate::provider::RustCryptoRsaPublicKey::new(
            public_key,
        )))
    }

    /// Create an RSA-OAEP recipient from an opaque provider key handle.
    pub fn provider_key_transport(public_key: Arc<dyn crate::provider::KeyTransportKey>) -> Self {
        Self::RsaOaep {
            public_key,
            parameters: RsaOaepParameters::default(),
            recipient: None,
            key_name: None,
        }
    }

    /// Create an AES Key Wrap recipient.
    pub fn aes_key_wrap(kek: impl Into<Vec<u8>>, algorithm: KeyWrapAlgorithm) -> Self {
        Self::AesKeyWrap {
            kek: kek.into(),
            algorithm,
            recipient: None,
            key_name: None,
        }
    }

    /// Override RSA-OAEP parameters.
    pub fn oaep_parameters(mut self, parameters: RsaOaepParameters) -> Self {
        if let Self::RsaOaep {
            parameters: current,
            ..
        } = &mut self
        {
            *current = parameters;
        }
        self
    }

    /// Set the recipient identifier emitted on `EncryptedKey`.
    pub fn recipient(mut self, value: impl Into<String>) -> Self {
        match &mut self {
            #[cfg(feature = "legacy-algorithms")]
            Self::RsaPkcs1v15 { recipient, .. } => *recipient = Some(value.into()),
            Self::RsaOaep { recipient, .. } | Self::AesKeyWrap { recipient, .. } => {
                *recipient = Some(value.into());
            }
        }
        self
    }

    /// Set the key name emitted inside the encrypted key's `KeyInfo`.
    pub fn key_name(mut self, value: impl Into<String>) -> Self {
        match &mut self {
            #[cfg(feature = "legacy-algorithms")]
            Self::RsaPkcs1v15 { key_name, .. } => *key_name = Some(value.into()),
            Self::RsaOaep { key_name, .. } | Self::AesKeyWrap { key_name, .. } => {
                *key_name = Some(value.into());
            }
        }
        self
    }
}

/// How generated `EncryptedData` replaces caller-owned XML.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplacementMode {
    /// Replace the selected element, including its start and end tags.
    ReplaceElement,
    /// Replace only the selected element's child content.
    ReplaceContent,
}

/// Result returned after encrypting bytes or XML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionResult {
    /// Complete `EncryptedData` XML fragment.
    pub encrypted_data_xml: String,
    /// Required caller-owned document replacement operation.
    pub replacement: ReplacementMode,
}

/// Caller-owned target selection for document encryption.
#[derive(Debug, Clone, Copy, Default)]
pub struct DocumentEncryptionOptions<'a> {
    /// Select an element by `Id`, `ID`, or `id`; `None` selects the document root.
    pub element_id: Option<&'a str>,
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
    /// ChaCha profile parameters, separate from RSA-OAEP labels.
    pub chacha: Option<ChaChaParameters>,
}

/// Request/wire data for the RFC 9231 ChaCha profiles, not policy.
/// A missing nonce is only allowed in an encryption template; decryption
/// requires an explicit nonce, and encryption generates it through its provider.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChaChaParameters {
    /// 96-bit nonce encoded as hexBinary in EncryptionMethod.
    pub nonce: Option<[u8; 12]>,
    /// Raw ChaCha's four little-endian counter bytes; absent for Poly1305.
    pub counter: Option<[u8; 4]>,
    /// Poly1305 additional authenticated data: UTF-8 XML text, not base64.
    pub aad: Option<String>,
}

impl ChaChaParameters {
    /// Borrow metadata for cryptographic dispatch and serialization without
    /// copying AAD when the operation supplies a generated nonce.
    pub fn borrowed(&self) -> ChaChaParametersRef<'_> {
        ChaChaParametersRef {
            nonce: self.nonce.as_ref(),
            counter: self.counter,
            aad: self.aad.as_deref(),
        }
    }
    /// Check the selected profile before any resolver or provider work.
    pub fn validate(&self, algorithm: DataEncryptionAlgorithm) -> Result<(), XmlEncError> {
        self.borrowed().validate(algorithm)
    }
}

/// Borrowed request parameters; no metadata allocation at provider dispatch.
#[derive(Debug, Clone, Copy, Default)]
pub struct ChaChaParametersRef<'a> {
    /// Explicit or operation-generated nonce.
    pub nonce: Option<&'a [u8; 12]>,
    /// Raw ChaCha's encoded initial block counter.
    pub counter: Option<[u8; 4]>,
    /// Borrowed UTF-8 additional authenticated data.
    pub aad: Option<&'a str>,
}

impl ChaChaParametersRef<'_> {
    /// Enforce the same profile invariants as owned parsed parameters.
    pub fn validate(self, algorithm: DataEncryptionAlgorithm) -> Result<(), XmlEncError> {
        // draft-eastlake-rfc9231bis-xmlsec-uris-06 §§3.6.7–3.6.8 separates
        // Counter from AAD. These experimental identifiers are not RFC 9231.
        // https://www.ietf.org/archive/id/draft-eastlake-rfc9231bis-xmlsec-uris-06.html#section-3.6.7
        let valid = match algorithm {
            DataEncryptionAlgorithm::ChaCha20 => self.counter.is_some() && self.aad.is_none(),
            DataEncryptionAlgorithm::ChaCha20Poly1305 => self.counter.is_none(),
            _ => false,
        };
        if !valid {
            return Err(XmlEncError::InvalidStructure(
                "invalid ChaCha EncryptionMethod parameters".into(),
            ));
        }
        Ok(())
    }
}

impl EncryptionMethod {
    /// Validate invariants imposed by the selected algorithm URI.
    ///
    /// Parsed XML and caller-constructed typed values share this check so the
    /// public typed API cannot express wire structures that XML parsing rejects.
    pub(crate) fn validate_structure(&self) -> Result<(), XmlEncError> {
        if let Some(parameters) = &self.chacha {
            parameters.validate(DataEncryptionAlgorithm::from_uri(&self.algorithm)?)?;
        } else if self.algorithm == DataEncryptionAlgorithm::ChaCha20.uri() {
            return Err(XmlEncError::MissingRequired("ChaCha20 Counter"));
        }
        if self.key_size_bits == Some(0) {
            return Err(XmlEncError::InvalidStructure(
                "KeySize must be a positive integer".into(),
            ));
        }
        let is_legacy_oaep = self.algorithm == KeyTransportAlgorithm::RsaOaepMgf1p.uri();
        let is_oaep11 = self.algorithm == KeyTransportAlgorithm::RsaOaep11.uri();
        if (self.oaep_params.is_some()
            || self.oaep_digest.is_some()
            || self.mgf_algorithm.is_some())
            && !is_legacy_oaep
            && !is_oaep11
        {
            return Err(XmlEncError::InvalidStructure(
                "OAEP parameters are only valid for RSA-OAEP EncryptionMethod".into(),
            ));
        }
        if let (Some(actual), Some(expected)) =
            (self.key_size_bits, fixed_aes_key_size(&self.algorithm))
            && actual != expected
        {
            return Err(XmlEncError::InvalidStructure(format!(
                "EncryptionMethod {} requires KeySize {expected}, got {actual}",
                self.algorithm
            )));
        }
        Ok(())
    }
}

fn fixed_aes_key_size(algorithm: &str) -> Option<usize> {
    let key_len = DataEncryptionAlgorithm::from_uri(algorithm)
        .map(DataEncryptionAlgorithm::key_len)
        .or_else(|_| KeyWrapAlgorithm::from_uri(algorithm).map(KeyWrapAlgorithm::key_len))
        .ok()?;
    Some(key_len * 8)
}

/// Ciphertext storage specified by XMLEnc 1.1 section 3.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CipherData {
    /// Whitespace-normalized base64 text from `CipherValue`.
    Value {
        /// Encoded ciphertext, not plaintext or key material.
        value: String,
    },
    /// A source-anchored reference, resolved before cryptographic dispatch.
    Reference {
        /// Required URI, including an explicitly empty URI.
        uri: String,
        /// Ordered transforms retained with their original XPath source identity.
        transforms: Vec<crate::xmldsig::transforms::Transform>,
    },
    /// Ciphertext octets resolved by the operation or supplied by the caller.
    Bytes(Vec<u8>),
}

impl CipherData {
    pub(super) fn octets(&self) -> Result<std::borrow::Cow<'_, [u8]>, XmlEncError> {
        use base64::Engine as _;
        match self {
            Self::Value { value } => base64::engine::general_purpose::STANDARD
                .decode(value)
                .map(std::borrow::Cow::Owned)
                .map_err(|error| XmlEncError::Base64(error.to_string())),
            Self::Bytes(bytes) => Ok(std::borrow::Cow::Borrowed(bytes)),
            Self::Reference { .. } => Err(XmlEncError::InvalidStructure(
                "CipherReference requires its original document context".into(),
            )),
        }
    }

    /// Return an inline base64 value, if this ciphertext is enveloped.
    pub fn inline_value(&self) -> Option<&str> {
        match self {
            Self::Value { value } => Some(value),
            Self::Reference { .. } | Self::Bytes(_) => None,
        }
    }

    /// Mutably access an inline value without changing its storage variant.
    pub fn inline_value_mut(&mut self) -> Option<&mut String> {
        match self {
            Self::Value { value } => Some(value),
            Self::Reference { .. } | Self::Bytes(_) => None,
        }
    }
}

/// Parsed embedded `EncryptedKey` used to recover a content-encryption key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedKey {
    /// Sources of the key which protects this transported key. These are not
    /// alternative content keys: their output feeds this key's EncryptionMethod.
    pub sources: EncryptionKeySources,
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

/// Typed establishment sources inside an encrypted key's `ds:KeyInfo`.
/// Recursion is checked against the operation's depth and candidate allowances.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EncryptionKeySources {
    /// Experimental KEM sources producing this wrapping key.
    pub encapsulation_methods: Vec<crate::key_establishment::EncapsulationMechanism>,
    /// Keys transporting the wrapping key, rather than the final content key.
    pub encrypted_keys: Vec<EncryptedKey>,
    /// Derivations producing the wrapping key.
    pub derived_keys: Vec<super::DerivedKey>,
    /// Agreements producing the wrapping key.
    pub agreement_methods: Vec<super::AgreementMethod>,
}

impl EncryptionKeySources {
    pub(super) fn is_empty(&self) -> bool {
        self.encrypted_keys.is_empty()
            && self.encapsulation_methods.is_empty()
            && self.derived_keys.is_empty()
            && self.agreement_methods.is_empty()
    }
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
    /// Experimental KEM sources; never silently treated as raw content keys.
    pub encapsulation_methods: Vec<crate::key_establishment::EncapsulationMechanism>,
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
    /// Ordered XML derivation candidates. Master material remains request-owned.
    pub derived_keys: Vec<super::DerivedKey>,
    /// Agreement candidates; trusted private keys remain in request context.
    pub agreement_methods: Vec<super::AgreementMethod>,
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

/// Errors raised while parsing, encrypting, resolving, or decrypting XMLEnc data.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum XmlEncError {
    /// Shared key establishment failed before content encryption/decryption.
    #[error(transparent)]
    KeyEstablishment(#[from] crate::key_establishment::KeyEstablishmentError),
    /// URI resolution or ciphertext transforms failed.
    #[error("ciphertext reference error: {0}")]
    Transform(#[from] crate::xmldsig::TransformError),
    /// The compiled encryption or decryption policy rejected an operation input.
    #[error("XML Encryption policy violation: {0}")]
    Policy(#[from] crate::policy::PolicyViolation),

    /// The selected cryptographic provider rejected or failed an operation.
    #[error("cryptographic provider error: {0}")]
    Provider(#[from] crate::provider::ProviderError),

    /// XML document parsing failed.
    #[error("XML parsing error: {0}")]
    XmlParse(#[from] crate::xml::dom::ParseError),
    /// The owned XML document boundary rejected an identity or mutation.
    #[error("XML document error: {0}")]
    Document(#[from] crate::document::XmlDocumentError),
    /// Required child element or attribute was absent.
    #[error("missing required {0}")]
    MissingRequired(&'static str),
    /// The XML element order or namespace is invalid for the XMLEnc profile.
    #[error("invalid encrypted structure: {0}")]
    InvalidStructure(String),
    /// The compiled operation graph rejected an identity, dependency, or generation invariant.
    #[error("invalid XML Encryption operation plan: {0}")]
    OperationPlan(String),
    /// The selected operation-start node ID is absent or resolves ambiguously.
    #[error("selected node ID is missing or ambiguous: {id}")]
    SelectedNodeUnavailable {
        /// Caller-supplied node identifier.
        id: String,
    },
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
    /// CBC ciphertext is not a non-empty multiple of the selected cipher's block size.
    #[error(
        "{algorithm} ciphertext length must be a non-zero multiple of {block} bytes, got {actual}"
    )]
    InvalidCbcCiphertextLength {
        /// Selected content cipher.
        algorithm: DataEncryptionAlgorithm,
        /// Cipher's block width in bytes.
        block: usize,
        /// Ciphertext body width, excluding the IV.
        actual: usize,
    },
    /// XMLEnc random padding is invalid.
    ///
    /// No decrypted padding details are exposed. This does not authenticate CBC
    /// ciphertexts or make success/failure safe to expose to an attacker.
    #[error("invalid XMLEnc padding")]
    InvalidPadding,
    /// Authenticated content decryption failed (GCM or ChaCha20-Poly1305).
    #[error("AEAD authentication failed")]
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
    /// An unauthenticated content algorithm cannot safely select among keys.
    #[error(
        "{algorithm:?} cannot safely select among {actual} unordered decryption key candidates"
    )]
    AmbiguousKeyCandidates {
        /// Unauthenticated algorithm for which key success is ambiguous.
        algorithm: DataEncryptionAlgorithm,
        /// Number of unresolved candidate keys.
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
    /// A wrapped-key input or provider output has invalid algorithm framing.
    #[error("wrapped-key value must be {expected} bytes, got {actual}")]
    InvalidWrappedKeyLength {
        /// Exact wrapped length required by the algorithm and key context.
        expected: usize,
        /// Actual input or provider output length.
        actual: usize,
    },
    /// Encryption configuration is internally inconsistent.
    #[error("invalid encryption configuration: {0}")]
    InvalidEncryptionConfig(String),
    /// No caller-provided resolver could supply a usable key.
    #[error("no suitable decryption key was resolved")]
    KeyNotFound,
    /// No `EncryptedData` matched the requested document selection.
    #[error("no matching EncryptedData element was found")]
    EncryptedDataNotFound,
    /// More than one `EncryptedData` matched the requested document selection.
    #[error("more than one EncryptedData element matched; select one by Id")]
    AmbiguousEncryptedData,
    /// No source element matched the requested encryption target.
    #[error("no matching element was found for encryption")]
    EncryptionTargetNotFound,
    /// More than one source element matched the requested encryption target.
    #[error("more than one element matched the encryption target")]
    AmbiguousEncryptionTarget,
    /// Document replacement requires an XML `Type` declaration.
    #[error("EncryptedData must declare Element or Content Type for document replacement")]
    ReplacementRequiresXml,
    /// RSA-OAEP session-key recovery failed.
    #[error("RSA-OAEP key unwrap failed: {0}")]
    Rsa(String),
    /// RSA-OAEP session-key wrapping failed.
    #[error("RSA-OAEP key wrap failed: {0}")]
    RsaEncrypt(String),
    /// RFC 3394 integrity validation failed while unwrapping a key.
    #[error("AES key unwrap failed integrity validation")]
    KeyWrapIntegrity,
    /// Operating-system randomness was unavailable.
    #[error("operating-system random number generation failed: {0}")]
    Rng(String),
    /// Generated XML could not be serialized.
    #[error("XML encryption serialization failed: {0}")]
    XmlSerialize(String),
    /// XML-declared plaintext could not be decoded as UTF-8.
    #[error("decrypted XML is not valid UTF-8: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}

impl From<crate::operation::OperationPlanError> for XmlEncError {
    fn from(error: crate::operation::OperationPlanError) -> Self {
        Self::OperationPlan(error.to_string())
    }
}

impl fmt::Display for DataEncryptionAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            #[cfg(feature = "legacy-algorithms")]
            Self::TripleDesCbc => "Triple DES CBC",
            #[cfg(feature = "legacy-algorithms")]
            Self::Aes192Cbc => "AES-192-CBC",
            #[cfg(feature = "legacy-algorithms")]
            Self::Aes192Gcm => "AES-192-GCM",
            Self::Aes128Cbc => "AES-128-CBC",
            Self::Aes256Cbc => "AES-256-CBC",
            Self::Aes128Gcm => "AES-128-GCM",
            Self::Aes256Gcm => "AES-256-GCM",
            Self::Camellia128Cbc => "Camellia-128-CBC",
            Self::Camellia192Cbc => "Camellia-192-CBC",
            Self::Camellia256Cbc => "Camellia-256-CBC",
            Self::ChaCha20 => "ChaCha20",
            Self::ChaCha20Poly1305 => "ChaCha20-Poly1305",
        })
    }
}

#[cfg(test)]
mod framing_tests {
    use super::*;

    #[test]
    fn cbc_framing_error_names_the_selected_cipher() {
        // Diagnostics must identify the actual cipher and its block width,
        // rather than reporting AES framing for a DES input.
        let error = validate_ciphertext_framing(DataEncryptionAlgorithm::Aes128Cbc, 33)
            .expect_err("AES ciphertext body is not block-aligned");
        assert_eq!(
            error.to_string(),
            "AES-128-CBC ciphertext length must be a non-zero multiple of 16 bytes, got 17"
        );
        #[cfg(feature = "legacy-algorithms")]
        {
            let error = validate_ciphertext_framing(DataEncryptionAlgorithm::TripleDesCbc, 17)
                .expect_err("3DES ciphertext body is not block-aligned");
            assert_eq!(
                error.to_string(),
                "Triple DES CBC ciphertext length must be a non-zero multiple of 8 bytes, got 9"
            );
        }
    }
}
