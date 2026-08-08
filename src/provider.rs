//! Provider-neutral cryptographic operations.
//!
//! XML parsing and protocol orchestration depend on this contract rather than
//! concrete cryptographic crates. Secret-bearing signing/decryption keys remain
//! opaque behind the operation-specific key traits exposed by `xmldsig` and
//! `xmlenc`; this provider owns stateless primitives and randomness.

#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
use getrandom::rand_core::TryCryptoRng;
use getrandom::{SysRng, rand_core::TryRng};

#[cfg(feature = "xmldsig")]
use crate::xmldsig::DigestAlgorithm;
#[cfg(feature = "xmlenc")]
use crate::xmlenc::RsaOaepParameters;
#[cfg(feature = "xmlenc")]
use crate::xmlenc::{DataEncryptionAlgorithm, KeyWrapAlgorithm};

/// A cryptographic operation advertised by a provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProviderOperation {
    /// Message digest computation.
    Digest,
    /// Public-key signature generation.
    Sign,
    /// Public-key signature verification.
    Verify,
    /// Authenticated or padded symmetric encryption.
    Encrypt,
    /// Authenticated or padded symmetric decryption.
    Decrypt,
    /// Symmetric key wrapping.
    KeyWrap,
    /// Symmetric key unwrapping.
    KeyUnwrap,
    /// Public-key key transport.
    KeyTransport,
    /// Key agreement.
    KeyAgreement,
    /// Key derivation.
    Kdf,
    /// Cryptographically secure random bytes.
    Random,
}

/// Provider capability query, including optional algorithm granularity.
#[derive(Debug, Clone, Copy)]
pub struct CapabilityQuery<'a> {
    /// Operation the caller intends to execute.
    pub operation: ProviderOperation,
    /// Standard algorithm URI when one exists.
    pub algorithm: Option<&'a str>,
}

/// Structured invalid-input reasons returned by cryptographic providers.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProviderInputError {
    /// A primitive rejected a key or IV after its public preconditions were checked.
    #[error("failed to initialize {0}")]
    PrimitiveInitialization(&'static str),
    /// AES-CBC input does not contain an IV followed by complete blocks.
    #[error("invalid AES-CBC framing")]
    AesCbcFraming,
    /// AES-CBC block decryption failed.
    #[error("invalid AES-CBC ciphertext")]
    AesCbcCiphertext,
    /// AES-CBC produced no plaintext block.
    #[error("empty AES-CBC plaintext")]
    AesCbcPlaintext,
    /// XMLEnc CBC padding length is outside the valid block range.
    ///
    /// This variant deliberately carries no decrypted bytes or padding length.
    /// CBC remains unauthenticated, so callers must authenticate ciphertexts
    /// before acting on decryption results or reject CBC through operation policy.
    #[error("invalid XMLEnc CBC padding")]
    XmlEncCbcPadding,
    /// AES-GCM input does not contain a nonce and authentication tag.
    #[error("invalid AES-GCM framing")]
    AesGcmFraming,
    /// AES key-wrap input or output framing is invalid.
    #[error("invalid AES key-wrap framing")]
    AesKeyWrapFraming,
    /// The legacy RSA-OAEP URI requires MGF1-SHA1.
    #[error("legacy RSA-OAEP requires MGF1-SHA1")]
    LegacyRsaOaepMgf,
}

/// Failure returned by a cryptographic provider.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProviderError {
    /// The selected provider does not implement the operation/parameters.
    #[error("provider does not support {operation:?} with algorithm {algorithm:?}")]
    Unsupported {
        /// Requested operation.
        operation: ProviderOperation,
        /// Requested algorithm URI or name.
        algorithm: Option<String>,
    },
    /// A key has the wrong size for the selected algorithm.
    #[error("invalid key size: expected {expected} bytes, got {actual}")]
    InvalidKeySize {
        /// Required key length.
        expected: usize,
        /// Supplied key length.
        actual: usize,
    },
    /// Input framing, padding, or primitive initialization is invalid.
    #[error("invalid cryptographic input: {0}")]
    InvalidInput(ProviderInputError),
    /// Authenticated decryption or key-wrap integrity validation failed.
    #[error("cryptographic authentication failed")]
    AuthenticationFailed,
    /// Operating-system randomness was unavailable.
    #[error("operating-system random number generation failed: {0}")]
    Random(String),
}

/// Stateless provider operations used by the XML Security pipelines.
pub trait CryptoProvider: Send + Sync {
    /// Stable provider name for diagnostics and capability reporting.
    fn name(&self) -> &'static str;

    /// Return whether this build supports the requested operation and parameters.
    fn supports(&self, query: CapabilityQuery<'_>) -> bool;

    /// Fill caller-owned output with cryptographically secure random bytes.
    fn fill_random(&self, output: &mut [u8]) -> Result<(), ProviderError>;

    /// Compute a message digest.
    #[cfg(feature = "xmldsig")]
    fn digest(&self, algorithm: DigestAlgorithm, data: &[u8]) -> Result<Vec<u8>, ProviderError>;

    /// Sign bytes with an opaque key handle.
    ///
    /// Providers that delegate primitive signing to the supplied key must call
    /// [`crate::xmldsig::SigningKey::sign_with_provider`] so randomized
    /// primitives consume this provider's randomness.
    #[cfg(feature = "xmldsig")]
    fn sign(
        &self,
        key: &dyn crate::xmldsig::SigningKey,
        algorithm: crate::xmldsig::SignatureAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>, crate::xmldsig::SigningKeyError>;

    /// Verify bytes with an opaque key handle.
    #[cfg(feature = "xmldsig")]
    fn verify(
        &self,
        key: &dyn crate::xmldsig::VerifyingKey,
        algorithm: crate::xmldsig::SignatureAlgorithm,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, crate::xmldsig::DsigError>;

    /// Encrypt XMLEnc content bytes, including standard framing.
    #[cfg(feature = "xmlenc")]
    fn encrypt_data(
        &self,
        algorithm: DataEncryptionAlgorithm,
        key: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError>;

    /// Decrypt XMLEnc content bytes, including framing validation.
    #[cfg(feature = "xmlenc")]
    fn decrypt_data(
        &self,
        algorithm: DataEncryptionAlgorithm,
        key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError>;

    /// Wrap a content key with RFC 3394 AES Key Wrap.
    #[cfg(feature = "xmlenc")]
    fn wrap_key(
        &self,
        algorithm: KeyWrapAlgorithm,
        kek: &[u8],
        key: &[u8],
    ) -> Result<Vec<u8>, ProviderError>;

    /// Unwrap a content key with RFC 3394 AES Key Wrap.
    #[cfg(feature = "xmlenc")]
    fn unwrap_key(
        &self,
        algorithm: KeyWrapAlgorithm,
        kek: &[u8],
        wrapped: &[u8],
    ) -> Result<Vec<u8>, ProviderError>;

    /// Wrap key bytes using an opaque RSA public-key operation.
    #[cfg(feature = "xmlenc")]
    fn transport_key(
        &self,
        key: &rsa::RsaPublicKey,
        parameters: &RsaOaepParameters,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError>;

    /// Recover key bytes using an opaque RSA private-key operation.
    #[cfg(feature = "xmlenc")]
    fn recover_key(
        &self,
        key: &rsa::RsaPrivateKey,
        parameters: &RsaOaepParameters,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError>;
}

/// Pure-Rust provider backed by RustCrypto crates.
#[derive(Debug, Clone, Copy, Default)]
pub struct RustCryptoProvider;

/// Process-wide immutable default provider. It contains no mutable state or keys.
pub static RUST_CRYPTO_PROVIDER: RustCryptoProvider = RustCryptoProvider;

/// Borrow the pure-Rust default provider.
#[must_use]
pub fn default_provider() -> &'static dyn CryptoProvider {
    &RUST_CRYPTO_PROVIDER
}

/// Adapter used when a RustCrypto primitive requires a fallible RNG object.
#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
pub(crate) struct ProviderRng<'a>(pub(crate) &'a dyn CryptoProvider);

#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
impl TryRng for ProviderRng<'_> {
    type Error = ProviderError;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0_u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0_u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill_random(output)
    }
}

#[cfg(any(feature = "xmldsig", feature = "xmlenc"))]
impl TryCryptoRng for ProviderRng<'_> {}

impl CryptoProvider for RustCryptoProvider {
    fn name(&self) -> &'static str {
        "rustcrypto"
    }

    fn supports(&self, query: CapabilityQuery<'_>) -> bool {
        match query.operation {
            ProviderOperation::Digest => {
                #[cfg(feature = "xmldsig")]
                {
                    query.algorithm.is_none_or(|algorithm| {
                        matches!(
                            algorithm,
                            "http://www.w3.org/2000/09/xmldsig#sha1"
                                | "http://www.w3.org/2001/04/xmlenc#sha256"
                                | "http://www.w3.org/2001/04/xmldsig-more#sha384"
                                | "http://www.w3.org/2001/04/xmlenc#sha512"
                        )
                    })
                }
                #[cfg(not(feature = "xmldsig"))]
                {
                    false
                }
            }
            ProviderOperation::Sign => {
                #[cfg(feature = "xmldsig")]
                {
                    query.algorithm.is_none_or(is_supported_signing_uri)
                }
                #[cfg(not(feature = "xmldsig"))]
                {
                    false
                }
            }
            ProviderOperation::Verify => {
                #[cfg(feature = "xmldsig")]
                {
                    query.algorithm.is_none_or(is_supported_signature_uri)
                }
                #[cfg(not(feature = "xmldsig"))]
                {
                    false
                }
            }
            ProviderOperation::Encrypt | ProviderOperation::Decrypt => {
                #[cfg(feature = "xmlenc")]
                {
                    query.algorithm.is_none_or(is_supported_data_encryption_uri)
                }
                #[cfg(not(feature = "xmlenc"))]
                {
                    false
                }
            }
            ProviderOperation::KeyWrap | ProviderOperation::KeyUnwrap => {
                #[cfg(feature = "xmlenc")]
                {
                    query.algorithm.is_none_or(is_supported_key_wrap_uri)
                }
                #[cfg(not(feature = "xmlenc"))]
                {
                    false
                }
            }
            ProviderOperation::KeyTransport => {
                #[cfg(feature = "xmlenc")]
                {
                    query.algorithm.is_none_or(|algorithm| {
                        matches!(
                            algorithm,
                            "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
                                | "http://www.w3.org/2009/xmlenc11#rsa-oaep"
                        )
                    })
                }
                #[cfg(not(feature = "xmlenc"))]
                {
                    false
                }
            }
            ProviderOperation::Random => true,
            ProviderOperation::KeyAgreement | ProviderOperation::Kdf => false,
        }
    }

    fn fill_random(&self, output: &mut [u8]) -> Result<(), ProviderError> {
        SysRng
            .try_fill_bytes(output)
            .map_err(|error| ProviderError::Random(error.to_string()))
    }

    #[cfg(feature = "xmldsig")]
    fn digest(&self, algorithm: DigestAlgorithm, data: &[u8]) -> Result<Vec<u8>, ProviderError> {
        use sha1::Sha1;
        use sha2::{Digest, Sha256, Sha384, Sha512};
        Ok(match algorithm {
            DigestAlgorithm::Sha1 => Sha1::digest(data).to_vec(),
            DigestAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
            DigestAlgorithm::Sha384 => Sha384::digest(data).to_vec(),
            DigestAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
        })
    }

    #[cfg(feature = "xmldsig")]
    fn sign(
        &self,
        key: &dyn crate::xmldsig::SigningKey,
        algorithm: crate::xmldsig::SignatureAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>, crate::xmldsig::SigningKeyError> {
        self.require(ProviderOperation::Sign, Some(algorithm.uri()))?;
        key.sign_with_provider(self, algorithm, data)
    }

    #[cfg(feature = "xmldsig")]
    fn verify(
        &self,
        key: &dyn crate::xmldsig::VerifyingKey,
        algorithm: crate::xmldsig::SignatureAlgorithm,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, crate::xmldsig::DsigError> {
        self.require(ProviderOperation::Verify, Some(algorithm.uri()))?;
        key.verify(algorithm, data, signature)
    }

    #[cfg(feature = "xmlenc")]
    fn encrypt_data(
        &self,
        algorithm: DataEncryptionAlgorithm,
        key: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        rustcrypto::encrypt_data(self, algorithm, key, plaintext)
    }

    #[cfg(feature = "xmlenc")]
    fn decrypt_data(
        &self,
        algorithm: DataEncryptionAlgorithm,
        key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        rustcrypto::decrypt_data(algorithm, key, ciphertext)
    }

    #[cfg(feature = "xmlenc")]
    fn wrap_key(
        &self,
        algorithm: KeyWrapAlgorithm,
        kek: &[u8],
        key: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        rustcrypto::wrap_key(algorithm, kek, key)
    }

    #[cfg(feature = "xmlenc")]
    fn unwrap_key(
        &self,
        algorithm: KeyWrapAlgorithm,
        kek: &[u8],
        wrapped: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        rustcrypto::unwrap_key(algorithm, kek, wrapped)
    }

    #[cfg(feature = "xmlenc")]
    fn transport_key(
        &self,
        key: &rsa::RsaPublicKey,
        parameters: &RsaOaepParameters,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        self.require(
            ProviderOperation::KeyTransport,
            Some(parameters.algorithm.uri()),
        )?;
        rustcrypto::transport_key(self, key, parameters, plaintext)
    }

    #[cfg(feature = "xmlenc")]
    fn recover_key(
        &self,
        key: &rsa::RsaPrivateKey,
        parameters: &RsaOaepParameters,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        self.require(
            ProviderOperation::KeyTransport,
            Some(parameters.algorithm.uri()),
        )?;
        rustcrypto::recover_key(self, key, parameters, ciphertext)
    }
}

impl RustCryptoProvider {
    fn require(
        &self,
        operation: ProviderOperation,
        algorithm: Option<&str>,
    ) -> Result<(), ProviderError> {
        if self.supports(CapabilityQuery {
            operation,
            algorithm,
        }) {
            Ok(())
        } else {
            Err(ProviderError::Unsupported {
                operation,
                algorithm: algorithm.map(str::to_owned),
            })
        }
    }
}

#[cfg(feature = "xmldsig")]
fn is_supported_signature_uri(algorithm: &str) -> bool {
    matches!(
        algorithm,
        "http://www.w3.org/2000/09/xmldsig#dsa-sha1"
            | "http://www.w3.org/2000/09/xmldsig#hmac-sha1"
            | "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
            | "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
            | "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
            | "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
            | "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
            | "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
    )
}

#[cfg(feature = "xmldsig")]
fn is_supported_signing_uri(algorithm: &str) -> bool {
    matches!(
        algorithm,
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
            | "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
            | "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
            | "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
            | "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
    )
}

#[cfg(feature = "xmlenc")]
fn is_supported_data_encryption_uri(algorithm: &str) -> bool {
    matches!(
        algorithm,
        "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
            | "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
            | "http://www.w3.org/2009/xmlenc11#aes128-gcm"
            | "http://www.w3.org/2009/xmlenc11#aes256-gcm"
    )
}

#[cfg(feature = "xmlenc")]
fn is_supported_key_wrap_uri(algorithm: &str) -> bool {
    matches!(
        algorithm,
        "http://www.w3.org/2001/04/xmlenc#kw-aes128" | "http://www.w3.org/2001/04/xmlenc#kw-aes256"
    )
}

#[cfg(feature = "xmlenc")]
mod rustcrypto {
    use aes::{
        Aes128, Aes256,
        cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::NoPadding},
    };
    use aes_gcm::{
        Aes128Gcm, Aes256Gcm, Nonce,
        aead::{AeadInOut, KeyInit},
    };
    use aes_kw::{KwAes128, KwAes256};
    use cbc::{Decryptor, Encryptor};
    use rsa::{Oaep, traits::PaddingScheme};
    use sha1::Sha1;
    use sha2::{Sha256, Sha384, Sha512};

    use super::{CryptoProvider, ProviderError, ProviderInputError};
    use crate::xmlenc::{
        DataEncryptionAlgorithm, KeyTransportAlgorithm, KeyWrapAlgorithm, OaepDigestAlgorithm,
        RsaOaepParameters,
    };

    pub(super) fn encrypt_data(
        provider: &dyn CryptoProvider,
        algorithm: DataEncryptionAlgorithm,
        key: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        check_key(algorithm.key_len(), key)?;
        match algorithm {
            DataEncryptionAlgorithm::Aes128Cbc => encrypt_cbc::<Aes128>(provider, key, plaintext),
            DataEncryptionAlgorithm::Aes256Cbc => encrypt_cbc::<Aes256>(provider, key, plaintext),
            DataEncryptionAlgorithm::Aes128Gcm => {
                encrypt_gcm::<Aes128Gcm>(provider, key, plaintext)
            }
            DataEncryptionAlgorithm::Aes256Gcm => {
                encrypt_gcm::<Aes256Gcm>(provider, key, plaintext)
            }
        }
    }

    pub(super) fn decrypt_data(
        algorithm: DataEncryptionAlgorithm,
        key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        check_key(algorithm.key_len(), key)?;
        match algorithm {
            DataEncryptionAlgorithm::Aes128Cbc => decrypt_cbc::<Aes128>(key, ciphertext),
            DataEncryptionAlgorithm::Aes256Cbc => decrypt_cbc::<Aes256>(key, ciphertext),
            DataEncryptionAlgorithm::Aes128Gcm => decrypt_gcm::<Aes128Gcm>(key, ciphertext),
            DataEncryptionAlgorithm::Aes256Gcm => decrypt_gcm::<Aes256Gcm>(key, ciphertext),
        }
    }

    fn check_key(expected: usize, key: &[u8]) -> Result<(), ProviderError> {
        if key.len() == expected {
            Ok(())
        } else {
            Err(ProviderError::InvalidKeySize {
                expected,
                actual: key.len(),
            })
        }
    }

    fn encrypt_cbc<C>(
        provider: &dyn CryptoProvider,
        key: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError>
    where
        C: aes::cipher::BlockCipherEncrypt + aes::cipher::KeyInit,
    {
        let mut iv = [0_u8; 16];
        provider.fill_random(&mut iv)?;
        let pad_len = 16 - (plaintext.len() % 16);
        let mut padded = vec![0_u8; plaintext.len() + pad_len];
        padded[..plaintext.len()].copy_from_slice(plaintext);
        if pad_len > 1 {
            let last = padded.len() - 1;
            provider.fill_random(&mut padded[plaintext.len()..last])?;
        }
        *padded.last_mut().expect("padding is non-empty") = pad_len as u8;
        Encryptor::<C>::new_from_slices(key, &iv)
            .map_err(|_| {
                ProviderError::InvalidInput(ProviderInputError::PrimitiveInitialization("AES-CBC"))
            })?
            .encrypt_padded::<NoPadding>(&mut padded, plaintext.len() + pad_len)
            .map_err(|_| {
                ProviderError::InvalidInput(ProviderInputError::PrimitiveInitialization(
                    "AES-CBC padding",
                ))
            })?;
        let mut output = Vec::with_capacity(16 + padded.len());
        output.extend_from_slice(&iv);
        output.extend_from_slice(&padded);
        Ok(output)
    }

    fn decrypt_cbc<C>(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ProviderError>
    where
        C: aes::cipher::BlockCipherDecrypt + aes::cipher::KeyInit,
    {
        if ciphertext.len() < 32 || !(ciphertext.len() - 16).is_multiple_of(16) {
            return Err(ProviderError::InvalidInput(
                ProviderInputError::AesCbcFraming,
            ));
        }
        let (iv, body) = ciphertext.split_at(16);
        let mut plaintext = body.to_vec();
        Decryptor::<C>::new_from_slices(key, iv)
            .map_err(|_| {
                ProviderError::InvalidInput(ProviderInputError::PrimitiveInitialization("AES-CBC"))
            })?
            .decrypt_padded::<NoPadding>(&mut plaintext)
            .map_err(|_| ProviderError::InvalidInput(ProviderInputError::AesCbcCiphertext))?;
        let pad_len = *plaintext.last().ok_or(ProviderError::InvalidInput(
            ProviderInputError::AesCbcPlaintext,
        ))?;
        let padding_bytes = usize::from(pad_len);
        if !(1..=16).contains(&padding_bytes) || padding_bytes > plaintext.len() {
            return Err(ProviderError::InvalidInput(
                ProviderInputError::XmlEncCbcPadding,
            ));
        }
        plaintext.truncate(plaintext.len() - padding_bytes);
        Ok(plaintext)
    }

    fn encrypt_gcm<C>(
        provider: &dyn CryptoProvider,
        key: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError>
    where
        C: AeadInOut + KeyInit,
    {
        let mut nonce = [0_u8; 12];
        provider.fill_random(&mut nonce)?;
        let cipher = C::new_from_slice(key).map_err(|_| {
            ProviderError::InvalidInput(ProviderInputError::PrimitiveInitialization("AES-GCM"))
        })?;
        let mut output = plaintext.to_vec();
        let nonce = Nonce::try_from(nonce.as_slice()).map_err(|_| {
            ProviderError::InvalidInput(ProviderInputError::PrimitiveInitialization(
                "AES-GCM nonce",
            ))
        })?;
        cipher
            .encrypt_in_place(&nonce, &[], &mut output)
            .map_err(|_| ProviderError::AuthenticationFailed)?;
        let mut framed = Vec::with_capacity(12 + output.len());
        framed.extend_from_slice(&nonce);
        framed.extend_from_slice(&output);
        Ok(framed)
    }

    fn decrypt_gcm<C>(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ProviderError>
    where
        C: AeadInOut + KeyInit,
    {
        if ciphertext.len() < 28 {
            return Err(ProviderError::InvalidInput(
                ProviderInputError::AesGcmFraming,
            ));
        }
        let (nonce, body) = ciphertext.split_at(12);
        let cipher = C::new_from_slice(key).map_err(|_| {
            ProviderError::InvalidInput(ProviderInputError::PrimitiveInitialization("AES-GCM"))
        })?;
        let mut plaintext = body.to_vec();
        let nonce = Nonce::try_from(nonce).map_err(|_| {
            ProviderError::InvalidInput(ProviderInputError::PrimitiveInitialization(
                "AES-GCM nonce",
            ))
        })?;
        cipher
            .decrypt_in_place(&nonce, &[], &mut plaintext)
            .map_err(|_| ProviderError::AuthenticationFailed)?;
        Ok(plaintext)
    }

    pub(super) fn wrap_key(
        algorithm: KeyWrapAlgorithm,
        kek: &[u8],
        key: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        check_key(algorithm.key_len(), kek)?;
        let mut output = vec![0_u8; key.len() + 8];
        match algorithm {
            KeyWrapAlgorithm::AesKw128 => KwAes128::new_from_slice(kek)
                .map_err(|_| ProviderError::InvalidKeySize {
                    expected: 16,
                    actual: kek.len(),
                })?
                .wrap_key(key, &mut output),
            KeyWrapAlgorithm::AesKw256 => KwAes256::new_from_slice(kek)
                .map_err(|_| ProviderError::InvalidKeySize {
                    expected: 32,
                    actual: kek.len(),
                })?
                .wrap_key(key, &mut output),
        }
        .map_err(|_| ProviderError::InvalidInput(ProviderInputError::AesKeyWrapFraming))?;
        Ok(output)
    }

    pub(super) fn unwrap_key(
        algorithm: KeyWrapAlgorithm,
        kek: &[u8],
        wrapped: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        check_key(algorithm.key_len(), kek)?;
        if wrapped.len() < 16 || !wrapped.len().is_multiple_of(8) {
            return Err(ProviderError::InvalidInput(
                ProviderInputError::AesKeyWrapFraming,
            ));
        }
        let mut output = vec![0_u8; wrapped.len() - 8];
        let key = match algorithm {
            KeyWrapAlgorithm::AesKw128 => KwAes128::new_from_slice(kek)
                .map_err(|_| ProviderError::InvalidKeySize {
                    expected: 16,
                    actual: kek.len(),
                })?
                .unwrap_key(wrapped, &mut output),
            KeyWrapAlgorithm::AesKw256 => KwAes256::new_from_slice(kek)
                .map_err(|_| ProviderError::InvalidKeySize {
                    expected: 32,
                    actual: kek.len(),
                })?
                .unwrap_key(wrapped, &mut output),
        }
        .map_err(|_| ProviderError::AuthenticationFailed)?;
        Ok(key.to_vec())
    }

    pub(super) fn transport_key(
        provider: &dyn CryptoProvider,
        key: &rsa::RsaPublicKey,
        parameters: &RsaOaepParameters,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        if parameters.algorithm == KeyTransportAlgorithm::RsaOaepMgf1p
            && parameters.mgf_digest != OaepDigestAlgorithm::Sha1
        {
            return Err(ProviderError::InvalidInput(
                ProviderInputError::LegacyRsaOaepMgf,
            ));
        }
        let mut rng = super::ProviderRng(provider);
        macro_rules! encrypt_with {
            ($digest:ty, $mgf:ty) => {
                Oaep::<$digest, $mgf>::new_with_mgf_hash_and_label(parameters.label.clone())
                    .encrypt(&mut rng, key, plaintext)
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
        result.map_err(map_rsa_error)
    }

    pub(super) fn recover_key(
        provider: &dyn CryptoProvider,
        key: &rsa::RsaPrivateKey,
        parameters: &RsaOaepParameters,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        if parameters.algorithm == KeyTransportAlgorithm::RsaOaepMgf1p
            && parameters.mgf_digest != OaepDigestAlgorithm::Sha1
        {
            return Err(ProviderError::InvalidInput(
                ProviderInputError::LegacyRsaOaepMgf,
            ));
        }
        let mut rng = super::ProviderRng(provider);
        macro_rules! decrypt_with {
            ($digest:ty, $mgf:ty) => {
                Oaep::<$digest, $mgf>::new_with_mgf_hash_and_label(parameters.label.clone())
                    .decrypt(Some(&mut rng), key, ciphertext)
            };
        }
        let result = match (parameters.digest, parameters.mgf_digest) {
            (OaepDigestAlgorithm::Sha1, OaepDigestAlgorithm::Sha1) => {
                decrypt_with!(Sha1, Sha1)
            }
            (OaepDigestAlgorithm::Sha1, OaepDigestAlgorithm::Sha256) => {
                decrypt_with!(Sha1, Sha256)
            }
            (OaepDigestAlgorithm::Sha1, OaepDigestAlgorithm::Sha384) => {
                decrypt_with!(Sha1, Sha384)
            }
            (OaepDigestAlgorithm::Sha1, OaepDigestAlgorithm::Sha512) => {
                decrypt_with!(Sha1, Sha512)
            }
            (OaepDigestAlgorithm::Sha256, OaepDigestAlgorithm::Sha1) => {
                decrypt_with!(Sha256, Sha1)
            }
            (OaepDigestAlgorithm::Sha256, OaepDigestAlgorithm::Sha256) => {
                decrypt_with!(Sha256, Sha256)
            }
            (OaepDigestAlgorithm::Sha256, OaepDigestAlgorithm::Sha384) => {
                decrypt_with!(Sha256, Sha384)
            }
            (OaepDigestAlgorithm::Sha256, OaepDigestAlgorithm::Sha512) => {
                decrypt_with!(Sha256, Sha512)
            }
            (OaepDigestAlgorithm::Sha384, OaepDigestAlgorithm::Sha1) => {
                decrypt_with!(Sha384, Sha1)
            }
            (OaepDigestAlgorithm::Sha384, OaepDigestAlgorithm::Sha256) => {
                decrypt_with!(Sha384, Sha256)
            }
            (OaepDigestAlgorithm::Sha384, OaepDigestAlgorithm::Sha384) => {
                decrypt_with!(Sha384, Sha384)
            }
            (OaepDigestAlgorithm::Sha384, OaepDigestAlgorithm::Sha512) => {
                decrypt_with!(Sha384, Sha512)
            }
            (OaepDigestAlgorithm::Sha512, OaepDigestAlgorithm::Sha1) => {
                decrypt_with!(Sha512, Sha1)
            }
            (OaepDigestAlgorithm::Sha512, OaepDigestAlgorithm::Sha256) => {
                decrypt_with!(Sha512, Sha256)
            }
            (OaepDigestAlgorithm::Sha512, OaepDigestAlgorithm::Sha384) => {
                decrypt_with!(Sha512, Sha384)
            }
            (OaepDigestAlgorithm::Sha512, OaepDigestAlgorithm::Sha512) => {
                decrypt_with!(Sha512, Sha512)
            }
        };
        result.map_err(map_rsa_error)
    }

    fn map_rsa_error(error: rsa::Error) -> ProviderError {
        match error {
            rsa::Error::Rng => ProviderError::Random("RSA-OAEP randomness failed".into()),
            _ => ProviderError::AuthenticationFailed,
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "xmldsig")]
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[cfg(feature = "xmldsig")]
    struct CountingRandomProvider {
        random_calls: AtomicUsize,
    }

    #[cfg(feature = "xmldsig")]
    impl CryptoProvider for CountingRandomProvider {
        fn name(&self) -> &'static str {
            "counting-random"
        }

        fn supports(&self, query: CapabilityQuery<'_>) -> bool {
            RUST_CRYPTO_PROVIDER.supports(query)
        }

        fn fill_random(&self, output: &mut [u8]) -> Result<(), ProviderError> {
            self.random_calls.fetch_add(1, Ordering::Relaxed);
            RUST_CRYPTO_PROVIDER.fill_random(output)
        }

        fn digest(
            &self,
            algorithm: DigestAlgorithm,
            data: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            RUST_CRYPTO_PROVIDER.digest(algorithm, data)
        }

        fn sign(
            &self,
            key: &dyn crate::xmldsig::SigningKey,
            algorithm: crate::xmldsig::SignatureAlgorithm,
            data: &[u8],
        ) -> Result<Vec<u8>, crate::xmldsig::SigningKeyError> {
            key.sign_with_provider(self, algorithm, data)
        }

        fn verify(
            &self,
            key: &dyn crate::xmldsig::VerifyingKey,
            algorithm: crate::xmldsig::SignatureAlgorithm,
            data: &[u8],
            signature: &[u8],
        ) -> Result<bool, crate::xmldsig::DsigError> {
            RUST_CRYPTO_PROVIDER.verify(key, algorithm, data, signature)
        }

        #[cfg(feature = "xmlenc")]
        fn encrypt_data(
            &self,
            algorithm: DataEncryptionAlgorithm,
            key: &[u8],
            plaintext: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            RUST_CRYPTO_PROVIDER.encrypt_data(algorithm, key, plaintext)
        }

        #[cfg(feature = "xmlenc")]
        fn decrypt_data(
            &self,
            algorithm: DataEncryptionAlgorithm,
            key: &[u8],
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            RUST_CRYPTO_PROVIDER.decrypt_data(algorithm, key, ciphertext)
        }

        #[cfg(feature = "xmlenc")]
        fn wrap_key(
            &self,
            algorithm: KeyWrapAlgorithm,
            kek: &[u8],
            key: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            RUST_CRYPTO_PROVIDER.wrap_key(algorithm, kek, key)
        }

        #[cfg(feature = "xmlenc")]
        fn unwrap_key(
            &self,
            algorithm: KeyWrapAlgorithm,
            kek: &[u8],
            wrapped: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            RUST_CRYPTO_PROVIDER.unwrap_key(algorithm, kek, wrapped)
        }

        #[cfg(feature = "xmlenc")]
        fn transport_key(
            &self,
            key: &rsa::RsaPublicKey,
            parameters: &RsaOaepParameters,
            plaintext: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            RUST_CRYPTO_PROVIDER.transport_key(key, parameters, plaintext)
        }

        #[cfg(feature = "xmlenc")]
        fn recover_key(
            &self,
            key: &rsa::RsaPrivateKey,
            parameters: &RsaOaepParameters,
            ciphertext: &[u8],
        ) -> Result<Vec<u8>, ProviderError> {
            RUST_CRYPTO_PROVIDER.recover_key(key, parameters, ciphertext)
        }
    }

    #[test]
    fn capability_query_is_explicit_about_unimplemented_operations() {
        assert!(RUST_CRYPTO_PROVIDER.supports(CapabilityQuery {
            operation: ProviderOperation::Digest,
            algorithm: None
        }));
        assert!(!RUST_CRYPTO_PROVIDER.supports(CapabilityQuery {
            operation: ProviderOperation::KeyAgreement,
            algorithm: None
        }));
        assert!(!RUST_CRYPTO_PROVIDER.supports(CapabilityQuery {
            operation: ProviderOperation::Sign,
            algorithm: Some("http://www.w3.org/2000/09/xmldsig#rsa-sha1")
        }));
        assert!(RUST_CRYPTO_PROVIDER.supports(CapabilityQuery {
            operation: ProviderOperation::Verify,
            algorithm: Some("http://www.w3.org/2000/09/xmldsig#rsa-sha1")
        }));
        assert!(!RUST_CRYPTO_PROVIDER.supports(CapabilityQuery {
            operation: ProviderOperation::Verify,
            algorithm: Some("urn:unsupported:signature"),
        }));
    }

    #[cfg(not(feature = "xmlenc"))]
    #[test]
    fn capability_query_hides_xmlenc_operations_when_feature_is_disabled() {
        // Capability discovery is a runtime API over the current build, so it
        // must not advertise methods removed from CryptoProvider by cfg.
        for operation in [
            ProviderOperation::Encrypt,
            ProviderOperation::Decrypt,
            ProviderOperation::KeyWrap,
            ProviderOperation::KeyUnwrap,
            ProviderOperation::KeyTransport,
        ] {
            assert!(!RUST_CRYPTO_PROVIDER.supports(CapabilityQuery {
                operation,
                algorithm: None,
            }));
        }
    }

    #[cfg(not(feature = "xmldsig"))]
    #[test]
    fn capability_query_hides_xmldsig_operations_when_feature_is_disabled() {
        // Digest/sign/verify methods do not exist in an xmlenc-only provider.
        for operation in [
            ProviderOperation::Digest,
            ProviderOperation::Sign,
            ProviderOperation::Verify,
        ] {
            assert!(!RUST_CRYPTO_PROVIDER.supports(CapabilityQuery {
                operation,
                algorithm: None,
            }));
        }
    }

    #[cfg(feature = "xmldsig")]
    #[test]
    fn rsa_signing_uses_the_selected_providers_randomness() {
        use crate::xmldsig::{RsaSigningKey, SignatureAlgorithm};

        // RSA PKCS#1 v1.5 uses randomness for blinding even though its wire
        // signature is deterministic; the selected provider owns that source.
        let key = RsaSigningKey::from_pkcs8_pem(include_str!(
            "../tests/fixtures/keys/rsa/rsa-2048-key.pem"
        ))
        .expect("RSA fixture must parse");
        let provider = CountingRandomProvider {
            random_calls: AtomicUsize::new(0),
        };

        let signature = provider
            .sign(&key, SignatureAlgorithm::RsaSha256, b"signed info")
            .expect("RSA signing must succeed");

        assert!(!signature.is_empty());
        assert!(provider.random_calls.load(Ordering::Relaxed) > 0);
    }

    #[cfg(feature = "xmlenc")]
    #[test]
    fn legacy_oaep_mgf_constraint_is_symmetric() {
        use rsa::pkcs8::DecodePrivateKey;

        // The legacy URI fixes MGF1 to SHA-1 for both directions; rejecting
        // before RSA processing keeps transport and recovery capabilities equal.
        let key = rsa::RsaPrivateKey::from_pkcs8_pem(include_str!(
            "../tests/fixtures/keys/rsa/rsa-2048-key.pem"
        ))
        .expect("RSA fixture must parse");
        let parameters = crate::xmlenc::RsaOaepParameters {
            algorithm: crate::xmlenc::KeyTransportAlgorithm::RsaOaepMgf1p,
            digest: crate::xmlenc::OaepDigestAlgorithm::Sha256,
            mgf_digest: crate::xmlenc::OaepDigestAlgorithm::Sha256,
            label: Vec::new(),
        };

        assert!(matches!(
            RUST_CRYPTO_PROVIDER.recover_key(&key, &parameters, &[0_u8; 256]),
            Err(ProviderError::InvalidInput(
                ProviderInputError::LegacyRsaOaepMgf
            ))
        ));
        assert!(matches!(
            RUST_CRYPTO_PROVIDER.transport_key(&key.to_public_key(), &parameters, &[0_u8; 16]),
            Err(ProviderError::InvalidInput(
                ProviderInputError::LegacyRsaOaepMgf
            ))
        ));
    }
}
