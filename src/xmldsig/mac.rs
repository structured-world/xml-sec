//! An incremental HMAC of an `XMLDSig` HMAC signature method.

use alloc::{borrow::ToOwned, vec::Vec};

use hmac::{KeyInit, Mac};

use super::{SignatureAlgorithm, SigningKeyError};

macro_rules! states {
    ($($(#[$attr:meta])* $variant:ident => $digest:ty;)*) => {
        /// The running MAC of one digest.
        enum State {
            $($(#[$attr])* $variant(hmac::Hmac<$digest>),)*
        }

        impl State {
            fn begin(algorithm: SignatureAlgorithm, secret: &[u8]) -> Result<Self, SigningKeyError> {
                let invalid = |_| SigningKeyError::InvalidKeyDer;
                Ok(match algorithm {
                    $($(#[$attr])* SignatureAlgorithm::$variant => {
                        Self::$variant(hmac::Hmac::<$digest>::new_from_slice(secret).map_err(invalid)?)
                    })*
                    _ => {
                        return Err(SigningKeyError::UnsupportedAlgorithm {
                            uri: algorithm.uri().to_owned(),
                        });
                    }
                })
            }

            fn update(&mut self, data: &[u8]) {
                match self {
                    $($(#[$attr])* Self::$variant(mac) => mac.update(data),)*
                }
            }

            fn finish(self) -> Vec<u8> {
                match self {
                    $($(#[$attr])* Self::$variant(mac) => mac.finalize().into_bytes().to_vec(),)*
                }
            }
        }
    };
}

states! {
    #[cfg(feature = "legacy-algorithms")]
    HmacMd5 => md5::Md5;
    #[cfg(feature = "legacy-algorithms")]
    HmacRipemd160 => ripemd::Ripemd160;
    HmacSha1 => sha1::Sha1;
    HmacSha224 => sha2::Sha224;
    HmacSha256 => sha2::Sha256;
    HmacSha384 => sha2::Sha384;
    HmacSha512 => sha2::Sha512;
}

/// An incremental HMAC (RFC 2104) of an `XMLDSig` HMAC signature method, for
/// a caller that feeds its input in chunks. The full MAC is returned;
/// truncation to `HMACOutputLength` and the policy's output and key minima
/// remain the caller's checks.
///
/// # Examples
///
/// ```
/// use xml_sec::xmldsig::{IncrementalHmac, SignatureAlgorithm};
///
/// let mut mac = IncrementalHmac::begin(SignatureAlgorithm::HmacSha256, b"key")?;
/// mac.update(b"The quick brown fox ");
/// mac.update(b"jumps over the lazy dog");
/// assert_eq!(mac.finish()[..4], [0xf7, 0xbc, 0x83, 0xf4]);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct IncrementalHmac {
    state: State,
}

impl IncrementalHmac {
    /// Start the MAC of `algorithm` keyed with `secret`.
    ///
    /// # Errors
    /// [`SigningKeyError::UnsupportedAlgorithm`] for a method that is no HMAC
    /// of this build, [`SigningKeyError::InvalidKeyDer`] for a rejected key.
    pub fn begin(algorithm: SignatureAlgorithm, secret: &[u8]) -> Result<Self, SigningKeyError> {
        Ok(Self {
            state: State::begin(algorithm, secret)?,
        })
    }

    /// Absorb the next input bytes.
    pub fn update(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    /// The MAC of all absorbed bytes, of the digest's full width.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.state.finish()
    }
}
