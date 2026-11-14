//! The `XMLDSig` HMAC signature methods over the shared incremental HMAC
//! (RFC 2104) of `structured-cms`.

use alloc::borrow::ToOwned;

use structured_cms::hmac::{Algorithm, Mac, Tag};

use super::{SignatureAlgorithm, SigningKeyError};

/// The HMAC digest of `method`, when it is an HMAC method of this build.
fn digest_of(method: SignatureAlgorithm) -> Option<Algorithm> {
    Some(match method {
        #[cfg(feature = "legacy-algorithms")]
        SignatureAlgorithm::HmacMd5 => Algorithm::Md5,
        #[cfg(feature = "legacy-algorithms")]
        SignatureAlgorithm::HmacRipemd160 => Algorithm::Ripemd160,
        SignatureAlgorithm::HmacSha1 => Algorithm::Sha1,
        SignatureAlgorithm::HmacSha224 => Algorithm::Sha224,
        SignatureAlgorithm::HmacSha256 => Algorithm::Sha256,
        SignatureAlgorithm::HmacSha384 => Algorithm::Sha384,
        SignatureAlgorithm::HmacSha512 => Algorithm::Sha512,
        _ => return None,
    })
}

/// An incremental HMAC of an `XMLDSig` HMAC signature method, for a caller
/// that feeds its input in chunks. The full MAC is returned; the policy's
/// output and key minima remain the caller's checks.
///
/// # Examples
///
/// ```
/// use xml_sec::xmldsig::{IncrementalHmac, SignatureAlgorithm};
///
/// let mut mac = IncrementalHmac::begin(SignatureAlgorithm::HmacSha256, b"key")?;
/// mac.update(b"The quick brown fox ");
/// mac.update(b"jumps over the lazy dog");
/// let tag = mac.finish();
/// assert_eq!(tag.as_bytes()[..4], [0xf7, 0xbc, 0x83, 0xf4]);
/// assert!(tag.matches_truncated(&[0xf7, 0xbc], 16));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct IncrementalHmac {
    mac: Mac,
}

impl IncrementalHmac {
    /// Start the MAC of `algorithm` keyed with `secret`.
    ///
    /// # Errors
    /// [`SigningKeyError::UnsupportedAlgorithm`] for a method that is no HMAC
    /// of this build, [`SigningKeyError::InvalidKeyDer`] for a rejected key.
    pub fn begin(algorithm: SignatureAlgorithm, secret: &[u8]) -> Result<Self, SigningKeyError> {
        let digest = digest_of(algorithm).ok_or_else(|| SigningKeyError::UnsupportedAlgorithm {
            uri: algorithm.uri().to_owned(),
        })?;
        let mac = Mac::begin(digest, secret).map_err(|_| SigningKeyError::InvalidKeyDer)?;
        Ok(Self { mac })
    }

    /// Absorb the next input bytes.
    pub fn update(&mut self, data: &[u8]) {
        self.mac.update(data);
    }

    /// The MAC of all absorbed bytes, of the digest's full width.
    #[must_use]
    pub fn finish(self) -> HmacTag {
        HmacTag(self.mac.finalize())
    }
}

/// A full-width HMAC value.
pub struct HmacTag(Tag);

impl HmacTag {
    /// The MAC octets.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Whether `expected` is the leftmost `bits` of this MAC, compared in
    /// constant time (`XMLDSig` 1.1 section 6.3.1, RFC 2104 section 5): it
    /// holds exactly `bits` rounded up to octets, and the unused low bits of
    /// its last octet are ignored. `false` for an empty or longer selection.
    #[must_use]
    pub fn matches_truncated(&self, expected: &[u8], bits: usize) -> bool {
        self.0.verify_truncated(expected, bits).is_ok()
    }
}
