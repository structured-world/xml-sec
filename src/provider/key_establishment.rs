//! RustCrypto primitives. XML syntax, deployment policy and cumulative operation
//! accounting remain in the caller; primitive protocol bounds are checked here.

mod bit_hash;
mod dh;
pub use dh::RustCryptoDhKey;

use crate::xmldsig::{DigestAlgorithm, SignatureAlgorithm};
use p256::elliptic_curve::sec1::ToSec1Point;

use super::{
    KdfContext, KdfParameters, KeyAgreementKey, KeyAgreementParameters, ProviderError,
    ProviderInputError, ProviderOperation,
};

pub(super) const X25519_URI: &str = "http://www.w3.org/2021/04/xmldsig-more#x25519";
pub(super) const X448_URI: &str = "http://www.w3.org/2021/04/xmldsig-more#x448";
pub(super) const ECDH_URI: &str = "http://www.w3.org/2009/xmlenc11#ECDH-ES";
pub(super) const DH_ES_URI: &str = "http://www.w3.org/2009/xmlenc11#dh-es";
pub(super) const DH_URI: &str = "http://www.w3.org/2001/04/xmlenc#dh";
const HKDF_URI: &str = "http://www.w3.org/2021/04/xmldsig-more#hkdf";
const PBKDF2_URI: &str = "http://www.w3.org/2009/xmlenc11#pbkdf2";
const CONCAT_KDF_URI: &str = "http://www.w3.org/2009/xmlenc11#ConcatKDF";
const LEGACY_DH_URI: &str = "http://www.w3.org/2001/04/xmlenc#dh";

/// Named curve used by an ECDH-ES private key. The peer must use this same curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdhCurve {
    /// NIST P-256 (32-byte scalar and shared secret).
    P256,
    /// NIST P-384 (48-byte scalar and shared secret).
    P384,
    /// NIST P-521 (66-byte scalar and shared secret).
    P521,
}

enum EcdhSecret {
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    P521(p521::SecretKey),
}

/// Opaque RustCrypto ECDH key with a fixed named-curve domain.
pub struct RustCryptoEcdhKey(EcdhSecret);

impl core::fmt::Debug for RustCryptoEcdhKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RustCryptoEcdhKey")
            .finish_non_exhaustive()
    }
}

impl RustCryptoEcdhKey {
    /// Import a fixed-width big-endian private scalar. Zero and out-of-range
    /// values are rejected, not reduced modulo the curve order.
    pub fn from_scalar(curve: EcdhCurve, bytes: &[u8]) -> Result<Self, ProviderError> {
        let width = match curve {
            EcdhCurve::P256 => 32,
            EcdhCurve::P384 => 48,
            EcdhCurve::P521 => 66,
        };
        if bytes.len() != width {
            return Err(ProviderError::InvalidKeySize {
                expected: width,
                actual: bytes.len(),
            });
        }
        let invalid = |_| ProviderError::InvalidInput(ProviderInputError::EcdhKey);
        Ok(Self(match curve {
            EcdhCurve::P256 => {
                EcdhSecret::P256(p256::SecretKey::from_slice(bytes).map_err(invalid)?)
            }
            EcdhCurve::P384 => {
                EcdhSecret::P384(p384::SecretKey::from_slice(bytes).map_err(invalid)?)
            }
            EcdhCurve::P521 => {
                EcdhSecret::P521(p521::SecretKey::from_slice(bytes).map_err(invalid)?)
            }
        }))
    }

    /// Export the public SEC1 uncompressed point, never private material.
    pub fn public_key(&self) -> Vec<u8> {
        match &self.0 {
            EcdhSecret::P256(key) => key.public_key().to_sec1_point(false).as_bytes().to_vec(),
            EcdhSecret::P384(key) => key.public_key().to_sec1_point(false).as_bytes().to_vec(),
            EcdhSecret::P521(key) => key.public_key().to_sec1_point(false).as_bytes().to_vec(),
        }
    }
}

impl KeyAgreementKey for RustCryptoEcdhKey {
    fn agree(&self, parameters: &KeyAgreementParameters<'_>) -> Result<Vec<u8>, ProviderError> {
        if parameters.algorithm != ECDH_URI {
            return Err(ProviderError::Unsupported {
                operation: ProviderOperation::KeyAgreement,
                algorithm: Some(parameters.algorithm.to_owned()),
            });
        }
        macro_rules! agree {
            ($key:expr, $public:ty) => {{
                // XMLEnc 1.1 section 5.6.4 requires a validated peer and fixed-width
                // shared-secret octets. The named-curve parser rejects infinity and
                // off-curve points before multiplication; do not integer-trim ZZ.
                // https://www.w3.org/TR/xmlenc-core1/#sec-ECDH-ES
                let peer = <$public>::from_sec1_bytes(parameters.peer_public_key)
                    .map_err(|_| ProviderError::InvalidInput(ProviderInputError::EcdhKey))?;
                let shared = $key.diffie_hellman(&peer);
                Ok(shared.raw_secret_bytes().to_vec())
            }};
        }
        match &self.0 {
            EcdhSecret::P256(key) => agree!(key, p256::PublicKey),
            EcdhSecret::P384(key) => agree!(key, p384::PublicKey),
            EcdhSecret::P521(key) => agree!(key, p521::PublicKey),
        }
    }
}

/// Opaque RustCrypto X25519 private key. Its scalar is zeroized on drop and is
/// never exposed through Debug or a byte-export accessor.
pub struct RustCryptoX25519Key(x25519_dalek::StaticSecret);

impl core::fmt::Debug for RustCryptoX25519Key {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RustCryptoX25519Key")
            .finish_non_exhaustive()
    }
}

impl RustCryptoX25519Key {
    /// Import the 32-byte scalar encoding; clamping follows RFC 7748 section 5.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(x25519_dalek::StaticSecret::from(bytes))
    }

    /// Return the public u-coordinate encoding defined by RFC 7748 section 5.
    pub fn public_key(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&self.0).to_bytes()
    }
}

impl KeyAgreementKey for RustCryptoX25519Key {
    fn agree(&self, parameters: &KeyAgreementParameters<'_>) -> Result<Vec<u8>, ProviderError> {
        if parameters.algorithm != X25519_URI {
            return Err(ProviderError::Unsupported {
                operation: ProviderOperation::KeyAgreement,
                algorithm: Some(parameters.algorithm.to_owned()),
            });
        }
        let bytes: [u8; 32] =
            parameters
                .peer_public_key
                .try_into()
                .map_err(|_| ProviderError::InvalidKeySize {
                    expected: 32,
                    actual: parameters.peer_public_key.len(),
                })?;
        let peer = x25519_dalek::PublicKey::from(bytes);
        let secret = self.0.diffie_hellman(&peer);
        // RFC 7748 section 6.1 permits the all-zero check. Our key-establishment
        // contract requires contributory behavior, rather than deriving a key
        // from a secret an untrusted low-order peer can force to zero.
        // https://www.rfc-editor.org/rfc/rfc7748.html#section-6.1
        if !secret.was_contributory() {
            return Err(ProviderError::AuthenticationFailed);
        }
        Ok(secret.as_bytes().to_vec())
    }
}

/// Opaque RustCrypto X448 private key, zeroized on drop without secret export.
pub struct RustCryptoX448Key(x448::StaticSecret);

impl core::fmt::Debug for RustCryptoX448Key {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RustCryptoX448Key")
            .finish_non_exhaustive()
    }
}

impl RustCryptoX448Key {
    /// Import a 56-byte scalar; clamping follows RFC 7748 section 5.
    pub fn from_bytes(bytes: [u8; 56]) -> Self {
        Self(x448::StaticSecret::from(bytes))
    }

    /// Import RFC 8410 PKCS#8, validating any included public-key identity.
    /// DER is borrowed; only the fixed-width scalar enters the zeroizing key.
    pub fn from_pkcs8_der(bytes: &[u8]) -> Result<Self, ProviderError> {
        use der::{Decode, asn1::OctetStringRef};
        use pkcs8::{ObjectIdentifier, PrivateKeyInfoRef};
        use subtle::ConstantTimeEq;
        let invalid = || ProviderError::InvalidInput(ProviderInputError::EcdhKey);
        let info = PrivateKeyInfoRef::try_from(bytes).map_err(|_| invalid())?;
        // RFC 8410 sections 3 and 7: id-X448, absent parameters, and a
        // CurvePrivateKey OCTET STRING nested inside PKCS#8 privateKey.
        // https://www.rfc-editor.org/rfc/rfc8410.html#section-7
        if info.algorithm.oid != ObjectIdentifier::new_unwrap("1.3.101.111")
            || info.algorithm.parameters.is_some()
        {
            return Err(invalid());
        }
        let scalar =
            <&OctetStringRef>::from_der(info.private_key.as_bytes()).map_err(|_| invalid())?;
        let scalar = zeroize::Zeroizing::new(
            <[u8; 56]>::try_from(scalar.as_bytes()).map_err(|_| invalid())?,
        );
        let key = Self::from_bytes(*scalar);
        // Section 7 allows carrying the public key. Binding it to the scalar
        // is our import invariant, not an extra ASN.1 syntax requirement.
        if let Some(public) = info.public_key {
            let public = public.as_bytes().ok_or_else(invalid)?;
            if !bool::from(key.public_key().as_slice().ct_eq(public)) {
                return Err(invalid());
            }
        }
        Ok(key)
    }

    /// Return the RFC 7748 section 5 little-endian public u-coordinate.
    pub fn public_key(&self) -> [u8; 56] {
        *x448::PublicKey::from(&self.0).as_bytes()
    }
}

impl KeyAgreementKey for RustCryptoX448Key {
    fn agree(&self, parameters: &KeyAgreementParameters<'_>) -> Result<Vec<u8>, ProviderError> {
        if parameters.algorithm != X448_URI {
            return Err(ProviderError::Unsupported {
                operation: ProviderOperation::KeyAgreement,
                algorithm: Some(parameters.algorithm.to_owned()),
            });
        }
        // RFC 7748 section 5 requires accepting noncanonical u-coordinates.
        // Decode only the width here; the Montgomery ladder reduces the field
        // element, and the contributory check below covers low-order aliases.
        // https://www.rfc-editor.org/rfc/rfc7748.html#section-5
        let peer = x448::PublicKey::from_bytes_unchecked(parameters.peer_public_key).ok_or(
            ProviderError::InvalidKeySize {
                expected: 56,
                actual: parameters.peer_public_key.len(),
            },
        )?;
        let secret = self.0.diffie_hellman(&peer);
        // Section 6.2 permits rejecting zero secrets; our agreement contract
        // requires contributory behavior. Examine every byte before branching.
        // https://www.rfc-editor.org/rfc/rfc7748.html#section-6.2
        use subtle::ConstantTimeEq;
        if bool::from(secret.as_bytes().ct_eq(&[0; 56])) {
            return Err(ProviderError::AuthenticationFailed);
        }
        Ok(secret.as_bytes().to_vec())
    }
}

pub(super) fn supports_kdf(parameters: &KdfParameters<'_>) -> bool {
    match parameters.algorithm {
        HKDF_URI | PBKDF2_URI => hmac_prf(parameters).is_some(),
        CONCAT_KDF_URI | LEGACY_DH_URI => concat_digest(parameters).is_some(),
        _ => false,
    }
}

fn hmac_prf(parameters: &KdfParameters<'_>) -> Option<SignatureAlgorithm> {
    let algorithm = SignatureAlgorithm::from_uri(parameters.digest?)?;
    match algorithm {
        SignatureAlgorithm::HmacSha1
        | SignatureAlgorithm::HmacSha224
        | SignatureAlgorithm::HmacSha256
        | SignatureAlgorithm::HmacSha384
        | SignatureAlgorithm::HmacSha512 => Some(algorithm),
        _ => None,
    }
}

pub(super) fn derive_key(
    parameters: &KdfParameters<'_>,
    secret: &[u8],
) -> Result<Vec<u8>, ProviderError> {
    if parameters.algorithm == LEGACY_DH_URI {
        return derive_legacy_dh(parameters, secret);
    }
    if parameters.algorithm == CONCAT_KDF_URI {
        return derive_concat(parameters, secret);
    }
    if parameters.algorithm == PBKDF2_URI {
        return derive_pbkdf2(parameters, secret);
    }
    if parameters.algorithm != HKDF_URI {
        return Err(ProviderError::Unsupported {
            operation: ProviderOperation::Kdf,
            algorithm: Some(parameters.algorithm.to_owned()),
        });
    }
    if parameters.iterations != 0 {
        return Err(ProviderError::InvalidInput(
            ProviderInputError::HkdfParameters,
        ));
    }
    let info = context_octets(parameters.info).ok_or(ProviderError::InvalidInput(
        ProviderInputError::HkdfParameters,
    ))?;
    macro_rules! derive {
        ($digest:ty, $width:expr) => {{
            // RFC 5869 section 2.3: L <= 255 * HashLen. Check before allocating;
            // XML policy may further restrict this immutable primitive bound.
            // https://www.rfc-editor.org/rfc/rfc5869.html#section-2.3
            if parameters.output_len > 255 * $width {
                return Err(ProviderError::InvalidInput(
                    ProviderInputError::HkdfParameters,
                ));
            }
            let kdf = hkdf::Hkdf::<$digest>::new(Some(parameters.salt), secret);
            let mut output = zeroize::Zeroizing::new(vec![0; parameters.output_len]);
            kdf.expand(info, &mut output)
                .map_err(|_| ProviderError::InvalidInput(ProviderInputError::HkdfParameters))?;
            Ok(core::mem::take(&mut *output))
        }};
    }
    match hmac_prf(parameters) {
        Some(SignatureAlgorithm::HmacSha1) => derive!(sha1::Sha1, 20),
        Some(SignatureAlgorithm::HmacSha224) => derive!(sha2::Sha224, 28),
        Some(SignatureAlgorithm::HmacSha256) => derive!(sha2::Sha256, 32),
        Some(SignatureAlgorithm::HmacSha384) => derive!(sha2::Sha384, 48),
        Some(SignatureAlgorithm::HmacSha512) => derive!(sha2::Sha512, 64),
        _ => Err(ProviderError::Unsupported {
            operation: ProviderOperation::Kdf,
            algorithm: Some(parameters.algorithm.to_owned()),
        }),
    }
}

fn derive_pbkdf2(parameters: &KdfParameters<'_>, secret: &[u8]) -> Result<Vec<u8>, ProviderError> {
    use hmac::Mac;
    use zeroize::Zeroize;

    if parameters.iterations == 0
        || parameters.output_len == 0
        || context_octets(parameters.info) != Some(&[][..])
    {
        return Err(ProviderError::InvalidInput(
            ProviderInputError::Pbkdf2Parameters,
        ));
    }
    macro_rules! derive {
        ($digest:ty, $width:expr) => {{
            // RFC 8018 section 5.2: dkLen <= (2^32 - 1) * hLen and the block
            // index is big-endian. Validate before allocation or PRF work.
            // https://www.rfc-editor.org/rfc/rfc8018.html#section-5.2
            let blocks = parameters.output_len.div_ceil($width);
            if u32::try_from(blocks).is_err() {
                return Err(ProviderError::InvalidInput(
                    ProviderInputError::Pbkdf2Parameters,
                ));
            }
            let prf = <hmac::Hmac<$digest> as hmac::KeyInit>::new_from_slice(secret)
                .map_err(|_| ProviderError::InvalidInput(ProviderInputError::Pbkdf2Parameters))?;
            let mut salted = prf.clone();
            salted.update(parameters.salt);
            let mut output = zeroize::Zeroizing::new(vec![0; parameters.output_len]);
            // The public parameter is u64: do not silently truncate it to the
            // u32 counter accepted by the existing pbkdf2 convenience function.
            // Only U_j/T_i live here; RustCrypto supplies every HMAC operation.
            for (index, chunk) in output.chunks_mut($width).enumerate() {
                let counter = u32::try_from(index + 1).map_err(|_| {
                    ProviderError::InvalidInput(ProviderInputError::Pbkdf2Parameters)
                })?;
                let mut first = salted.clone();
                first.update(&counter.to_be_bytes());
                let mut previous = first.finalize().into_bytes();
                chunk.copy_from_slice(&previous[..chunk.len()]);
                for _ in 1..parameters.iterations {
                    let mut next = prf.clone();
                    next.update(&previous);
                    previous.zeroize();
                    previous = next.finalize().into_bytes();
                    for (byte, value) in chunk.iter_mut().zip(previous.iter()) {
                        *byte ^= value;
                    }
                }
                previous.zeroize();
            }
            Ok(core::mem::take(&mut *output))
        }};
    }
    match hmac_prf(parameters) {
        Some(SignatureAlgorithm::HmacSha1) => derive!(sha1::Sha1, 20),
        Some(SignatureAlgorithm::HmacSha224) => derive!(sha2::Sha224, 28),
        Some(SignatureAlgorithm::HmacSha256) => derive!(sha2::Sha256, 32),
        Some(SignatureAlgorithm::HmacSha384) => derive!(sha2::Sha384, 48),
        Some(SignatureAlgorithm::HmacSha512) => derive!(sha2::Sha512, 64),
        _ => Err(ProviderError::Unsupported {
            operation: ProviderOperation::Kdf,
            algorithm: Some(parameters.algorithm.to_owned()),
        }),
    }
}

fn context_octets(context: KdfContext<'_>) -> Option<&[u8]> {
    match context {
        KdfContext::Octets(bytes) => Some(bytes),
        KdfContext::Bits { bytes, bit_len }
            if bit_len.is_multiple_of(8) && bit_len / 8 == bytes.len() =>
        {
            Some(bytes)
        }
        KdfContext::Bits { .. } | KdfContext::LegacyDh { .. } => None,
    }
}

fn concat_digest(parameters: &KdfParameters<'_>) -> Option<DigestAlgorithm> {
    DigestAlgorithm::from_uri(parameters.digest?)
}

fn derive_concat(parameters: &KdfParameters<'_>, secret: &[u8]) -> Result<Vec<u8>, ProviderError> {
    let invalid = || ProviderError::InvalidInput(ProviderInputError::ConcatKdfParameters);
    if parameters.iterations != 0 || !parameters.salt.is_empty() || parameters.output_len == 0 {
        return Err(invalid());
    }
    let (info, bit_len) = match parameters.info {
        KdfContext::Octets(bytes) => (bytes, bytes.len().checked_mul(8).ok_or_else(invalid)?),
        KdfContext::Bits { bytes, bit_len } => (bytes, bit_len),
        KdfContext::LegacyDh { .. } => return Err(invalid()),
    };
    if bit_len.div_ceil(8) != info.len() {
        return Err(invalid());
    }
    let used_bits = bit_len % 8;
    if used_bits != 0 && info[info.len() - 1] & (0xff >> used_bits) != 0 {
        return Err(invalid());
    }
    let algorithm = concat_digest(parameters).ok_or_else(|| ProviderError::Unsupported {
        operation: ProviderOperation::Kdf,
        algorithm: Some(parameters.algorithm.to_owned()),
    })?;
    let width = algorithm.output_len();
    if u32::try_from(parameters.output_len.div_ceil(width)).is_err() {
        return Err(invalid());
    }
    let total_bits = 32 + secret.len() as u128 * 8 + bit_len as u128;
    if width <= 32 && total_bits > u64::MAX as u128 {
        return Err(invalid());
    }
    // XMLEnc 1.1 section 5.4.1 specifies a big-endian counter and unpadded
    // OtherInfo bits. The bit-oriented path shares RustCrypto compression and
    // never allocates a counter || secret || context concatenation per block.
    // https://www.w3.org/TR/xmlenc-core1/#sec-ConcatKDF
    let mut output = zeroize::Zeroizing::new(vec![0; parameters.output_len]);
    for (index, chunk) in output.chunks_mut(width).enumerate() {
        let counter = u32::try_from(index + 1)
            .map_err(|_| invalid())?
            .to_be_bytes();
        let block = bit_hash::hash(algorithm, &[&counter, secret], info, bit_len)?;
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
    Ok(core::mem::take(&mut *output))
}

fn derive_legacy_dh(
    parameters: &KdfParameters<'_>,
    secret: &[u8],
) -> Result<Vec<u8>, ProviderError> {
    let invalid = || ProviderError::InvalidInput(ProviderInputError::LegacyDhKdfParameters);
    let KdfContext::LegacyDh {
        encryption_algorithm,
        nonce,
    } = parameters.info
    else {
        return Err(invalid());
    };
    if parameters.iterations != 0 || !parameters.salt.is_empty() || parameters.output_len == 0 {
        return Err(invalid());
    }
    let algorithm = concat_digest(parameters).ok_or_else(|| ProviderError::Unsupported {
        operation: ProviderOperation::Kdf,
        algorithm: Some(parameters.algorithm.to_owned()),
    })?;
    let width = algorithm.output_len();
    if parameters.output_len.div_ceil(width) > u8::MAX as usize {
        return Err(invalid());
    }
    let mut key_bits = parameters.output_len.checked_mul(8).ok_or_else(invalid)?;
    // usize has at most 39 decimal digits on supported 128-bit platforms.
    // Format directly on the stack rather than allocating per hash block.
    let mut decimal = [0u8; 40];
    let mut start = decimal.len();
    while key_bits != 0 {
        start -= 1;
        decimal[start] = b'0' + (key_bits % 10) as u8;
        key_bits /= 10;
    }
    let total_bytes = secret.len() as u128
        + 2
        + encryption_algorithm.len() as u128
        + nonce.len() as u128
        + (decimal.len() - start) as u128;
    if width <= 32 && total_bytes * 8 > u64::MAX as u128 {
        return Err(invalid());
    }
    // XMLEnc 1.1 section 5.6.2.2 uses a ONE-BYTE counter encoded as two
    // uppercase ASCII hex digits and an unpadded decimal KeySize in bits.
    // This is neither ConcatKDF's BE32 counter nor the agreement algorithm URI.
    // https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-DHKeyAgreementLegacyKDF
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = zeroize::Zeroizing::new(vec![0; parameters.output_len]);
    for (index, chunk) in output.chunks_mut(width).enumerate() {
        let counter = index + 1;
        let ascii = [HEX[counter >> 4], HEX[counter & 15]];
        let hash = bit_hash::hash(
            algorithm,
            &[
                secret,
                &ascii,
                encryption_algorithm.as_bytes(),
                nonce,
                &decimal[start..],
            ],
            &[],
            0,
        )?;
        chunk.copy_from_slice(&hash[..chunk.len()]);
    }
    Ok(core::mem::take(&mut *output))
}
